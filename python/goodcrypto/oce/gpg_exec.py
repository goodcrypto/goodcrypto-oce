'''
    Single module where gpg is invoked.

    GPG should never be directly invoked from anywhere else.
    This module is on the worker/server end of an rq fifo queue.
    Other code should enqueue all gpg calls to the client end of that queue.

    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-11-22

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os, sh
from base64 import b64decode, b64encode
from cStringIO import StringIO
from random import uniform
from rq.timeouts import JobTimeoutException
from tempfile import gettempdir
from time import sleep

# set up django early
from goodcrypto.utils import gc_django
gc_django.setup()

from goodcrypto.oce import gpg_constants
from goodcrypto.oce.key.gpg_utils import parse_fingerprint_and_expiration
from goodcrypto.oce.rq_gpg_settings import GPG_RQ, GPG_REDIS_PORT
from goodcrypto.oce.utils import is_expired
from goodcrypto.utils.exception import record_exception
from goodcrypto.utils.log_file import LogFile
from goodcrypto.utils.manage_rq import get_job_count
from syr.cli import minimal_env
from syr.lock import locked
from syr.times import elapsed_time


def execute_gpg_command(home_dir, initial_args, passphrase=None, data=None):
    '''
        Issue a GPG command in its own worker so there are no concurrency challenges.
    '''

    log = LogFile(filename='goodcrypto.oce.gpg_exec_queue.log')
    gpg_exec = None
    try:
        if initial_args is not None:
            new_args = []
            for arg in initial_args:
                new_args.append(b64decode(arg))
            initial_args = new_args
            log.write_and_flush('gpg exec: {}'.format(initial_args))
        if passphrase is not None:
            passphrase = b64decode(passphrase)
        if data is not None:
            data = bytearray(b64decode(data))

        auto_check_trustdb = gpg_constants.CHECK_TRUSTDB in initial_args

        # different higher levels may try to generate the same key
        # so only allow one key to be generated
        if gpg_constants.GEN_KEY in initial_args:
            command_ready = need_private_key(home_dir, data)
            if not command_ready:
                result_code = gpg_constants.GOOD_RESULT
                gpg_output = gpg_constants.KEY_EXISTS
                gpg_error = None
                log.write_and_flush('{}'.format(gpg_output))

        # if deleting a key, get the fingerprint because gpg
        # only allows deletion in batch mode with the fingerprint
        elif gpg_constants.DELETE_KEYS in initial_args:
            fingerprint = prep_to_delete_key(home_dir, initial_args)
            if fingerprint is not None:
                initial_args = [gpg_constants.DELETE_KEYS, fingerprint]
                log.write_and_flush('ready to delete key: {}'.format(fingerprint))
            command_ready = True

        else:
            command_ready = True

        if command_ready:
            gpg_exec = GPGExec(home_dir, auto_check_trustdb=auto_check_trustdb)
            result_code, gpg_output, gpg_error = gpg_exec.execute(
                initial_args, passphrase, data)

        log.write_and_flush('result code: {}'.format(result_code))
        if gpg_output is not None:
            gpg_output = b64encode(gpg_output)
        if gpg_error is not None:
            gpg_error = b64encode(gpg_error)
    except JobTimeoutException as job_exception:
        log.write_and_flush('gpg exec {}'.format(str(job_exception)))
        result_code = gpg_constants.TIMED_OUT_RESULT
        gpg_error = b64encode(str(job_exception))
        gpg_output = None
        log.write_and_flush('EXCEPTION - see goodcrypto.utils.exception.log for details')
        record_exception()
    except Exception as exception:
        result_code = gpg_constants.ERROR_RESULT
        gpg_output = None
        gpg_error = b64encode(str(exception))
        log.write_and_flush('EXCEPTION - see goodcrypto.utils.exception.log for details')
        record_exception()

        if gpg_exec is not None and gpg_exec.gpg_home is not None:
            gpg_exec.clear_gpg_lock_files()
            gpg_exec.clear_gpg_tmp_files()

    log.flush()

    return result_code, gpg_output, gpg_error

def need_private_key(home_dir, data):
    ''' See if the private key already exists. '''

    private_key_exists = False

    gpg_exec = GPGExec(home_dir)
    try:
        i = data.find(gpg_constants.NAME_EMAIL)
        if i > 0:
            email = data[i + len(gpg_constants.NAME_EMAIL):]
            i = email.find(gpg_constants.EOL)
            if i > 0:
                email = email[:i]
            gpg_exec.log_message('checking if we need to create key for: "{}"'.format(email))
        else:
            email = None
            gpg_exec.log_message('unable to find email in: {}'.format(data))

        if email is None or len(email.strip()) <= 0:
            private_key_exists = False
        else:
            initial_args = [gpg_constants.LIST_SECRET_KEYS, '<{}>'.format(email)]
            result_code, gpg_output, gpg_error = gpg_exec.execute(initial_args)
            private_key_exists = result_code == gpg_constants.GOOD_RESULT

            gpg_exec.log_message('result code: {}'.format(result_code))
            if gpg_error and len(gpg_error.strip()) > 0: gpg_exec.log_message('error: {}'.format(gpg_error))
        gpg_exec.log_message('private key exists for {}: {}'.format(email, private_key_exists))
    except:
        record_exception()
        gpg_exec.log_message('EXCEPTION: see goodcrypto.utils.exception.log for details')

    return not private_key_exists

def prep_to_delete_key(home_dir, initial_args):
    ''' Prepare to delete a key. '''

    fingerprint = None

    if len(initial_args) == 2:
        gpg_exec = GPGExec(home_dir)
        try:
            # get the user's fingerprint so we can delete a key in batch mode
            email = initial_args[1]
            initial_args = [gpg_constants.GET_FINGERPRINT, '<{}>'.format(email)]
            result_code, gpg_output, gpg_error = gpg_exec.execute(initial_args)
            if result_code == gpg_constants.GOOD_RESULT:
                fingerprint, __ = parse_fingerprint_and_expiration(gpg_output)
            else:
                gpg_exec.log_message('no fingperint for {}'.format(email))
        except:
            record_exception()
            gpg_exec.log_message('EXCEPTION: see goodcrypto.utils.exception.log for details')

    return fingerprint

class GPGExec(object):
    '''
        Execute a gpg command.

        gpg expects single tasks so we use redis to queue tasks.

        -fd: 0 = stdin
             1 = stdout
             2 = stderr
    '''

    DEBUGGING = False

    def __init__(self, home_dir, auto_check_trustdb=False):
        '''
            Create a new GPGExec object.

            >>> gpg_exec = GPGExec('/var/local/projects/goodcrypto/server/data/oce/.gnupg')
            >>> gpg_exec != None
            True
        '''

        self.log = LogFile()

        self.gpg_home = home_dir

        self.result_code = gpg_constants.ERROR_RESULT
        self.gpg_output = None
        self.gpg_error = None

        self.set_up_conf()

        # --no-tty: Do not write anything to TTY
        # --homedir: home directory for gpg's keyring files
        # --verbose: give details if error
        # --ignore-time-conflict: Since different machines have different ideas of what time it is, we want to ignore time conflicts.
        # --ignore-valid-from: "valid-from" is just a different kind of time conflict.
        # --batch: We're always in batch mode.
        # --lock-once: Lock the databases the first time a lock is requested and do not release the lock until the process terminates.
        # --no-auto-key-locate: Don't look for keys outside our system
        # --no-auto-check-trustdb: Do not always update the trust db because it goes online
        # --always-trust: We don't have any trust infrastructure yet.
        ## --utf8-strings: Assume all arguments are in UTF-8 format.
        # redirect stdout and stderr so we can exam the results as needed
        kwargs = dict(no_tty=True, verbose=True, homedir=self.gpg_home,
           ignore_time_conflict=True, ignore_valid_from=True, batch=True,
           no_auto_key_locate=True, lock_once=True, _env=minimal_env())

        # gpg tries to go online when it updates the trustdb
        # so we don't want to check on every command
        if auto_check_trustdb:
            kwargs['auto_check_trustdb'] = True
        else:
            kwargs['no_auto_check_trustdb'] = True
            kwargs['always_trust'] = True
        self.gpg = sh.gpg.bake(**kwargs)

        # make sure no old job has left locked files
        self.clear_gpg_lock_files()
        self.clear_gpg_tmp_files()


    def execute(self, initial_args, passphrase=None, data=None):
        ''' Prepare and then run a gpg command. '''

        result_ok = False
        timeout = None
        try:
            stdin_file = StringIO()
            args = initial_args
            if GPGExec.DEBUGGING: self.log_message("executing: {}".format(args))

            if passphrase and len(passphrase) > 0:
                self.log_message('passphrase supplied')

                # passphrase will be passed on stdin, file descriptor 0 is stdin
                passphraseOptions = ['--passphrase-fd', '0']
                args.append(passphraseOptions)
                stdin_file.write(passphrase)
                stdin_file.write(gpg_constants.EOL)

            if data:
                stdin_file.write(buffer(data))

                data_length = len(data)
                self.log_message('data length: {}'.format(data_length))
                if data_length > gpg_constants.LARGE_DATA_CHUNK:
                    timeout = int(
                      (data_length / gpg_constants.LARGE_DATA_CHUNK) * gpg_constants.TIMEOUT_PER_CHUNK) *  1000 # in ms
                    self.log_message('timeout in ms: {}'.format(data_length))

                if GPGExec.DEBUGGING: self.log_message("data: {}".format(data))

            stdin = stdin_file.getvalue()
            stdin_file.close()

            if GPGExec.DEBUGGING:
                self.log_message("gpg args:")
                for arg in args:
                    self.log_message('  {}'.format(arg))

            result_ok = self.run_gpg(args, stdin, timeout=timeout)
            self.log_message("gpg command result_ok: {}".format(result_ok))

        except Exception as exception:
            result_ok = False
            self.result_code = gpg_constants.ERROR_RESULT
            self.gpg_error = str(exception)

            self.log_message('result code: {}'.format(self.result_code))
            if gpg_error and len(gpg_error.strip()) > 0:
                self.log_message("gpg error: {}".format(self.gpg_error))
            self.log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
            record_exception()

        self.log.flush()

        return self.result_code, self.gpg_output, self.gpg_error

    def run_gpg(self, args, stdin, timeout=None):
        ''' Run the GPG command. '''

        try:
            if gpg_constants.ENCRYPT_DATA in args:
                command = gpg_constants.ENCRYPT_DATA
            elif gpg_constants.DECRYPT_DATA in args:
                command = gpg_constants.DECRYPT_DATA
            else:
                command = args[0]
            self.log_message('--- started executing: {} ---'.format(command))

            with elapsed_time() as gpg_time:
                if timeout is None:
                    if stdin and len(stdin) > 0:
                        gpg_results = self.gpg(*args, _in=stdin, _ok_code=[0,2])
                    else:
                        gpg_results = self.gpg(*args, _ok_code=[0,2])
                else:
                    if stdin and len(stdin) > 0:
                        gpg_results = self.gpg(*args, _in=stdin, _ok_code=[0,2], _timeout=timeout)
                    else:
                        gpg_results = self.gpg(*args, _ok_code=[0,2], _timeout=timeout)

                self.log_message('{} command elapsed time: {}'.format(command, gpg_time))

            self.log_message('{} exit code: {}'.format(command, gpg_results.exit_code))
            self.log_message('--- finished executing: {} ---'.format(command))

            self.result_code = gpg_results.exit_code
            self.gpg_output = gpg_results.stdout
            self.gpg_error = gpg_results.stderr

            if GPGExec.DEBUGGING:
                if self.gpg_output:
                    self.log_message('stdout:')
                    if type(self.gpg_output) == str:
                        self.log_message(self.gpg_output)
                    else:
                        self.log_message(repr(self.gpg_output))
                if self.gpg_error:
                    self.log_message('stderr:')
                    if type(self.gpg_output) == str:
                        self.log_message(self.gpg_error)
                    else:
                        self.log_message(repr(self.gpg_error))

        except sh.ErrorReturnCode as exception:
            self.result_code = exception.exit_code

            if self.gpg_error is None:
                self.gpg_error = exception.stderr

            # get the essence of the error
            self.gpg_error = exception.stderr
            if self.gpg_error and self.gpg_error.find(':'):
                self.gpg_error = self.gpg_error[self.gpg_error.find(':') + 1:]
            if self.gpg_error and self.gpg_error.find(':'):
                self.gpg_error = self.gpg_error[self.gpg_error.find(':') + 1:]

            self.log_message('exception result code: {}'.format(self.result_code))
            if exception:
                self.log_message("exception:\n==============\n{}\n============".format(exception))

        except JobTimeoutException as job_exception:
            self.log_message('run_gpg exception: {}'.format(str(job_exception)))
            self.result_code = gpg_constants.TIMED_OUT_RESULT
            self.gpg_error = b64encode(str(job_exception))
            self.gpg_output = None

            self.log_message('--- timedout executing {} ---'.format(command))

        return self.result_code == gpg_constants.GOOD_RESULT

    def set_up_conf(self):
        ''' Set up the GPG conf file, if it doesn't exist. '''

        try:
            if self.gpg_home is None:
                self.log_message('gpg home not defined yet')
            else:
                gpg_conf = os.path.join(self.gpg_home, gpg_constants.CONF_FILENAME)
                if not os.path.exists(gpg_conf):
                    lines = []
                    lines.append('#\n')
                    lines.append('# This is an adpation of the Riseup OpenPGP Best Practices\n')
                    lines.append('# https://help.riseup.net/en/security/message-security/openpgp/best-practices\n')
                    lines.append('#\n')
                    lines.append('#-----------------------------\n')
                    lines.append('# behavior\n')
                    lines.append('#-----------------------------\n')
                    lines.append('# Disable inclusion of the version string in ASCII armored output\n')
                    lines.append('no-emit-version\n')
                    lines.append('# Disable comment string in clear text signatures and ASCII armored messages\n')
                    lines.append('no-comments\n')
                    lines.append('# Display long key IDs\n')
                    lines.append('keyid-format 0xlong\n')
                    lines.append('# List all keys (or the specified ones) along with their fingerprints\n')
                    lines.append('with-fingerprint\n')
                    lines.append('# Display the calculated validity of user IDs during key listings\n')
                    lines.append('list-options show-uid-validity\n')
                    lines.append('verify-options show-uid-validity\n')
                    lines.append('# Try to use the GnuPG-Agent. With this option, GnuPG first tries to connect to\n')
                    lines.append('# the agent before it asks for a passphrase.\n')
                    lines.append('use-agent\n')
                    lines.append('#-----------------------------\n')
                    lines.append('# keyserver -- goodcrypto relies on per-to-per key exchange, not key servers\n')
                    lines.append('#-----------------------------\n')
                    lines.append('# This is the server that --recv-keys, --send-keys, and --search-keys will\n')
                    lines.append('# communicate with to receive keys from, send keys to, and search for keys on\n')
                    lines.append('# keyserver hkps://hkps.pool.sks-keyservers.net\n')
                    lines.append('# Provide a certificate store to override the system default\n')
                    lines.append('# Get this from https://sks-keyservers.net/sks-keyservers.netCA.pem\n')
                    lines.append('# keyserver-options ca-cert-file=/usr/local/etc/ssl/certs/hkps.pool.sks-keyservers.net.pem\n')
                    lines.append('# Set the proxy to use for HTTP and HKP keyservers - default to the standard\n')
                    lines.append('# local Tor socks proxy\n')
                    lines.append('# It is encouraged to use Tor for improved anonymity. Preferrably use either a\n')
                    lines.append('# dedicated SOCKSPort for GnuPG and/or enable IsolateDestPort and\n')
                    lines.append('# IsolateDestAddr\n')
                    lines.append('#keyserver-options http-proxy=socks5-hostname://127.0.0.1:9050\n')
                    lines.append("# Don't leak DNS, see https://trac.torproject.org/projects/tor/ticket/2846\n")
                    lines.append('keyserver-options no-try-dns-srv\n')
                    lines.append('# When using --refresh-keys, if the key in question has a preferred keyserver\n')
                    lines.append('# URL, then disable use of that preferred keyserver to refresh the key from\n')
                    lines.append('keyserver-options no-honor-keyserver-url\n')
                    lines.append('# When searching for a key with --search-keys, include keys that are marked on\n')
                    lines.append('# the keyserver as revoked\n')
                    lines.append('keyserver-options include-revoked\n')
                    lines.append('#-----------------------------\n')
                    lines.append('# algorithm and ciphers\n')
                    lines.append('#-----------------------------\n')
                    lines.append('# list of personal digest preferences. When multiple digests are supported by\n')
                    lines.append('# all recipients, choose the strongest one\n')
                    lines.append('personal-cipher-preferences AES256 AES192 AES CAST5\n')
                    lines.append('# list of personal digest preferences. When multiple ciphers are supported by\n')
                    lines.append('# all recipients, choose the strongest one\n')
                    lines.append('personal-digest-preferences SHA512 SHA384 SHA256 SHA224\n')
                    lines.append('# message digest algorithm used when signing a key\n')
                    lines.append('cert-digest-algo SHA512\n')
                    lines.append('# This preference list is used for new keys and becomes the default for\n')
                    lines.append('# "setpref" in the edit menu\n')
                    lines.append('default-preference-list SHA512 SHA384 SHA256 SHA224 AES256 AES192 AES CAST5 ZLIB BZIP2 ZIP Uncompressed\n')
                    '''
                    lines.append('# when outputting certificates, view user IDs distinctly from keys:\n')
                    lines.append('fixed-list-mode\n')
                    lines.append("# long keyids are more collision-resistant than short keyids (it's trivial to make a key with any desired short keyid)")
                    lines.append('keyid-format 0xlong\n')
                    lines.append('# when multiple digests are supported by all recipients, choose the strongest one:\n')
                    lines.append('personal-digest-preferences SHA512 SHA384 SHA256 SHA224\n')
                    lines.append('# preferences chosen for new keys should prioritize stronger algorithms: \n')
                    lines.append('default-preference-list SHA512 SHA384 SHA256 SHA224 AES256 AES192 AES CAST5 BZIP2 ZLIB ZIP Uncompressed\n')
                    lines.append("# If you use a graphical environment (and even if you don't) you should be using an agent:")
                    lines.append('# (similar arguments as  https://www.debian-administration.org/users/dkg/weblog/64)\n')
                    lines.append('use-agent\n')
                    lines.append('# You should always know at a glance which User IDs gpg thinks are legitimately bound to the keys in your keyring:\n')
                    lines.append('verify-options show-uid-validity\n')
                    lines.append('list-options show-uid-validity\n')
                    lines.append('# include an unambiguous indicator of which key made a signature:\n')
                    lines.append('# (see http://thread.gmane.org/gmane.mail.notmuch.general/3721/focus=7234)\n')
                    lines.append('sig-notation issuer-fpr@notations.openpgp.fifthhorseman.net=%g\n')
                    lines.append('# when making an OpenPGP certification, use a stronger digest than the default SHA1:\n')
                    lines.append('cert-digest-algo SHA256\n')
                    '''

                    self.log_message('creating {}'.format(gpg_conf))
                    with open(gpg_conf, 'wt') as f:
                        for line in lines:
                            f.write(line)
                    sh.chmod('0400', gpg_conf)
                    self.log_message('created {}'.format(gpg_conf))
        except Exception:
            record_exception()
            self.log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    def clear_gpg_lock_files(self):
        '''
            Delete gpg lock files.

            Warning: Calling this method when a valid lock file exists can have very
            serious consequences.

            Lock files are in gpg home directory and are in the form
            ".*.lock", ".?*", or possibly "trustdb.gpg.lock".
        '''

        try:
            if self.gpg_home is None:
                self.log_message("unable to clear gpg's lock files because home dir unknown")
            else:
                filenames = os.listdir(self.gpg_home)
                if filenames and len(filenames) > 0:
                    for name in filenames:
                        if name.endswith(gpg_constants.LOCK_FILE_SUFFIX):
                            os.remove(os.path.join(self.gpg_home, name))
                            self.log_message("deleted lock file " + name)
        except Exception:
            record_exception()
            self.log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    def clear_gpg_tmp_files(self):
        '''
            Delete gpg tmp files.
        '''

        TmpPREFIX = 'tmp'
        TmpSUFFIX = '~'

        try:
            if self.gpg_home is None:
                self.log_message("unable to clear gpg's tmp files because home dir unknown")
            else:
                filenames = os.listdir(self.gpg_home)
                if filenames and len(filenames) > 0:
                    for name in filenames:
                        if name.startswith(TmpPREFIX) and name.endswith(TmpSUFFIX):
                            os.remove(os.path.join(self.gpg_home, name))
        except Exception:
            record_exception()
            self.log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    def log_message(self, message):
        '''
            Log the message.
        '''

        if self.log is None:
            self.log = LogFile()

        self.log.write_and_flush(message)

