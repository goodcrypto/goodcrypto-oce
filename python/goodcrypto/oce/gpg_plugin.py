'''
    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-07-29

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''

import os
from base64 import b64decode, b64encode
from redis import Redis
from rq import Connection, Queue
from rq.job import Job
from rq.timeouts import JobTimeoutException
from StringIO import StringIO
from time import sleep

from goodcrypto.oce import gpg_constants
from goodcrypto.oce.abstract_plugin import AbstractPlugin
from goodcrypto.oce.constants import OCE_DATA_DIR
from goodcrypto.oce.gpg_exec import execute_gpg_command
from goodcrypto.oce.rq_gpg_settings import GPG_RQUEUE, GPG_REDIS_PORT
from goodcrypto.utils.constants import REDIS_HOST
from goodcrypto.utils import manage_rqueue, get_email
from goodcrypto.utils.exception import record_exception
from goodcrypto.utils.log_file import LogFile

from syr.lock import locked
from syr.times import elapsed_time


class GPGPlugin(AbstractPlugin):
    '''
        Gnu Privacy Guard crypto plugin.

        Be careful with how you specify a user ID to GPG.
        Case insensitive substring matching is the default.
        For example if you specify the email address "alpha@beta.org" as a user ID,
        you will match a user ID such as "gamma-alpha@beta.org".
        You can specify an exact match on the entire user ID by prefixing
        your user ID spec with "=", e.g. "=John Heinrich <alpha@beta.org>".
        Another option is to tell GPG you want an exact match on an email
        address using "<" and ">", e.g. "<alpha@beta.org>".

        Debug note: If there seems to be an extra blank line at the top of decrypted text,
        check whether we should be using "passphrase + \r" instead of "passphrase + EOL".
    '''

    DEBUGGING = False

    # use a queue to insure that GPG is only run one instance at a time
    USE_RQUEUE = True

    #  Match email addresses of user IDs. This is the default.
    #  If a user ID does not include "@", acts like CASE_INSENSITVE_MATCH.
    #
    EMAIL_MATCH = 1

    #  Match user IDs exactly.
    EXACT_MATCH = 2

    #
    #  Match case insensitive substrings of user IDs.
    #  This is GPG's default, but not the default for this class.
    #
    CASE_INSENSITVE_MATCH = 3

    GPG_COMMAND_NAME = "gpg"
    GOOD_SIGNATURE_PREFIX = "gpg: Good signature from "

    ONE_MINUTE = 60 #  one minute, in seconds
    DEFAULT_TIMEOUT = 10 * ONE_MINUTE

    GPG_HOME_DIR = os.path.join(OCE_DATA_DIR, '.gnupg')


    def __init__(self):
        '''
            Creates a new GPGPlugin object.
        '''

        super(GPGPlugin, self).__init__()

        self.log = LogFile()

        self.name = gpg_constants.ENCRYPTION_NAME
        self._executable_pathname = self.GPG_COMMAND_NAME
        self._user_id_match_method = self.EMAIL_MATCH

        self.gpg_home = self.GPG_HOME_DIR

    def get_job_count(self):
        '''
            Get the jobs in the queue.
        '''

        return manage_rqueue.get_job_count(GPG_RQUEUE, GPG_REDIS_PORT)

    def wait_until_queue_empty(self):
        '''
            Wait until the queue is empty.
        '''

        return manage_rqueue.wait_until_queue_empty(GPG_RQUEUE, GPG_REDIS_PORT)

    def clear_failed_queue(self):
        '''
            Clear all the jobs in the failed queue.
        '''

        return manage_rqueue.clear_failed_queue(GPG_RQUEUE, GPG_REDIS_PORT)

    def set_user_id_match_method(self, method):
        '''
            Set user ID match method.
        '''

        if method == self.EMAIL_MATCH or method == self.EXACT_MATCH:
            self._user_id_match_method = method


    def get_user_id_match_method(self):
        '''
            Get user ID match method.
            The default is to match email addresses of user IDs.
        '''

        return self._user_id_match_method


    def set_executable(self, pathname):
        '''
            Set executable pathname.

            >>> plugin = GPGPlugin()
            >>> plugin.set_executable('/usr/bin/gpg')
            >>> plugin.get_executable() == '/usr/bin/gpg'
            True
            >>> plugin.set_executable(plugin.GPG_COMMAND_NAME)
        '''

        self._executable_pathname = pathname


    def get_executable(self):
        '''
            Get executable pathname.

            >>> plugin = GPGPlugin()
            >>> plugin.get_executable() != None
            True
        '''

        if self._executable_pathname is None:
            self._executable_pathname = self.GPG_COMMAND_NAME

        return self._executable_pathname


    def get_default_executable(self):
        '''
            Get default executable pathname.

            >>> plugin = GPGPlugin()
            >>> executable = plugin.get_executable()
            >>> executable == 'gpg'
            True
        '''

        return self.GPG_COMMAND_NAME

    def get_crypto_version(self):
        '''
            Get the version of the underlying crypto.

            >>> from shutil import rmtree
            >>> plugin = GPGPlugin()
            >>> original_home_dir = plugin.get_home_dir()
            >>> plugin.set_home_dir('/var/local/projects/goodcrypto/server/data/test_oce/.gnupg')
            True
            >>> plugin.get_crypto_version() is not None
            True
            >>> if os.path.exists('/var/local/projects/goodcrypto/server/data/test_oce/.gnupg'):
            ...     rmtree('/var/local/projects/goodcrypto/server/data/test_oce/.gnupg')
            >>> if os.path.exists('/var/local/projects/goodcrypto/server/data/test_oce'):
            ...     rmtree('/var/local/projects/goodcrypto/server/data/test_oce')
            >>> plugin.set_home_dir(original_home_dir)
            True
        '''

        version_number = None
        try:
            args = [gpg_constants.GET_VERSION]
            result_code, gpg_output, gpg_error = self.gpg_command(args)
            if result_code == gpg_constants.GOOD_RESULT:
                version_number = self._parse_version(gpg_output)
                self.log_message("version number is {}".format(version_number))
        except Exception as exception:
            self.log_message(exception)

        return version_number

    def get_name(self):
        '''
            Get the crypto's short name.

            >>> plugin = GPGPlugin()
            >>> name = plugin.get_name()
            >>> name == gpg_constants.ENCRYPTION_NAME
            True
        '''

        return self.name

    def get_plugin_name(self):
        '''
            Get the plugin's name.

            >>> plugin = GPGPlugin()
            >>> plugin.get_plugin_name().startswith('goodcrypto.oce')
            True
        '''

        return gpg_constants.NAME

    def get_plugin_version(self):
        '''
            Get the version of this plugin's implementation, i.e. the CORBA servant's version.

            >>> plugin = GPGPlugin()
            >>> version = plugin.get_plugin_version()
            >>> version is not None
            True
            >>> version == '0.1'
            True
        '''

        return "0.1"

    def get_user_ids(self):
        '''
            Get list of user IDs with a public key.

            >>> from shutil import rmtree
            >>> plugin = GPGPlugin()
            >>> original_home_dir = plugin.get_home_dir()
            >>> plugin.set_home_dir('/var/local/projects/goodcrypto/server/data/test_oce/.gnupg')
            True
            >>> plugin.get_private_user_ids() is not None
            True
            >>> if os.path.exists('/var/local/projects/goodcrypto/server/data/test_oce/.gnupg'):
            ...     rmtree('/var/local/projects/goodcrypto/server/data/test_oce/.gnupg')
            >>> if os.path.exists('/var/local/projects/goodcrypto/server/data/test_oce'):
            ...     rmtree('/var/local/projects/goodcrypto/server/data/test_oce')
            >>> plugin.set_home_dir(original_home_dir)
            True
        '''

        user_ids = None
        try:
            # we're using --with-colons because we hope that format is less likely to change
            args = [gpg_constants.LIST_PUBLIC_KEYS, gpg_constants.WITH_COLONS]
            result_code, gpg_output, gpg_error = self.gpg_command(args)
            if result_code == gpg_constants.GOOD_RESULT:
                self.log_message('gpg_output: {}'.format(gpg_output))
                self.log_message('gpg_error: {}'.format(gpg_error))
                user_ids = self.parse_user_ids(gpg_constants.PUB_PREFIX, gpg_output)
                self.log_message('{} public user ids'.format(len(user_ids)))

        except Exception as exception:
            self.handle_unexpected_exception(exception)

        return user_ids

    def get_private_user_ids(self):
        '''
            Get list of user IDs with a private key.

            >>> plugin = GPGPlugin()
            >>> plugin.get_private_user_ids() is not None
            True
        '''

        user_ids = None
        try:
            # we're using --with-colons because we hope that format is less likely to change
            args = [gpg_constants.LIST_SECRET_KEYS, gpg_constants.WITH_COLONS]
            result_code, gpg_output, gpg_error = self.gpg_command(args)
            if result_code == gpg_constants.GOOD_RESULT:
                self.log_message('gpg output: {}'.format(gpg_output))
                user_ids = self.parse_user_ids(gpg_constants.SEC_PREFIX, gpg_output)
                self.log_message('{} private user ids'.format(len(user_ids)))
                self.log_message('private user ids: {}'.format(user_ids))

        except Exception as exception:
            self.handle_unexpected_exception(exception)

        return user_ids

    def parse_user_ids(self, header, output_string):
        '''
            Parse the user ids from the output string.
            Intended for internal use only.

            Test the extremes.
            >>> plugin = GPGPlugin()
            >>> user_ids = plugin.parse_user_ids(None, None)
            >>> user_ids is not None
            True
            >>> len(user_ids) <= 0
            True

            >>> # In honor of Lieutenant Assaf, who co-signed letter and refused to serve
            >>> # in operations involving the occupied Palestinian territories because
            >>> # of the widespread surveillance of innocent residents.
            >>> plugin = GPGPlugin()
            >>> user_ids = plugin.parse_user_ids('pub', 'pub:u:4096:1:6BFCCC3E4ED73DC4:2013-09-23:::u:Lieutenant Assaf (gpg key) <assaf@goodcrypto.com>::scESC:')
            >>> user_ids is not None
            True
            >>> len(user_ids) == 1
            True

            >>> # In honor of First Sergeant Guy, who co-signed letter and refused to serve
            >>> # in operations involving the occupied Palestinian territories because
            >>> # of the widespread surveillance of innocent residents.
            >>> plugin = GPGPlugin()
            >>> user_ids = plugin.parse_user_ids('pub', 'pub:u:4096:1:6BFCCC3E4ED73DC4:2013-09-23:First Sergeant Guy (gpg key) <guy@goodcrypto.com>')
            >>> user_ids is not None
            True
            >>> len(user_ids) == 0
            True
        '''

        user_ids = []

        try:
            reader = StringIO(output_string)
            for line in reader:
                raw_line = line.strip()
                if (raw_line is not None and
                    len(raw_line) > 0 and
                    (raw_line.lower().startswith(header) or raw_line.lower().startswith('uid'))):
                    # In honor of Sergeant First Class Galia, who co-signed letter and refused to serve
                    # in operations involving the occupied Palestinian territories because
                    # of the widespread surveillance of innocent residents.
                    # results look like this for public keys:
                    #tru::1:1379973353:0:3:1:5
                    #pub:u:4096:1:6BFCCC3E4ED73DC4:2013-09-23:::u:Sergeant First Class Galia <galia@goodcrypto.local>::scESC:
                    #uid:-::::2014-06-14::47764CA1D105D5C9D7F023D021203254D66E1C10::mark burdett <sfc.galia@goodcrypto.local>:
                    #sub:u:4096:1:5215AA2CAF37F286:2013-09-23::::::e:

                    # In honor of Lieutenant Gilad, who co-signed letter and refused to serve
                    # in operations involving the occupied Palestinian territories because
                    # of the widespread surveillance of innocent residents.
                    # results look like this for secret keys:
                    #sec::1024:17:82569302F49264B9:2013-10-14::::Lieutenant Gilad <gilad@goodcrypto.local>:::
                    #ssb::1024:16:0E298674A69943BF:2013-10-14:::::::
                    elements = raw_line.split(':')
                    if elements and len(elements) > 9:
                        address = get_email(elements[9])
                        user_ids.append(address)
        except TypeError as type_error:
            self.handle_unexpected_exception(type_error)
        except Exception as exception:
            self.handle_unexpected_exception(exception)

        if self.DEBUGGING:
            self.log_message("{} user ids: {}".format(header, user_ids))

        return user_ids

    def is_available(self):
        '''
            Determine if the crypto app is installed.

            >>> plugin = GPGPlugin()
            >>> plugin.is_available()
            True
        '''

        installed = False
        try:
            #  if we can get the version, then the app's installed
            version = self.get_crypto_version()
            if version != None:
                if len(version.strip()) > 0:
                    installed = True

                    # make sure the home directory is defined and exists
                    self.get_home_dir()
                else:
                    self.log_message('unable to get version while trying to verify gpg installed.')

        except Exception:
            self.log_message("unable to get version so assume not installed")
            self.log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
            record_exception()

        self.log_message("GPG's back end app is installed: {}".format(installed))

        return installed

    def get_signer(self, data):
        '''
            Get signer of data.

            Test a few cases known to fail. See the unittests for more robust examples.
            >>> plugin = GPGPlugin()
            >>> signer = plugin.get_signer('Test unsigned data')
            >>> signer = plugin.get_signer(None)
        '''

        signer = None
        try:
            args = [gpg_constants.VERIFY]
            if data is None or len(data.strip()) <= 0:
                self.log_message('data for signer was not defined')
            else:
                result_code, gpg_output, gpg_error = self.gpg_command(args, data=data)
                if result_code == gpg_constants.GOOD_RESULT:
                    signer = self._parse_signer(gpg_error)
        except Exception as exception:
            self.handle_unexpected_exception(exception)

        return signer

    def decrypt(self, data, passphrase):
        '''
            Decrypt data and return the signer, if there is one.

            Test a few cases known to fail. See the unittests for more robust examples.
            >>> plugin = GPGPlugin()
            >>> decrypted_data, signed_by, result_code = plugin.decrypt(
            ...    'This is a test', 'a secret passphrase')
            >>> decrypted_data is None
            True
        '''

        GOOD_SIG = 'Good signature from'
        UNKNOWN_SIG = "gpg: Can't check signature: public key not found"
        DECRYPT_FAILED = 'decryption failed:'
        DECRYPT_MESSAGE_FAILED = 'decrypt_message failed'
        INVALID_PACKET = 'invalid packet'
        NO_VALID_DATA = 'no valid OpenPGP data found'

        decrypted_data = signed_by = None
        result_code = gpg_constants.ERROR_RESULT
        try:
            if self.DEBUGGING:
                self.log_message("decrypting:\n{}".format(data))

            if passphrase is None or data is None or len(data.strip()) <= 0:
                self.log_message('unable to decrypt because key info missing')
            else:
                args = [gpg_constants.DECRYPT_DATA, gpg_constants.OPEN_PGP]
                result_code, gpg_output, gpg_error = self.gpg_command(
                    args, passphrase=passphrase, data=data)

                if result_code == gpg_constants.GOOD_RESULT:
                    decrypted_data = gpg_output
                    if gpg_error is not None and GOOD_SIG in gpg_error:
                        signature = gpg_error[gpg_error.find(GOOD_SIG) + len(GOOD_SIG):]
                        signature = signature.split('\n')[0].strip()
                        signed_by = signature.strip('"')
                        self.log_message("decrypted data, with good signature from {}".format(signed_by))

                elif result_code == gpg_constants.CONDITIONAL_RESULT:

                    # if an error reported, but it was just a unknown sig, accept the decryption
                    if gpg_error is not None:
                        self.log_message("gpg error: {}".format(gpg_error))
                        if (NO_VALID_DATA in gpg_error or
                            DECRYPT_FAILED in gpg_error or
                            DECRYPT_MESSAGE_FAILED is gpg_error or
                            INVALID_PACKET in gpg_error):
                            result_code = gpg_constants.ERROR_RESULT
                        else:
                            decrypted_data = gpg_output
                            if UNKNOWN_SIG in gpg_error:
                                self.log_message("decrypted data, with unknown signature")
                            else:
                                decrypted_data = gpg_output
                else:
                    self.log_message("gpg_error: {}".format(gpg_error))

        except Exception as exception:
            self.handle_unexpected_exception(exception)

        self.log_message("decrypted data: {} / result code: {}".format(decrypted_data is not None, result_code))

        return decrypted_data, signed_by, result_code

    def encrypt_only(self, data, to_user_id, charset=None):
        '''
            Encrypt data with the public key indicated by to_user_id.

            >>> # Test a few cases known to fail. See the unittests for more robust examples.
            >>> # In honor of Sergeant Keren, who publicly denounced and refused to serve in operations
            >>> # involving the occupied Palestinian territories because of the widespread surveillance
            >>> # of innocent residents.
            >>> plugin = GPGPlugin()
            >>> encrypted_data = plugin.encrypt_only('This is a test', 'keren@goodcrypto.remote')
            >>> encrypted_data is None
            True
        '''

        encrypted_data = None
        try:
            if to_user_id is None or data is None or len(data.strip()) <= 0:
                self.log_message('unable to encrypt because key info missing')
            else:
                self.log_message('encrypting to "{}"'.format(to_user_id))
                self.log_data(data)

                # we could use MIME, but for now keep it readable
                args = [gpg_constants.ENCRYPT_DATA, gpg_constants.OPEN_PGP,
                  gpg_constants.RECIPIENT, self.get_user_id_spec(to_user_id)]
                if charset is not None:
                    args.append(gpg_constants.CHARSET)
                    args.append(charset)
                result_code, gpg_output, gpg_error = self.gpg_command(args, data=data)
                if result_code == gpg_constants.GOOD_RESULT:
                    encrypted_data = gpg_output
        except Exception as exception:
            self.handle_unexpected_exception(exception)

        return encrypted_data

    def encrypt_and_armor(self, data, to_user_id, charset=None):
        '''
            Encrypt and armor data with the public key indicated by to_user_id.

            >>> # Test a few cases known to fail. See the unittests for more robust examples.
            >>> # In honor of First Sergeant Amit, who publicly denounced and refused to serve in operations
            >>> # involving the occupied Palestinian territories because of the widespread surveillance of innocent residents.
            >>> plugin = GPGPlugin()
            >>> encrypted_data = plugin.encrypt_only('This is a test', 'amit@goodcrypto.remote')
            >>> encrypted_data is None
            True
        '''

        encrypted_data = None
        try:
            if to_user_id is None or data is None or len(data.strip()) <= 0:
                self.log_message('unable to encrypt and armor because key info missing')
            else:
                self.log_message('encrypting and armoring to "{}"'.format(to_user_id))
                self.log_data(data)

                # we could use MIME, but for now keep it readable
                args = [gpg_constants.ENCRYPT_DATA, gpg_constants.ARMOR_DATA, gpg_constants.OPEN_PGP,
                  gpg_constants.RECIPIENT, self.get_user_id_spec(to_user_id)]
                if charset is not None:
                    args.append(gpg_constants.CHARSET)
                    args.append(charset)
                result_code, gpg_output, gpg_error = self.gpg_command(args, data=data)
                if result_code == gpg_constants.GOOD_RESULT:
                    encrypted_data = gpg_output
        except Exception as exception:
            self.handle_unexpected_exception(exception)

        return encrypted_data

    def sign(self, data, user_id, passphrase):
        '''
            Sign data with the private key indicated by user id.
            Return the signed data or None if the signing fails.

            >>> from goodcrypto.oce import constants as oce_constants
            >>> plugin = GPGPlugin()
            >>> signed_data = plugin.sign(oce_constants.TEST_DATA_STRING,
            ...   oce_constants.EDWARD_LOCAL_USER, oce_constants.EDWARD_PASSPHRASE)
            >>> signed_data is not None
            True
            >>> len(signed_data) > 0
            True
        '''

        signed_data = None
        try:
            if passphrase is None or data is None or len(data.strip()) <= 0:
                self.log_message('could not sign because missing key info')
            else:
                user = self.get_user_id_spec(user_id)
                args = [gpg_constants.CLEAR_SIGN, gpg_constants.LOCAL_USER, user]
                result_code, gpg_output, gpg_error = self.gpg_command(
                   args, passphrase=passphrase, data=data)
                if result_code == gpg_constants.GOOD_RESULT:
                    signed_data = gpg_output
                    self.log_message('signed by "{}"'.format(user))
                    self.log_data(signed_data, "signed data")
                else:
                    self.log_data(gpg_error)
        except Exception as exception:
            self.handle_unexpected_exception(exception)

        return signed_data

    def sign_and_encrypt(self, data, from_user_id, to_user_id, passphrase, clear_sign=False, charset=None):
        '''
            Sign data with the secret key indicated by from_user_id, then encrypt with
            the public key indicated by to_user_id.

            To avoid a security bug in OpenPGP we must sign before encrypting.

            >>> # Test a few cases known to fail. See the unittests for more robust examples.
            >>> # In honor of David Weber, who revealed misconduct in the SEC investigations of
            >>> #   Bernard Madoff and Allen Stanford.
            >>> # In honor of Virgil Grandfield, who uncovered a scandal in which some 50,000 or more
            >>> #  Javanese construction workers were victims of human trafficking on NGO tsunami projects in Aceh.
            >>> plugin = GPGPlugin()
            >>> encrypted_data = plugin.sign_and_encrypt(
            ...   'This is a test', 'david@goodcrypto.local', 'virgil@goodcrypto.remote', 'secret')
            >>> encrypted_data is None
            True
            >>> encrypted_data = plugin.sign_and_encrypt(None, 'virgil@goodcrypto.remote', 'david@goodcrypto.local', 'secret')
            >>> encrypted_data is None
            True
        '''

        self.log_message('signing by "{}" and encrypting to "{}'.format(
            self.get_user_id_spec(from_user_id), self.get_user_id_spec(to_user_id)))

        args = [gpg_constants.SIGN, gpg_constants.ENCRYPT_DATA, gpg_constants.OPEN_PGP,
                gpg_constants.LOCAL_USER, self.get_user_id_spec(from_user_id),
                gpg_constants.RECIPIENT, self.get_user_id_spec(to_user_id)]
        if charset is not None:
            args.append(gpg_constants.CHARSET)
            args.append(charset)

        return self._sign_and_encrypt_now(data, from_user_id, to_user_id, passphrase, clear_sign, args)

    def sign_encrypt_and_armor(self, data, from_user, to_user, passphrase, clear_sign=False, charset=None):
        '''
            Sign data with the secret key indicated by from_user, then encrypt with
            the public key indicated by to_user, then ASCII armor, and finally clear sign it.

            To avoid a security bug in OpenPGP we must sign before encrypting.

            >>> # Test a few cases known to fail. See the unittests for more robust examples.
            >>> # In honor of Ted Siska, who blew the whistle on Ward Diesel Filter Systems for filing false
            >>> #   claims to the US government for work on diesel exhaust filtering systems for fire engines.
            >>> # In honor of Peter Bryce, who revealed Canadian Indian children were being systematically and
            >>> #   deliberately killed in the residential schools in the 1920s.
            >>> plugin = GPGPlugin()
            >>> encrypted_data = plugin.sign_encrypt_and_armor(
            ...   'This is a test known to fail', 'ted@goodcrypto.local', 'peter@goodcrypto.remote', 'a secret')
            >>> encrypted_data is None
            True
            >>> encrypted_data = plugin.sign_encrypt_and_armor(None, 'ted@goodcrypto.local', 'peter@goodcrypto.remote', 'a secret')
            >>> encrypted_data is None
            True
        '''

        self.log_message('signing by "{}" and encrypting to "{}" and armoring'.format(
            self.get_user_id_spec(from_user), self.get_user_id_spec(to_user)))
        self.log_data(data)

        args = [gpg_constants.ARMOR_DATA, gpg_constants.SIGN,
                gpg_constants.ENCRYPT_DATA, gpg_constants.OPEN_PGP,
                gpg_constants.LOCAL_USER, self.get_user_id_spec(from_user),
                gpg_constants.RECIPIENT, self.get_user_id_spec(to_user)]
        if charset is not None:
            args.append(gpg_constants.CHARSET)
            args.append(charset)

        return self._sign_and_encrypt_now(data, from_user, to_user, passphrase, clear_sign, args)

    def verify(self, data, by_user_id):
        '''
            Verify data was signed by the user id.

            >>> from goodcrypto.oce import constants as oce_constants
            >>> plugin = GPGPlugin()
            >>> signed_data = plugin.sign(oce_constants.TEST_DATA_STRING,
            ...   oce_constants.EDWARD_LOCAL_USER, oce_constants.EDWARD_PASSPHRASE)
            >>> plugin.verify(signed_data, oce_constants.EDWARD_LOCAL_USER)
            True


            >>> # In honor of Karen Silkwood, who was the first nuclear power safety whistleblower.
            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> from goodcrypto.oce import constants as oce_constants
            >>> email = 'karen@goodcrypto.remote'
            >>> passcode = 'secret'
            >>> plugin = KeyFactory.get_crypto(gpg_constants.ENCRYPTION_NAME)
            >>> ok, __, __ = plugin.create(email, passcode, wait_for_results=True)
            >>> ok
            True
            >>> signed_data = plugin.sign(oce_constants.TEST_DATA_STRING, email, passcode)
            >>> plugin.delete(email)
            True
            >>> plugin.verify(signed_data, email)
            False
        '''

        self.log_message('verify home: {}'.format(self.gpg_home))
        self.log_message('user "{}"; signed data'.format(by_user_id))
        signer = self.get_signer(data)
        if signer is None:
            verified = False
            self.log_message("no signer found")
        else:
            self.log_message('signed by "{}"'.format(signer))
            user_email = get_email(by_user_id)
            signer_email = get_email(signer)
            verified = signer_email == user_email
            if not verified:
                self.log_message('could not verify because signed by "{}" not "{}"'.format(
                    signer, by_user_id))
        self.log_message('verified: {}'.format(verified))

        return verified


    def get_user_id_spec(self, user_id):
        ''' Get user ID spec based on the _user_id_match_method. '''

        if user_id is None:
            user = user_id
        else:
            try:
                user = get_email(user_id)
            except Exception:
                self.log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
                record_exception()
                user = user_id

            # if there's an @ sign and the email address is *not* in angle brackets, then add the brackets
            if (self._user_id_match_method == self.EMAIL_MATCH and
                user.find('@') > 0 and
                user.find('<') < 0 and
                user.find('>') < 0):
                user = "<{}>".format(user)

            # if the match method is exact match and the user doesn't start with an equal sign, prefix =
            elif self._user_id_match_method == self.EXACT_MATCH and not user.startswith("="):
                user = "=" + user

        return user

    def list_packets(self, data, passphrase=None):
        ''' Get a list of packets from the data or None if the data isn't encrypted. '''

        packets = None
        try:
            if data is None or (isinstance(data, str) and len(data.strip()) <= 0):
                self.log_message('no data so no packets')
            else:
                self.log_message('trying to list encrypted packets')
                args = [gpg_constants.LIST_PACKETS]
                result_code, gpg_output, gpg_error = self.gpg_command(
                    args, passphrase=passphrase, data=data)

                if result_code == gpg_constants.GOOD_RESULT:
                    packets = gpg_output
                    self.log_data(packets, "good packets")

                elif result_code == gpg_constants.TIMED_OUT_RESULT:
                    self.log_message('timed out analyzing packets')

                elif gpg_error is not None and gpg_error.find('encrypted with') > 0:
                    packets = gpg_error
                    self.log_data(packets, "bad packets")

        except Exception as exception:
            self.handle_unexpected_exception(exception)

        return packets

    def set_home_dir(self, dirname):
        '''
            Sets the home dir and creates it if it doesn't exist.

            If the dirname doesn't start with /, then prefixes the standard OCE data directory.
            Intended for testing the GPG plugin.
        '''

        command_ok = True

        old_home_dir = self.gpg_home

        if dirname.startswith('/'):
            self.gpg_home = dirname
        else:
            self.gpg_home = os.path.join(OCE_DATA_DIR, dirname)

        if not os.path.exists(self.get_home_dir()):
            self.log_message('unable to change home dir to {}'.format(self.gpg_home))
            self.gpg_home = old_home_dir
            command_ok = False

        return command_ok


    def get_home_dir(self):
        ''' Gets the home dir and create it if it doesn't. '''

        if self.gpg_home == None:
            self.gpg_home = self.GPG_HOME_DIR

        try:
            # create gpg's parent directories, if they don't already exist
            parent_dir = os.path.dirname(self.gpg_home)
            if not os.path.exists(parent_dir):
                statinfo = os.stat(os.path.dirname(parent_dir))
                if statinfo.st_uid == os.geteuid():
                    os.makedirs(parent_dir, 0770)
                    self.log_message('created parent of home dir: {}'.format(parent_dir))
                else:
                    self.log_message('unable to create parent of home dir as {}: {}'.format(os.geteuid(), parent_dir))

            #  create gpg's home directory, if it doesn't exist already
            if not os.path.exists(self.gpg_home):
                statinfo = os.stat(os.path.dirname(self.gpg_home))
                if statinfo.st_uid == os.geteuid():
                    os.mkdir(self.gpg_home, 0700)
                    self.log_message('created home dir: {}'.format(self.gpg_home))
                else:
                    self.log_message('unable to create home dir as {}: {}'.format(os.geteuid(), self.gpg_home))
        except OSError:
            record_exception()
            self.log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
        except Exception as exception:
            self.log_message(exception)
            self.log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
            record_exception()

        return self.gpg_home


    def gpg_command(self, initial_args, passphrase=None, data=None, wait_for_results=True):
        '''
            Issue a gpg command.

            This should be used internally to the gpg classes instead of directly.
            See the public functions that perform gpg commands for better examples.
        '''

        result_code = gpg_constants.ERROR_RESULT
        gpg_output = None
        gpg_error = None

        if gpg_constants.ENCRYPT_DATA in initial_args:
            command = gpg_constants.ENCRYPT_DATA
        elif gpg_constants.DECRYPT_DATA in initial_args:
            command = gpg_constants.DECRYPT_DATA
        else:
            command = initial_args[0]

        # syr.lock.locked() is only a per-process lock
        # syr.lock has a system wide lock, but it is not well tested
        with locked():
            try:
                self.log_message('--- started gpg command: {} ---'.format(command))
                result_code = gpg_constants.ERROR_RESULT
                gpg_output = None
                gpg_error = None

                result_code, gpg_output, gpg_error = self.activate_queue(
                    command, initial_args, passphrase, data, wait_for_results)
            except JobTimeoutException as job_exception:
                self.log_message('gpg command {}'.format(str(job_exception)))
                result_code = gpg_constants.TIMED_OUT_RESULT
            except Exception:
                self.log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
                record_exception()
                result_code = gpg_constants.ERROR_RESULT
                gpg_output = None
                gpg_error = str(exception)
                self.handle_unexpected_exception(exception)
            finally:
                self.log_message('gpg command result_code: {}'.format(result_code))
                self.log_message('--- finished gpg command: {} ---'.format(command))
                self.log.flush()

        return result_code, gpg_output, gpg_error

    def activate_queue(self, command, initial_args, passphrase, data, wait_for_results):
        ''' Run the command and wait for the results if appropriate. '''

        def wait_until_queued(job, job_count):
            ''' Wait until the job is queued or timeout. '''
            secs = 0
            while (not job.is_queued and
                   not job.is_started and
                   not job.is_finished ):
                sleep(1)
                secs += 1
            self.log_message('seconds until {} job was queued: {}'.format(job.get_id(), secs))

        def wait_for_job(command, job):
            ''' Wait until the job finishes or fails.

                Gpg (1.x) is not thread safe. We use a queue yo make sure it
                only has one instance at a time. But we sometimes need to wait
                here in the client for an operation to complete. So we
                simulate a remote procedure call.
            '''

            result_code = gpg_constants.ERROR_RESULT
            gpg_output = gpg_error = None

            try:
                # wait for the job
                with elapsed_time() as job_time:
                    while job.result is None:
                        sleep(1)
                self.log_message('{} job {} elapsed time: {}'.
                    format(command, job.get_id(), job_time))

                if job.is_finished:
                    self.log_message('{} job finished'.format(command))
                elif job.is_failed:
                    self.log_message('{} job failed'.format(command))

                result_code, gpg_output, gpg_error = job.result
                self.log_message('{} job {} result code: {}'.format(command, job.get_id(), result_code))
                if gpg_output is not None: gpg_output = b64decode(gpg_output)
                if gpg_error is not None: gpg_error = b64decode(gpg_error)
                if self.DEBUGGING:
                    if gpg_output: self.log_message(gpg_output)
                    if gpg_error: self.log_message(gpg_error)

                if result_code == gpg_constants.ERROR_RESULT:
                    self.log_message('job.status: {}'.format(job.get_status()))

            except JobTimeoutException as job_exception:
                self.log_message('gpg queue job timed out {}'.format(str(job_exception)))
                result_code = gpg_constants.TIMED_OUT_RESULT

            return result_code, gpg_output, gpg_error

        result_code = gpg_constants.ERROR_RESULT
        gpg_output = gpg_error = None
        try:
            current_job_timeout = self.DEFAULT_TIMEOUT
            if initial_args is None or len(initial_args) <= 0:
                encoded_args = initial_args
            else:
                encoded_args = []
                for arg in initial_args:
                    encoded_args.append(b64encode(arg))
            if passphrase is not None:
                passphrase = b64encode(passphrase)
            if data is not None:
                data = b64encode(data)
                data_length = len(data)
                self.log_message('data length: {}'.format(data_length))
                if data_length > gpg_constants.LARGE_DATA_CHUNK:
                    # set the timeout if the data is large; the timeout
                    # should be a little larger than the gpg timeout
                    current_job_timeout += int(
                      (data_length / gpg_constants.LARGE_DATA_CHUNK) * gpg_constants.TIMEOUT_PER_CHUNK)

            # arguments for the 'gpg' command itself
            gpg_command_args = [self.get_home_dir(), encoded_args, passphrase, data]

            redis_connection = Redis(REDIS_HOST, GPG_REDIS_PORT)
            queue = Queue(name=GPG_RQUEUE, connection=redis_connection)
            self.log_message('jobs waiting in gpg queue {}'.format(queue.count))
            self.log_message('about to queue {}'.format(command))

            # each job needs to wait for the jobs ahead of it so when 
            # calculating the timeout include the jobs already in the queue
            timeout = current_job_timeout * (queue.count + 1)
            self.log_message('{} job timeout in seconds: {}'.format(command, timeout))
            job = queue.enqueue_call(execute_gpg_command, args=gpg_command_args, timeout=timeout)

            if job is None:
                self.log_message('unable to queue {} job'.format(command))
            else:
                job_id = job.get_id()

                self.log_message('{} job: {} times out in {} secs'.format(command, job_id, job.timeout))
                wait_until_queued(job, queue.count)

                self.log_message('wait for {} job results: {}'.format(command, wait_for_results))
                if wait_for_results:
                    result_code, gpg_output, gpg_error = wait_for_job(command, job)
                else:
                    if job.is_failed:
                        result_code = gpg_constants.ERROR_RESULT
                        job_dump = job.dump()
                        if 'exc_info' in job_dump:
                            gpg_error = job_dump['exc_info']
                            log_message('{} job exc info: {}'.format(job_id, error))
                        elif 'status' in job_dump:
                            gpg_error = job_dump['status']
                            self.log_message('{} job status: {}'.format(job_id, gpg_error))
                        self.log_message('job dump:\n{}'.format(job_dump))
                        job.cancel()
                        queue.remove(job_id)

                    elif job.is_queued or job.is_started or job.is_finished:
                        result_code = gpg_constants.GOOD_RESULT
                        self.log_message('{} {} job queued'.format(job_id, queue))

                    else:
                        self.log_message('{} job results: {}'.format(job_id, job.result))

        except Exception as exception:
            gpg_error = str(exception)
            record_exception()
            self.log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

        if isinstance(result_code, bool):
            if result_code:
                result_code = gpg_constants.GOOD_RESULT
            else:
                result_code = gpg_constants.ERROR_RESULT

        return result_code, gpg_output, gpg_error

    def log_data(self, data, message="data"):
        ''' Log data. '''

        if self.DEBUGGING:
            self.log_message("{}:\n{}".format(message, data))

    def log_message(self, message):
        ''' Log a message. '''

        if self.log is None:
            self.log = LogFile()

        self.log.write_and_flush(message)

    def _sign_and_encrypt_now(self, data, from_user_id, to_user_id, passphrase, clear_sign, args):
        '''
            Sign and encrypt the data now. Only used internally. Use one of the public
            functions to sign, encrypt, and armor data, and finally clear sign it.
        '''

        encrypted_data = None

        try:
            if data is None or from_user_id is None or to_user_id is None or passphrase is None:
                self.log_message('Could not encrypt because missing critical info')
            else:
                self.log_data(data)

                result_code, gpg_output, gpg_error = self.gpg_command(
                    args, passphrase=passphrase, data=data, wait_for_results=True)
                self.log_message('results after signing, encrypting, and armoring: {}'.format(result_code))
                if result_code == gpg_constants.GOOD_RESULT:
                    if clear_sign:
                        encrypted_data = self.sign(gpg_output, from_user_id, passphrase)
                        self.log_message('results after clear signing: {}'.format(len(encrypted_data) > 0))
                    else:
                        encrypted_data = gpg_output
        except TypeError as type_error:
            self.handle_unexpected_exception(type_error)
        except Exception as exception:
            self.handle_unexpected_exception(exception)

        return encrypted_data


    def _parse_signer(self, output_string):
        ''' Parse the signer from the gpg command's results. '''

        signer = None

        try:
            if output_string is not None:
                lines = output_string.split('\n')
                for line in lines:
                    if line.startswith(self.GOOD_SIGNATURE_PREFIX):
                        signer = line[len(self.GOOD_SIGNATURE_PREFIX):].strip('"')
                        if len(signer) > 0:
                            break
        except Exception as exception:
            self.handle_unexpected_exception(exception)

        return signer


    def _parse_version(self, version):
        ''' Parse the version from the gpg command's results. '''

        version_number = None

        reader = StringIO(version)
        for l in reader:
            line = l.strip()
            index = line.rfind(' ')
            if index >= 0:
                possibleVersionNumber = line[index + 1:]

                #  make sure we got something resembling "X.Y"
                dotIndex = possibleVersionNumber.find('.')
                if dotIndex > 0 and dotIndex < len(possibleVersionNumber) - 1:
                    version_number = possibleVersionNumber
                else:
                    self.log_message("version number not found in " + line)

            #  stop looking when we find the version
            if version_number != None:
                break

        if version_number == None:
            version_number = ''

        return version_number

