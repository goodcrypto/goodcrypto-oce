'''
    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-08-03

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os, re, shutil
from datetime import date, timedelta
from tempfile import mkdtemp
from time import sleep

from goodcrypto.oce import gpg_constants
from goodcrypto.oce.gpg_plugin import GPGPlugin as GPGCryptoPlugin
from goodcrypto.oce.key import gpg_constants as gpg_key_constants
from goodcrypto.oce.key import gpg_utils
from goodcrypto.oce.key.abstract_key import AbstractKey
from goodcrypto.oce.utils import is_expired, strip_fingerprint
from goodcrypto.utils import parse_address, get_email
from syr.exception import record_exception


class GPGPlugin(GPGCryptoPlugin, AbstractKey):
    '''
        Gnu Privacy Guard crypto key plugin.

        For the functions that usually insist on /dev/tty, use --batch and specify the key by
        using the fingerprint, with no spaces.

        !!!! Warning: Code here should be careful to only allow one instance of gpg at a time.
    '''

    # we want to use RSA for both the master key and all sub-keys
    # DSA appears to have been comprimised because the 'standard' key size
    # is only 1024 which is bad guys likely have rainbow tables to crack
    DefaultKeyLength = '4096'
    DefaultKeyType = 'RSA'
    DefaultSubkeyType = 'RSA'

    def __init__(self):
        '''
            Creates a new GPGPlugin object.

            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> plugin = KeyFactory.get_crypto(gpg_key_constants.NAME)
            >>> plugin != None
            True
        '''

        super(GPGPlugin, self).__init__()


    #@synchronized
    def get_plugin_name(self):
        '''
            Get the plugin's name.

            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> plugin = KeyFactory.get_crypto(gpg_key_constants.NAME)
            >>> plugin.get_plugin_name() == 'goodcrypto.oce.key.gpg_plugin.GPGPlugin'
            True
        '''

        return gpg_key_constants.NAME


    #@synchronized
    def get_plugin_version(self):
        '''
            Get the version of this plugin's implementation.

            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> plugin = KeyFactory.get_crypto(gpg_key_constants.NAME)
            >>> version = plugin.get_plugin_version()
            >>> version is not None
            True
            >>> version == '0.1'
            True
        '''

        return '0.1'


    def is_function_supported(self, func):
        '''
            Returns whether the specified function is supported.

            >>> from goodcrypto.oce.key.constants import CREATE_FUNCTION
            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> plugin = KeyFactory.get_crypto(gpg_key_constants.NAME)
            >>> plugin.is_function_supported(CREATE_FUNCTION)
            True
            >>> plugin.is_function_supported('non_existant_function')
            False
        '''

        try:
            function_supported = func in dir(self)
        except Exception:
            function_supported = False
            record_exception()
            self.log_message('EXCEPTION - see syr.exception.log for details')

        return function_supported

    def create(self, user_id, passcode, expiration=None, wait_for_results=False):
        '''
            Create a new key. If wait_for_results is False, then start the process, but
            don't wait for the results.

            If the key already exists and hasn't expired, then return True without creating a new key.
            If key generated while waiting or key generation started successfully when not waiting,
            then return True; otherwise, False.

            >>> # In honor of Moritz Bartl, advocate for the Tor project.
            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> plugin = KeyFactory.get_crypto(gpg_key_constants.NAME)
            >>> plugin.create('moritz@goodcrypto.local', 'a secret code')
            (True, False, None, False)

            >>> # In honor of Roger Dingledine, one of the original developers of the Tor project.
            >>> from goodcrypto.oce.key.constants import EXPIRES_IN, EXPIRATION_UNIT
            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> email = 'roger@goodcrypto.local'
            >>> plugin = KeyFactory.get_crypto(gpg_key_constants.NAME)
            >>> plugin.create(email, 'a secret code', wait_for_results=True)
            (True, False, None, False)
            >>> while not plugin.private_key_exists(email):
            ...     sleep(10)
            >>> plugin.private_key_exists(email)
            True
            >>> encrypted_data, __ = plugin.encrypt_and_armor('Test data', email)
            >>> unencrypted_data, signed_by, result_code = plugin.decrypt(encrypted_data, 'a secret code')
            >>> result_code == gpg_constants.GOOD_RESULT
            True
            >>> unencrypted_data, signed_by, result_code = plugin.decrypt(encrypted_data, 'another code')
            >>> result_code == gpg_constants.ERROR_RESULT
            True
            >>> plugin.create(email, 'another code', wait_for_results=True)
            (True, False, None, True)
            >>> plugin.delete(email)
            True
        '''

        result_code = gpg_constants.ERROR_RESULT
        result_ok = timed_out = key_already_exists = False
        fingerprint = None
        try:
            self.log_message('gen key for {} that expires within {}'.format(user_id, expiration))

            name, email = parse_address(user_id)
            # gpg requires "real names" be at least 5 characters long
            if name == None or len(name) <= 4:
                index = email.find('@')
                if index > 0:
                    name = email[:index].capitalize()
                else:
                    name = email
                if len(name) <= 4:
                    name = email

            expires_in, expiration_unit = gpg_utils.get_standardized_expiration(expiration)

            data = ''
            data += '{}{}{}'.format(gpg_constants.KEY_TYPE, self.DefaultKeyType, gpg_constants.EOL)
            data += '{}{}{}'.format(gpg_constants.KEY_LENGTH, self.DefaultKeyLength, gpg_constants.EOL)
            data += '{}{}{}'.format(gpg_constants.SUBKEY_TYPE, self.DefaultSubkeyType, gpg_constants.EOL)
            data += '{}{}{}'.format(gpg_constants.SUBKEY_LENGTH, self.DefaultKeyLength, gpg_constants.EOL)
            data += '{}{}{}{}'.format(gpg_constants.EXPIRE_DATE, expires_in, expiration_unit, gpg_constants.EOL)
            data += '{}{}{}'.format(gpg_constants.KEY_PASSPHRASE, passcode, gpg_constants.EOL)
            data += '{}{}{}'.format(gpg_constants.NAME_REAL, name, gpg_constants.EOL)
            data += '{}{}{}'.format(gpg_constants.NAME_EMAIL, email, gpg_constants.EOL)
            data += '{}{}'.format(gpg_constants.COMMIT_KEY, gpg_constants.EOL)

            if GPGPlugin.DEBUGGING:
                self.log_message('Name-Real: {}'.format(name))
                self.log_message('Name-Email: {}'.format(email))
                self.log_message('Expire-Date: {}{}'.format(expires_in, expiration_unit))

            result_code, gpg_output, gpg_error = self.gpg_command(
                [gpg_constants.GEN_KEY], data=data, wait_for_results=wait_for_results)

            if result_code == gpg_constants.GOOD_RESULT:
                fingerprint = gpg_utils.parse_gen_key_results(gpg_error)
                if fingerprint is None:
                    if gpg_output: self.log_message(gpg_output)
                    if gpg_error: self.log_message(gpg_error)

                if gpg_output == gpg_constants.KEY_EXISTS:
                    key_already_exists = True
                    self.log_message('key already exists for {}'.format(email))
            else:
                self.log_message('created key for {} <{}>: {} result code'.format(name, email, result_code))
                if gpg_output: self.log_message(gpg_output)
                if gpg_error: self.log_message(gpg_error)

            result_ok = result_code == gpg_constants.GOOD_RESULT
            self.log_message('result ok: {}'.format(result_ok))
            timed_out = result_code == gpg_constants.TIMED_OUT_RESULT
            self.log_message('timedout: {}'.format(timed_out))

        except Exception as exception:
            self.handle_unexpected_exception(exception)
        finally:
            self.log_message('finished starting to gen key for {}'.format(user_id))

        return result_ok, timed_out, fingerprint, key_already_exists

    def delete(self, user_id):
        '''
            Delete an existing key, or key pair, from the keyring.

            >>> # In honor of Caspar Bowden, advocate for Tor in Europe.
            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> plugin = KeyFactory.get_crypto(gpg_key_constants.NAME)
            >>> plugin.set_home_dir('/var/local/projects/goodcrypto/server/data/test_oce/.gnupg')
            True
            >>> ok, __, __, __ = plugin.create('caspar@goodcrypto.local', 'test passphrase', wait_for_results=True)
            >>> ok
            True
            >>> plugin.delete('caspar@goodcrypto.local')
            True
            >>> plugin.delete('unknown@goodcrypto.local')
            True
            >>> plugin.delete(None)
            False
            >>> from shutil import rmtree
            >>> rmtree('/var/local/projects/goodcrypto/server/data/test_oce')
        '''

        result_ok = True
        try:
            if user_id is None:
                result_ok = False
                self.log_message('no need to delete key for blank user id')
            else:
                address = get_email(user_id)
                self.log_message('deleting: {}'.format(address))
                result_code = gpg_constants.GOOD_RESULT
                while result_code == gpg_constants.GOOD_RESULT:
                    # delete the public and private key -- do *not* include <> or quotes
                    args = [gpg_constants.DELETE_KEYS, address]
                    result_code, gpg_output, gpg_error= self.gpg_command(args)
                    if result_code == gpg_constants.GOOD_RESULT:
                        result_ok = True
                        if gpg_output and len(gpg_output.strip()) > 0: self.log_message(gpg_output)
                        if gpg_error and len(gpg_error.strip()) > 0: self.log_message(gpg_error)

        except Exception as exception:
            result_ok = False
            record_exception()
            self.log_message('EXCEPTION - see syr.exception.log for details')
            self.handle_unexpected_exception(exception)

        self.log_message('delete ok: {}'.format(result_ok))

        return result_ok


    def delete_private_key_only(self, user_id):
        '''
            Delete an existing secret key from the keyring.

            GPG (as of 1.2.3) has a bug that allows more than ine unrelated key to
            have the same user id.
            If there is more than one key that matches the user id, all will be deleted.

            >>> # In honor of Griffin Boyce, a developer for browser extensions to let
            >>> # people volunteer to become a Flash Proxy for censored users.
            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> plugin = KeyFactory.get_crypto(gpg_key_constants.NAME)
            >>> plugin.set_home_dir('/var/local/projects/goodcrypto/server/data/test_oce/.gnupg')
            True
            >>> ok, __, __, __ = plugin.create('griffin@goodcrypto.local', 'test passphrase', wait_for_results=True)
            >>> ok
            True
            >>> plugin.delete_private_key_only('unknown@goodcrypto.local')
            False
            >>> plugin.delete_private_key_only(None)
            False
            >>> plugin.delete_private_key_only('griffin@goodcrypto.local')
            True
            >>> from shutil import rmtree
            >>> rmtree('/var/local/projects/goodcrypto/server/data/test_oce')
        '''

        result_code = gpg_constants.ERROR_RESULT
        self.log_message('delete private key for user_id: {}'.format(user_id))
        try:
            # batch mode requires that we use the fingerprint instead of the email address
            fingerprint, expiration = self.get_fingerprint(user_id)
            if expiration:
                self.log_message('{} key expired on {}'.format(user_id, expiration))

            result_ok = fingerprint is not None
            if result_ok:
                # delete the private key
                args = [gpg_constants.DELETE_SECRET_KEY, fingerprint]
                result_code, gpg_output, gpg_error= self.gpg_command(args)
                if result_code != gpg_constants.GOOD_RESULT:
                    message = 'unable to delete private key for {}: {}'.format(user_id, result_code)
                    self.log_message(message)
                    if gpg_output: self.log_message(gpg_output)
                    if gpg_error: self.log_message(gpg_error)
        except Exception as exception:
            result_code = gpg_constants.ERROR_RESULT
            self.handle_unexpected_exception(exception)

        self.log_message('delete private key only result_code: {}'.format(result_code == gpg_constants.GOOD_RESULT))

        return result_code == gpg_constants.GOOD_RESULT


    def export_public(self, user_id):
        '''
            Export a public key from the keyring.

            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> filename = '/var/local/projects/goodcrypto/server/tests/mail/pubkeys/joseph@goodcrypto.remote.gpg.pub'
            >>> with open(filename) as f:
            ...    data = f.read()
            ...    plugin = KeyFactory.get_crypto(gpg_key_constants.NAME)
            ...    plugin.set_home_dir('/var/local/projects/goodcrypto/server/data/test_oce/.gnupg')
            ...    plugin.import_public(data)
            ...    len(plugin.export_public('joseph@goodcrypto.remote')) > 0
            True
            True
            True

            >>> plugin = KeyFactory.get_crypto(gpg_key_constants.NAME)
            >>> plugin.set_home_dir('/var/local/projects/goodcrypto/server/data/test_oce/.gnupg')
            True
            >>> plugin.export_public('unknown@goodcrypto.remote')
            ''
            >>> plugin.export_public(None) is None
            True
            >>> from shutil import rmtree
            >>> rmtree('/var/local/projects/goodcrypto/server/data/test_oce')
        '''

        public_key = None
        try:
            if user_id:
                args = [gpg_constants.EXPORT_KEY, gpg_constants.ARMOR_DATA, self.get_user_id_spec(user_id)]
                result_code, gpg_output, gpg_error= self.gpg_command(args)
                if result_code == gpg_constants.GOOD_RESULT:
                    public_key = gpg_output
                    self.log_message('len public key: {}'.format(len(public_key)))
                else:
                    self.log_message('exporting key result code: {}'.format(result_code))
                    if GPGPlugin.DEBUGGING:
                        if gpg_output: self.log_message(gpg_output)
                        if gpg_error: self.log_message(gpg_error)
        except Exception as exception:
            self.handle_unexpected_exception(exception)

        return public_key


    def import_public(self, data, temporary=False, id_fingerprint_pairs=None):
        '''
            Import a public key to the keyring.

            Some crypto engines will allow more than one public key to be imported at
            one time, but applications should not rely on this.

            GPG (as of 1.2.3) has a bug that allows import of a key that matches the user
            id of an existing key. GPG then does not handle keys for that user id properly.
            This method deletes any existing matching keys.

            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> filename = '/var/local/projects/goodcrypto/server/tests/mail/pubkeys/laura@goodcrypto.remote.gpg.pub'
            >>> with open(filename) as f:
            ...    data = f.read()
            ...    plugin = KeyFactory.get_crypto(gpg_key_constants.NAME)
            ...    plugin.set_home_dir('/var/local/projects/goodcrypto/server/data/test_oce/.gnupg')
            ...    plugin.import_public(data)
            True
            True
            >>> plugin = KeyFactory.get_crypto(gpg_key_constants.NAME)
            >>> plugin.set_home_dir('/var/local/projects/goodcrypto/server/data/test_oce/.gnupg')
            True
            >>> plugin.import_public(None)
            False
            >>> from shutil import rmtree
            >>> rmtree('/var/local/projects/goodcrypto/server/data/test_oce')
        '''

        def remove_matching_keys(id_fingerprint_pairs):
           # delete every user id that matches
            for (user_id, fingerprint) in id_fingerprint_pairs:
                try:
                    self.delete(user_id)
                except Exception:
                    record_exception()
                    self.log_message('EXCEPTION - see syr.exception.log for details')

        try:
            result_ok = False
            if data and len(data.strip()) > 0:

                if GPGCryptoPlugin.DEBUGGING:
                    self.log_message('importing data:\n{}'.format(data))
                args = [gpg_constants.IMPORT_KEY]

                if not temporary:
                    if id_fingerprint_pairs is None:
                        id_fingerprint_pairs = self.get_id_fingerprint_pairs(data)
                        self.log_message('id fingerprint pairs: {}'.format(id_fingerprint_pairs))

                    remove_matching_keys(id_fingerprint_pairs)

                result_code, gpg_output, gpg_error= self.gpg_command(args, data=data)
                if result_code == gpg_constants.GOOD_RESULT:
                    result_ok = True
                else:
                    result_ok = False
                    message = "result code: {}\n".format(result_code)
                    try:
                        message = "stdout: {}\n".format(gpg_output)
                        message += "stderr: {}".format(gpg_error)
                    except:
                        pass
                    self.log_message(message)

        except Exception as exception:
            result_ok = False
            self.handle_unexpected_exception(exception)

        return result_ok


    def import_temporarily(self, data):
        '''
            Import a public key to a temporary keyring.

            The temporary keyring is destroyed at the end of this function.

            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> filename = '/var/local/projects/goodcrypto/server/tests/mail/pubkeys/laura@goodcrypto.remote.gpg.pub'
            >>> with open(filename) as f:
            ...    data = f.read()
            ...    plugin = KeyFactory.get_crypto(gpg_key_constants.NAME)
            ...    plugin.set_home_dir('/var/local/projects/goodcrypto/server/data/test_oce/.gnupg')
            ...    plugin.import_temporarily(data)
            True
            True

            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> plugin = KeyFactory.get_crypto(gpg_key_constants.NAME)
            >>> plugin.set_home_dir('/var/local/projects/goodcrypto/server/data/test_oce/.gnupg')
            True
            >>> plugin.import_temporarily(None)
            False
        '''

        result_ok = False

        try:
            self.log_message('importing key block temporarily')
            if data and len(data) > 0:
                if GPGCryptoPlugin.DEBUGGING:
                    self.log_message('imported data temporarily:\n{}'.format(data))

                original_home_dir = self.get_home_dir()
                temp_home_dir = mkdtemp()
                self.log_message('setting home to temp dir: {}'.format(temp_home_dir))
                self.set_home_dir(temp_home_dir)

                result_ok = self.import_public(data, temporary=True)
                self.log_message('temporary import ok: {}'.format(result_ok))

                self.set_home_dir(original_home_dir)
                shutil.rmtree(temp_home_dir, ignore_errors=True)
                self.log_message('restored home dir and destroyed temp dir')
        except:
            record_exception()

        return result_ok


    def get_user_ids_from_key(self, data):
        '''
            Get the user ids from a public key block.

            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> plugin = KeyFactory.get_crypto(gpg_key_constants.NAME)
            >>> dirname = '/var/local/projects/goodcrypto/server/tests/mail/pubkeys'
            >>> filename = '{}/laura@goodcrypto.remote.gpg.pub'.format(dirname)
            >>> with open(filename) as f:
            ...    data = f.read()
            ...    user_ids = plugin.get_user_ids_from_key(data)
            ...    user_ids == ['laura@goodcrypto.remote']
            True
            >>> plugin.get_user_ids_from_key(None)
            []
        '''

        try:
            user_ids = []
            id_fingerprint_pairs = self.get_id_fingerprint_pairs(data)
            if id_fingerprint_pairs is not None:
                for (user_id, __) in id_fingerprint_pairs:
                    user_ids.append(user_id)
            self.log_message('extracted user ids: {}'.format(user_ids))
        except Exception:
            user_ids = []
            record_exception()
            self.log_message('EXCEPTION - see syr.exception.log for details')

        return user_ids


    def is_valid(self, user_id):
        '''
            Returns whether a key ID is valid.
            This just checks for a fingerprint and makes sure it's not expired.
            There is no check for a public key, or private key, or both.

            >>> # In honor of Colin Childs, translation coordinator and end user support for Tor project.
            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> plugin = KeyFactory.get_crypto(gpg_key_constants.NAME)
            >>> plugin.set_home_dir('/var/local/projects/goodcrypto/server/data/test_oce/.gnupg')
            True
            >>> ok, __, __, __ = plugin.create('colin@goodcrypto.local', 'test passphrase', wait_for_results=True)
            >>> ok
            True
            >>> plugin.is_valid('colin@goodcrypto.local')
            True
            >>> plugin.is_valid('unknown@goodcrypto.local')
            False
            >>> plugin.is_valid('expired_user@goodcrypto.local')
            False
            >>> from shutil import rmtree
            >>> rmtree('/var/local/projects/goodcrypto/server/data/test_oce')
        '''

        fingerprint, expiration = self.get_fingerprint(user_id)
        valid = fingerprint is not None
        if valid and expiration is not None:
            valid = not self.fingerprint_expired(expiration)

        return valid

    def is_passcode_valid(self, user_id, passcode, key_exists=False):
        '''
            Returns whether the passcode is valid for the user. It ignores
            whether the private key has expired or not.

            >>> # In honor of Erinn Clark, developer of installer for Tor project.
            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> plugin = KeyFactory.get_crypto(gpg_key_constants.NAME)
            >>> plugin.set_home_dir('/var/local/projects/goodcrypto/server/data/test_oce/.gnupg')
            True
            >>> ok, __, __, __ = plugin.create('erinn@goodcrypto.local', 'test passphrase', wait_for_results=True)
            >>> ok
            True
            >>> plugin.is_passcode_valid('Erinn@goodcrypto.local', 'test passphrase')
            True
            >>> plugin.is_passcode_valid('Erinn <erinn@goodcrypto.local>', 'test passphrase')
            True
            >>> plugin.is_passcode_valid('erinn@goodcrypto.local', 'bad passphrase')
            False
            >>> from shutil import rmtree
            >>> rmtree('/var/local/projects/goodcrypto/server/data/test_oce')
        '''

        valid = False

        if user_id is None or passcode is None:
            valid = False
            self.log_message('missing user id ({}) and/or passcode'.format(user_id))

        else:
            self.log_message('-- starting is_passcode_valid --')

            try:
                if key_exists or self.private_key_exists(user_id):
                    self.log_message('found private key for {}'.format(user_id))

                    # verify the passphrase is correct
                    signed_data, error_message = self.sign('Test data', user_id, passcode)
                    if signed_data and signed_data.find(self.get_begin_pgp_signed_message()) >= 0:
                        valid = True
                    elif error_message is not None:
                        self.log_message(error_message)
                else:
                    self.log_message('unable to find private key for {}'.format(user_id))
            except Exception:
                record_exception()
                self.log_message('EXCEPTION - see syr.exception.log for details')

            self.log_message('-- finished is_passcode_valid --')

        self.log_message('{} passcode valid: {}'.format(user_id, valid))

        return valid

    def private_key_exists(self, user_id):
        '''
            Returns whether there is a private key for the user. It ignores
            whether the private key has expired or not.

            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> plugin = KeyFactory.get_crypto(gpg_key_constants.NAME)
            >>> plugin.set_home_dir(plugin.GPG_HOME_DIR)
            True
            >>> plugin.private_key_exists('edward@goodcrypto.local')
            True
            >>> plugin.private_key_exists('Ed <edward@goodcrypto.local>')
            True
        '''

        key_exists = False

        if user_id is None:
            key_exists = False
            self.log_message('missing user id so unable to see if private key exists')

        else:
            try:
                email = get_email(user_id)
                args = [gpg_constants.LIST_SECRET_KEYS, self.get_user_id_spec(email)]
                result_code, gpg_output, gpg_error= self.gpg_command(args)
                key_exists = result_code == gpg_constants.GOOD_RESULT

                self.log_message('found private key for {}: {}'.format(user_id, key_exists))
            except Exception:
                record_exception()
                self.log_message('EXCEPTION - see syr.exception.log for details')

        return key_exists

    def public_key_exists(self, user_id):
        '''
            Returns whether there is a public key for the user. It ignores
            whether the public key has expired or not.

            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> plugin = KeyFactory.get_crypto(gpg_key_constants.NAME)
            >>> plugin.set_home_dir(plugin.GPG_HOME_DIR)
            True
            >>> plugin.public_key_exists('edward@goodcrypto.local')
            True
            >>> plugin.public_key_exists('Ed <edward@goodcrypto.local>')
            True
        '''

        key_exists = False

        if user_id is None:
            key_exists = False
            self.log_message('missing user id ({})'.format(user_id))

        else:
            try:
                email = get_email(user_id)
                args = [gpg_constants.LIST_PUBLIC_KEYS, self.get_user_id_spec(email)]
                result_code, gpg_output, gpg_error= self.gpg_command(args)
                key_exists = result_code == gpg_constants.GOOD_RESULT

                self.log_message('found public key for {}: {}'.format(user_id, key_exists))
            except Exception:
                record_exception()
                self.log_message('EXCEPTION - see syr.exception.log for details')

        return key_exists

    def check_trustdb(self):
        ''' Force gpg to check the trust DB. '''

        result_code = gpg_constants.ERROR_RESULT
        try:
            args = [gpg_constants.CHECK_TRUSTDB, gpg_constants.FORCE_TRUSTDB_CHECK]
            result_code, gpg_output, gpg_error= self.gpg_command(args)

            if result_code == gpg_constants.GOOD_RESULT or result_code == gpg_constants.CONDITIONAL_RESULT:
                self.log_message('trustdb checked')

            elif result_code == gpg_constants.TIMED_OUT_RESULT:
                self.log_message('timed out checking trustdb')

            else:
                self.log_message('error while checking trustdb')
                if gpg_output: self.log_message('gpg output: {}'.format(gpg_output))
                if gpg_error: self.log_message('gpg error: {}'.format(gpg_error))

        except Exception as exception:
            self.handle_unexpected_exception(exception)

        return result_code

    def get_fingerprint(self, user_id):
        '''
            Returns a key's fingerprint and expiration.

            Test extreme case
            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> plugin = KeyFactory.get_crypto(gpg_key_constants.NAME)
            >>> plugin.set_home_dir(plugin.GPG_HOME_DIR)
            True
            >>> plugin.get_fingerprint(None)
            (None, None)
        '''

        fingerprint = expiration_date = None
        try:
            email = get_email(user_id)
            self.log_message('getting fingerprint for {}'.format(email))

            # add angle brackets around the email address so we don't
            # confuse the email with any similar addresses and non-ascii characters are ok
            args = [gpg_constants.GET_FINGERPRINT, self.get_user_id_spec(email)]
            result_code, gpg_output, gpg_error= self.gpg_command(args)
            if result_code == gpg_constants.GOOD_RESULT:
                if GPGPlugin.DEBUGGING: self.log_message('fingerprint gpg output: {}'.format(gpg_output))
                fingerprint, expiration_date = gpg_utils.parse_fingerprint_and_expiration(gpg_output)
                self.log_message('{} fingerprint: {}'.format(email, fingerprint))
                self.log_message('{} expiration_date: {}'.format(email, expiration_date))
            # unable to get key
            elif result_code == gpg_constants.CONDITIONAL_RESULT:
                self.log_message(gpg_error.strip())
            else:
                errors = gpg_error
                if errors is not None:
                    errors = gpg_error
                self.log_message('gpg command had errors')
                self.log_message('  result code: {} / gpg error'.format(result_code))
                self.log_message(errors)
        except Exception as exception:
            self.handle_unexpected_exception(exception)

        return fingerprint, expiration_date

    def get_user_ids_from_fingerprint(self, fingerprint):
        '''
            Returns a list of user ids associated with the fingerprint.

            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> plugin = KeyFactory.get_crypto(gpg_key_constants.NAME)
            >>> plugin.get_user_ids_from_fingerprint(None)
            []
        '''

        ids = []
        try:
            args = [gpg_constants.GET_FINGERPRINT]
            result_code, gpg_output, gpg_error= self.gpg_command(args)
            if result_code == gpg_constants.GOOD_RESULT:
                if GPGPlugin.DEBUGGING: self.log_message(
                  'get_user_ids_from_fingerprint gpg output: {}'.format(gpg_output))
                ids = gpg_utils.parse_ids_matching_key_id(fingerprint, gpg_output)
            # unable to get any fingerprints
            elif result_code == gpg_constants.CONDITIONAL_RESULT:
                self.log_message(gpg_error.strip())
            else:
                errors = gpg_error
                if errors is not None:
                    errors = gpg_error
                self.log_message('gpg command had errors')
                self.log_message('  result code: {} / gpg error'.format(result_code))
                self.log_message(errors)
            self.log_message('user ids associated with {}: {}'.format(fingerprint, ids))
        except Exception as exception:
            self.handle_unexpected_exception(exception)

        return ids

    def get_id_fingerprint_pairs(self, data):
        '''
            Returns a key's fingerprint and user id pairs.

            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> plugin = KeyFactory.get_crypto(gpg_key_constants.NAME)
            >>> plugin.get_id_fingerprint_pairs(None)
            []
        '''

        id_fingerprint_pairs = []
        try:
            if data is None or len(data.strip()) <= 0:
                self.log_message('no key block to get fingerprint')
            else:
                if self.DEBUGGING:
                    self.log_message('getting fingerprint from key block:\n{}'.format(data))

                args = [gpg_constants.GET_USER_FROM_BLOCK]
                result_code, gpg_output, gpg_error= self.gpg_command(args, data=data)
                if result_code == gpg_constants.GOOD_RESULT:
                    if GPGPlugin.DEBUGGING: self.log_message('block fingerprint gpg output: {}'.format(gpg_output))
                    id_fingerprint_pairs = gpg_utils.parse_id_fingerprint_pairs(gpg_output)
                    self.log_message('user id and fingerprint pairs: {}'.format(id_fingerprint_pairs))
                # unable to get fingerprints
                elif result_code == gpg_constants.CONDITIONAL_RESULT:
                    self.log_message(gpg_error.strip())
                else:
                    errors = gpg_error
                    if errors is not None:
                        errors = gpg_error
                    self.log_message('gpg command had errors')
                    self.log_message('  result code: {} / gpg error'.format(result_code))
                    self.log_message(errors)
        except Exception as exception:
            self.handle_unexpected_exception(exception)

        return id_fingerprint_pairs

    def fingerprint_expired(self, expiration_date):
        '''
            Determine if this date, if there is one, has expired.

            Test extreme case.
            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> plugin = KeyFactory.get_crypto(gpg_key_constants.NAME)
            >>> plugin.fingerprint_expired(None)
            False
        '''

        return is_expired(expiration_date)

    def search_for_key(self, user_id, keyserver, wait_for_results=False):
        '''
            Returns a key's ID if found. If not returns the error message from attempt.

            # Test extreme cases
            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> plugin = KeyFactory.get_crypto(gpg_key_constants.NAME)
            >>> plugin.search_for_key('chelsea@goodcrypto.local', None)
            (None, None)
            >>> plugin.search_for_key(None, 'www.uk.pgp.net')
            (None, None)
            >>> plugin.search_for_key(None, None)
            (None, None)
        '''

        key_id = error_message = None

        if user_id is None:
            self.log_message('missing user id so cannot search for key from keyserver')

        elif keyserver is None:
            self.log_message('missing keyserver so cannot search for key')

        else:
            try:
                email = get_email(user_id)
                args = [
                  gpg_constants.KEYSERVER_NAME, keyserver,
                  gpg_constants.SEARCH_KEYSERVER, self.get_user_id_spec(email)
                ]
                result_code, gpg_output, gpg_error = self.gpg_command(args, wait_for_results=wait_for_results)
                if result_code == gpg_constants.CONDITIONAL_RESULT:
                    key_id = self.parse_keyserver_search(gpg_output)

                if wait_for_results:
                    if key_id is None:
                        combined_output = '{}\n{}'.format(gpg_output.lower(), gpg_error.lower())
                        if gpg_key_constants.KEYSERVER_CONNECTION_ERROR in combined_output:
                            error_message = 'Unable to connect to server'
                        elif (gpg_key_constants.KEYSERVER_CONNECTION_TIMEDOUT in combined_output or
                              gpg_key_constants.KEYSERVER_TIMEDOUT in combined_output):
                            error_message = 'Timed out connecting to server'
                        elif gpg_key_constants.KEYSERVER_KEY_NOT_FOUND in combined_output:
                            # we don't need to record this error as it's not an error with the server
                            error_message = None
                        else:
                            error_message = gpg_error
                            self.log_message('result code: {}'.format(result_code))
                            self.log_message('gpg output: {}'.format(gpg_output))

                    self.log_message('found key for {}: {}'.format(user_id, key_id is not None))
                    if error_message is not None:
                        self.log_message('error message: {}'.format(error_message))
                else:
                    self.log_message('result code after starting keyserver search on {} for {}: {}'.format(
                        email, keyserver, result_code))

            except Exception:
                record_exception()
                self.log_message('EXCEPTION - see syr.exception.log for details')

        return key_id, error_message


    def retrieve_key(self, key_id, keyserver, wait_for_results=False):
        '''
            Returns ok if key retrieved successfully.

            # Test extreme cases
            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> plugin = KeyFactory.get_crypto(gpg_key_constants.NAME)
            >>> plugin.retrieve_key('F2AD85AC1E42B367', None)
            False
            >>> plugin.retrieve_key(None, 'www.uk.pgp.net')
            False
            >>> plugin.retrieve_key(None, None)
            False
        '''

        result_ok = False

        if key_id is None:
            self.log_message('missing key id so cannot retrieve key from keyserver')

        elif keyserver is None:
            self.log_message('missing keyserver so cannot retrieve key for {}'.format(key_id))

        else:
            try:
                args = [
                  gpg_constants.KEYSERVER_NAME, keyserver,
                  gpg_constants.RETRIEVE_KEYS, strip_fingerprint(key_id)
                ]
                result_code, gpg_output, gpg_error= self.gpg_command(args, wait_for_results=wait_for_results)
                result_ok = result_code == gpg_constants.GOOD_RESULT

            except Exception:
                record_exception()
                self.log_message('EXCEPTION - see syr.exception.log for details')

            finally:
                if wait_for_results:
                    self.log_message('retrieved key for {}: {}'.format(key_id, result_ok))
                else:
                    self.log_message('finished starting to retrieve key for {}'.format(key_id))

        return result_ok

    def parse_keyserver_search(self, output):
        '''
            Parse the output of a keyserver search.

            Test extreme case.
            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> plugin = KeyFactory.get_crypto(gpg_key_constants.NAME)
            >>> results = plugin.parse_keyserver_search(None)
            >>> results == None
            True
        '''

        return gpg_utils.parse_search_results(output)

    def parse_keyserver_search_error(self, output, error):
        '''
            Returns an error message after failing to get a key.

            Test extreme cases.
            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> plugin = KeyFactory.get_crypto(gpg_key_constants.NAME)
            >>> error = plugin.parse_keyserver_search_error(None, None)
            >>> error is None
            True
        '''

        return gpg_utils.parse_search_error(output, error)

    def parse_keyserver_ids_retrieved(self, output):
        '''
            Parse the output of a keyserver key retrieval.

            Test extreme case.
            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> plugin = KeyFactory.get_crypto(gpg_key_constants.NAME)
            >>> plugin.parse_keyserver_ids_retrieved(None)
            []
        '''

        imported_ids, corrupted_ids = gpg_utils.parse_ids_retrieved(output)

        # remove any corrupted ids
        if len(corrupted_ids) > 0:
            for corrupted_id in corrupted_ids:
                args = [gpg_constants.DELETE_KEYS, corrupted_id]
                result_code, gpg_output, gpg_error= self.gpg_command(args)
                if gpg_output and len(gpg_output.strip()) > 0: self.log_message(gpg_output)
                if gpg_error and len(gpg_error.strip()) > 0: self.log_message(gpg_error)

        return imported_ids

    def parse_create_key_results(self, output):
        '''
            Parse the output from creating a key.
        '''

        return gpg_utils.parse_gen_key_results(output)

    def get_background_job_results(self, email, key_job, good_result=gpg_constants.GOOD_RESULT):
        '''
            Get the results from the a job (e.g., gen-key) if not waiting for results.
            This allows another function to run after the first job finishes
            without waiting, but instead using RQ's depends_on function.

            Test extreme case
            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> plugin = KeyFactory.get_crypto(gpg_key_constants.NAME)
            >>> plugin.get_background_job_results(None, None)
            (False, False, None, None)
        '''
        result_code = gpg_constants.ERROR_RESULT
        result_ok = timed_out = False
        gpg_output = gpg_error = job_id = None
        try:
            job_id = key_job.get_id()
            self.log_message('good result code for {} background job: {}'.format(job_id, good_result))
            result_code, gpg_output, gpg_error = key_job.result
            self.log_message('{} background job result code: {}'.format(job_id, result_code))

            if result_code == good_result:
                if self.DEBUGGING:
                    if gpg_output: self.log_message(gpg_output)
                    if gpg_error: self.log_message(gpg_error)
            else:
                self.log_message('error while running background job for {}: {} result code'.format(
                     email, result_code))
                if gpg_output: self.log_message('output: {}'.format(gpg_output))
                if gpg_error:
                    self.log_message('error: {}'.format(gpg_error))
                    if 'timed out' in gpg_error:
                        timed_out = True

                # only use the result code if the output hasn't already shown a timeout
                if not timed_out:
                    timed_out = result_code == gpg_constants.TIMED_OUT_RESULT
                self.log_message('timedout: {}'.format(timed_out))

            result_ok = result_code == good_result
            self.log_message('result ok: {}'.format(result_ok))

        except Exception as exception:
            self.handle_unexpected_exception(exception)
        finally:
            self.log_message('finished background {} job for {}'.format(job_id, email))

        return result_ok, timed_out, gpg_output, gpg_error

    def get_good_search_result(self):
        '''
            Returns the result code of a successful search.

            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> plugin = KeyFactory.get_crypto(gpg_key_constants.NAME)
            >>> plugin.get_good_search_result()
            2
        '''

        return gpg_constants.CONDITIONAL_RESULT


