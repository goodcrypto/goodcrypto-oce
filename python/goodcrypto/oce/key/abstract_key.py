'''
    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-06-01

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
from abc import abstractmethod
from syr.abstract_python3_class import AbstractPythonClass


class AbstractKey(AbstractPythonClass):
    ''' Key interface for the Open Crypto Engine. '''

    @abstractmethod
    def get_plugin_name(self):
        '''
            Get the plugin's name.

            @return                                              Name of the plugin
        '''


    @abstractmethod
    def get_plugin_version(self):
        '''
            Get the version of this plugin's implementation, i.e. the CORBA servant's version.

            @return                                              Plugin version
        '''


    @abstractmethod
    def get_crypto_version(self):
        '''
            Get the version of the underlying crypto.

            @return                                              Crypto version
        '''


    @abstractmethod
    def is_function_supported(self, func):
        '''
            Returns whether the specified function is supported.

            @param  func  The function to check
            @return       Whether the function is supported
        '''


    @abstractmethod
    def create(self, user_id, passcode, expiration=None, wait_for_results=False):
        '''
            Creating a new key pair.

            @param  user_id                     ID for the new key. This is typically an email address.
            @param  passcode                    Passphrase
            @param  expiration                  Time until the key expires.
        '''


    @abstractmethod
    def delete(self, user_id):
        '''
            Delete an existing key, or key pair, from the keyring.

            @param  user_id                                       ID for the key. This is typically an email address.
        '''


    @abstractmethod
    def export_public(self, user_id):
        '''
            Export a public key from the keyring.

            @param  user_id                                       ID for the key. This is typically an email address.
            @return                                              Public key
        '''


    @abstractmethod
    def import_public(self, data, temporary=False, id_fingerprint_pairs=None):
        '''
            Add a public key to the keyring.

            @param  data                     Public key block.
            @return      List of fingerprints of the user ids imported or an empty list of none imported.
        '''


    @abstractmethod
    def import_temporarily(self, data):
        '''
            Add a public key to a temporary keyring.

            The temporary keyring is destroyed at the end of this function.

            @param  data                    Public key data.
            @return      List of fingerprints of the user ids imported or an empty list of none imported.
        '''


    @abstractmethod
    def get_user_ids_from_key(self, data):
        '''
            Get the user ids from a key block.

            @param  data               Public key block.
            @return   List of user ids or an empty list if no users contained in key block.
        '''


    @abstractmethod
    def is_valid(self, user_id):
        '''
            Whether a key ID is valid.

            @param  user_id                                       ID for the key. This is typically an email address.
            @return                                              Whether the key ID is valid
        '''


    @abstractmethod
    def is_passcode_valid(self, user_id, passcode):
        '''
            Whether the passcode is valid for the user.
        '''


    @abstractmethod
    def private_key_exists(self, user_id):
        '''
            Whether there is a private key for the user.
        '''


    @abstractmethod
    def public_key_exists(self, user_id):
        '''
            Whether there is a public key for the user.
        '''


    @abstractmethod
    def get_fingerprint(self, user_id):
        '''
            Returns a key's fingerprint and the expiration date.

            @param  user_id                                       ID for the key. This is typically an email address.
            @return                                              Fingerprint and expiration
        '''

    @abstractmethod
    def get_user_ids_from_fingerprint(self):
        '''
            Returns a list of user ids associated with the fingerprint.

            @return                                              List of user ids.
        '''

    @abstractmethod
    def get_id_fingerprint_pairs(self, key_block):
        '''
            Returns a key's user id, fingerprint and the expiration date.

            @param  user_id                                       Key block.
            @return                                              Fingerprint, user id, and expiration
        '''

    @abstractmethod
    def fingerprint_expired(self, expiration):
        ''' Determine if the expiration, if there is one, is older than tomorrow. '''


    @abstractmethod
    def search_for_key(self, user_id, keyserver, wait_for_results=False):
        '''
            Search for a key on the keyserver.

            @param  user_id                                       ID for the key. This is typically an email address.
            @param  keyserver                                     The keyserver to search.
            @param  wait_for_results                              Waits for results
            @return                                           OK if search started.
        '''

    @abstractmethod
    def retrieve_key(self, key_id, keyserver, wait_for_results=False):
        '''
            Returns ok if key retrieved successfully.

            @param  key_id                                        ID for the key.
            @param  keyserver                                    The keyserver to use to get key.
            @param  wait_for_results                              Waits for results
            @return                                              OK if successful.
        '''

    @abstractmethod
    def parse_keyserver_search(self, output):
        '''
            Parse the output of a keyserver search.

            @return                 Fingerprint.
        '''

    @abstractmethod
    def parse_keyserver_search_error(self, output, error):
        '''
            Returns an error message after failing to get a key.

            @return                 Error message about failure or none if failure due to key not found.
        '''

    @abstractmethod
    def parse_keyserver_ids_retrieved(self, output):
        '''
            Parse the output of a keyserver key retrieval.

            @return                 Imported ids that were retrieved or an empty list.
        '''

    @abstractmethod
    def parse_create_key_results(self, output):
        '''
            Parse the output from creating a key.

            @return                 Fingerprint of key or None.
        '''

    @abstractmethod
    def get_background_job_results(self, email, key_job, good_result):
        '''
            Returns ok if successful.

            @param  email                                        The email address associated with the job.
            @param  key_job                                      The job number of the background task.
            @param  good_result                                  The result code if successful.
            @return                                              OK if successful, timed_out, output, error
        '''

    @abstractmethod
    def get_good_search_result(self):
        '''
            Returns the result code of a successful search.
        '''

