#! /usr/bin/python
'''
    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-07-28

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
from time import sleep

from goodcrypto.utils.log_file import LogFile
from goodcrypto.oce import gpg_constants
from goodcrypto.oce.crypto_exception import CryptoException
from goodcrypto.oce.crypto_factory import CryptoFactory


class OpenPGPAnalyzer(object):
    '''
        OpenPGP analyzer.

        Currently this is a *very* simply analyzer which relies on GPG to list packets.

        It would be ideal if we could find a packet analyzer as good as
        Bouncy Castle. Perhaps someone has/will build a command line interface
        to allow 3rd party programs to access this excellent java encryption tool.
    '''

    # the gpg --list-packets command takes minutes
    USE_ANALYZER = False

    def __init__(self):
        '''
            >>> analyzer = OpenPGPAnalyzer()
            >>> analyzer != None
            True
        '''

        self.log = None


    def is_encrypted(self, data, passphrase=None, crypto=None):
        '''
            Determines if the data is encrypted.

            >>> from goodcrypto.oce import constants as oce_constants
            >>> plugin = CryptoFactory.get_crypto(CryptoFactory.DEFAULT_ENCRYPTION_NAME)
            >>> encrypted_data = plugin.sign_encrypt_and_armor(
            ...   oce_constants.TEST_DATA_STRING, oce_constants.EDWARD_LOCAL_USER,
            ...   oce_constants.JOSEPH_REMOTE_USER, oce_constants.EDWARD_PASSPHRASE)
            >>> analyzer = OpenPGPAnalyzer()
            >>> analyzer.is_encrypted(
            ...    bytearray(encrypted_data), crypto=plugin, passphrase=oce_constants.EDWARD_PASSPHRASE)
            True
        '''

        encrypted = False

        try:
            if OpenPGPAnalyzer.USE_ANALYZER:
                if crypto is None or 'list_packets' not in dir(crypto):
                    crypto = CryptoFactory.get_crypto(CryptoFactory.DEFAULT_ENCRYPTION_NAME)
                packets = crypto.list_packets(data, passphrase=passphrase)
                encrypted = packets is not None and len(packets) > 0
            else:
                # !! this risks spoofing
                encrypted = (
                    gpg_constants.BEGIN_PGP_MESSAGE in data and
                    gpg_constants.END_PGP_MESSAGE in data)

        except CryptoException as crypto_exception:
            self.log_message(crypto_exception.value)

        self.log_message('data encrypted: {}'.format(encrypted))

        return encrypted


    def is_signed(self, data, crypto=None):
        '''
            Determines if the data is signed.

            >>> from goodcrypto.oce.constants import EDWARD_LOCAL_USER, EDWARD_PASSPHRASE
            >>> plugin = CryptoFactory.get_crypto(CryptoFactory.DEFAULT_ENCRYPTION_NAME)
            >>> signed_data = plugin.sign('This is a test', EDWARD_LOCAL_USER, EDWARD_PASSPHRASE)
            >>> analyzer = OpenPGPAnalyzer()
            >>> analyzer.is_signed(signed_data, crypto=plugin)
            True
        '''

        signed = False

        try:
            if crypto is None:
                crypto = CryptoFactory.get_crypto(CryptoFactory.DEFAULT_ENCRYPTION_NAME)
            signer = crypto.get_signer(data)
            signed = signer is not None and len(signer) > 0
        except CryptoException as crypto_exception:
            self.log_message(crypto_exception.value)

        self.log_message('data signed: {}'.format(signed))

        return signed

    def log_message(self, message):
        '''
            Log the message to the local log.

            >>> import os.path
            >>> from syr.log import BASE_LOG_DIR
            >>> from syr.user import whoami
            >>> OpenPGPAnalyzer().log_message('test')
            >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.oce.open_pgp_analyzer.log'))
            True
        '''

        if self.log is None:
            self.log = LogFile()

        self.log.write_and_flush(message)

