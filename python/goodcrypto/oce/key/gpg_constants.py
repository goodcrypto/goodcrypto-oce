'''
    Constant declarations for the GNU Privacy Guard key plugin.

    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-02-08

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''

#  Name of the plugin.
NAME = "goodcrypto.oce.key.gpg_plugin.GPGPlugin"

# prefix for the public key info on import
PUBLIC_KEY_PREFIX = 'gpg: pub'
ALT_KEY_PREFIX = 'gpg: key'

# prefixes for the public key block
USER_ID_PACKET_PREFIX = ':user ID packet'
SIGNATURE_PACKET_PREFIX = ':signature packet'
KEY_ID_LABEL = 'keyid'

# error messages when searching and retrieving keys; must be in lower case
KEYSERVER_PREFIX = 'gpg: '
KEYSERVER_KEY_PREFIX = 'gpgkeys: '
KEYSERVER_CONNECTION_ERROR = "couldn't connect:"
KEYSERVER_CONNECTION_TIMEDOUT = 'connection timed out'
KEYSERVER_TIMEDOUT = 'keyserver timed out'
KEYSERVER_KEY_NOT_FOUND = 'not found on keyserver'

# messages when successful retreiving a key from a keyserver
RETRIEVE_SUCCESS1 = 'gpg: Total number processed: '
RETRIEVE_SUCCESS2 = 'gpg:               imported: '

