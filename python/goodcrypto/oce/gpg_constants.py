'''
    Public constants for GNU Privacy Guard.

    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-10-26

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os

#  Name of the plugin.
NAME = 'goodcrypto.oce.gpg_plugin.GPGPlugin'

#  Name of the GPG encryption software.
ENCRYPTION_NAME = "GPG"

#  Directory for GPG keyrings.
DIR_NAME = ".gnupg"

#  Filename for GPG's configuration.
CONF_FILENAME = 'gpg.conf'

#  Filename of GPG public keyring.
PUBLIC_KEY_FILENAME = "pubring.gpg"

#  Filename of GPG secret keyring.
SECRET_KEY_FILENAME = "secring.gpg"

#  Filename of GPG trust database.
TRUST_DB_FILENAME = "trustdb.gpg"

# End of line
EOL = os.linesep

# result codes
GOOD_RESULT = 0
ERROR_RESULT = -1
TIMED_OUT_RESULT = -2
CONDITIONAL_RESULT = 2

# suffix for lock files
LOCK_FILE_SUFFIX = ".lock"

# gpg commands
GET_FINGERPRINT = '--fingerprint'
GET_USER_FROM_BLOCK = '--with-fingerprint'
GET_VERSION = '--version'
LIST_PUBLIC_KEYS = '--list-public-keys'
LIST_SECRET_KEYS = '--list-secret-keys'
GEN_KEY = '--gen-key'
EXPORT_KEY = '--export'
IMPORT_KEY = '--import'
DRY_RUN = '--dry-run'

DELETE_KEYS = '--delete-secret-and-public-key'
DELETE_SECRET_KEY = '--delete-secret-key'

DECRYPT_DATA = '--decrypt'
ENCRYPT_DATA = '--encrypt'
ARMOR_DATA = '--armor'
VERIFY = '--verify'
LIST_PACKETS = '--list-packets'

SIGN = '--sign'
CLEAR_SIGN = '--clearsign'
LOCAL_USER = '--local-user'
RECIPIENT = '--recipient'

OPEN_PGP = '--openpgp'
CHARSET = '--charset'
UTF8 = 'utf-8'
WITH_COLONS = '--with-colons'

CHECK_TRUSTDB = '--check-trustdb'
FORCE_TRUSTDB_CHECK = '--yes'

KEYSERVER_NAME = '--keyserver'
SEARCH_KEYSERVER = '--search-key'
RETRIEVE_KEYS = '--recv-keys'

# Used to gen a key
KEY_TYPE = 'Key-Type: '
KEY_LENGTH = 'Key-Length: '
SUBKEY_TYPE = 'Subkey-Type: '
SUBKEY_LENGTH = 'Subkey-Length: '
EXPIRE_DATE = 'Expire-Date: '
KEY_PASSPHRASE = 'Passphrase: '
NAME_REAL = 'Name-Real: '
NAME_EMAIL = 'Name-Email: '
COMMIT_KEY = '%commit'

# used to parse key, fingerprint, uid
PUB_PREFIX = 'pub'
SUB_PREFIX = 'sub'
SEC_PREFIX = "sec"
UID_PREFIX = 'uid'
FINGERPRINT_PREFIX = 'Key fingerprint = '

LARGE_DATA_CHUNK = 1000000
TIMEOUT_PER_CHUNK = 240 # in seconds

# message to alert that key already exists
KEY_EXISTS = 'Key already exists'

