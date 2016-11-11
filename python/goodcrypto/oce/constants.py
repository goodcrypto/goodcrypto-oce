'''
    Constants for OCE.

    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-10-26

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os
from goodcrypto.constants import GOODCRYPTO_DATA_DIR

OCE_DATA_DIR = os.path.join(GOODCRYPTO_DATA_DIR, 'oce')

BEGIN_PGP_MESSAGE = '-----BEGIN PGP MESSAGE-----'
END_PGP_MESSAGE = '-----END PGP MESSAGE-----'

BEGIN_PGP_SIGNED_MESSAGE = '-----BEGIN PGP SIGNED MESSAGE-----'
BEGIN_PGP_SIGNATURE = '-----BEGIN PGP SIGNATURE-----'
END_PGP_SIGNATURE = '-----END PGP SIGNATURE-----'

