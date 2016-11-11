'''
    Basic utilities for crypto.

    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-08-03

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
from datetime import date

from goodcrypto.utils.log_file import LogFile
from syr.exception import record_exception

_log = LogFile()

def format_fingerprint(fingerprint):
    '''
        Format a fingerprint so it's more readable.

        >>> format_fingerprint(None)
    '''

    if fingerprint is None or len(fingerprint.strip()) <= 0:
        formatted_fingerprint = fingerprint
    else:
        if fingerprint.strip().find(' ') <= 0:
            cluster = ''
            formatted_fingerprint = ''
            for letter in fingerprint:
                cluster += letter
                if len(cluster) % 4 == 0:
                    cluster += ' '
                    formatted_fingerprint += cluster
                    cluster = ''
            formatted_fingerprint = formatted_fingerprint.strip()
        else:
            formatted_fingerprint = fingerprint

    return formatted_fingerprint

def strip_fingerprint(fingerprint):
    '''
        Strip the fingerprint of all spaces.

        >>> fingerprint = strip_fingerprint('D106 3C24 9F55 FFE3 0DC7 80DF D90F 1880 8F6C CF14')
        >>> fingerprint == 'D1063C249F55FFE30DC780DFD90F18808F6CCF14'
        True
        >>> fingerprint = strip_fingerprint('')
        >>> fingerprint == ''
        True
        >>> strip_fingerprint(None)
    '''

    if fingerprint is not None:
        space_position = fingerprint.find(' ')
        while space_position >= 0:
            #  remove each space until there aren't any
            fingerprint = fingerprint[0: space_position] + fingerprint[space_position + 1:]
            space_position = fingerprint.find(' ')

    return fingerprint

def is_expired(this_date):
    '''
        Determine if this date, if there is one, is older than tomorrow.

        >>> is_expired('2013-06-05')
        True
        >>> is_expired('2020-06-05')
        False
        >>> is_expired(None)
        False
    '''

    expired = False
    if this_date:
        try:
            year, month, day = this_date.split('-')
            expired_date = date(int(year), int(month), int(day))
            expired = expired_date <= date.today()
        except Exception:
            record_exception()
            _log.write('EXCEPTION - see syr.exception.log for details')

    return expired


