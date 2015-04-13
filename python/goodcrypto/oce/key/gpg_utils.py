#!/usr/bin/env python
'''
    Copyright 2014 GoodCrypto
    Last modified: 2014-11-26

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import re
from datetime import date
from traceback import format_exc

from goodcrypto.oce import gpg_constants
from goodcrypto.oce.key.constants import EXPIRES_IN, EXPIRATION_UNIT
from goodcrypto.oce.utils import parse_address, strip_fingerprint
from goodcrypto.utils.log_file import LogFile

_log = LogFile()


def parse_id_fingerprint_pairs(output):
    '''
        Parse the output for the user ids and fingerprints.
        
        >>> output = 'pub  1024D/0x68B7AB8957548DCD 1998-07-07 Werner Koch (gnupg sig) <dd9jn@gnu.org>\\n      Key fingerprint = 6BD9 050F D8FC 941B 4341  2DCC 68B7 AB89 5754 8DCD\\n'
        >>> parse_id_fingerprint_pairs(output)

        >>> output = 'pub  4096R/0x07E937498DD94D6F 2014-08-12 GoodCrypto Sales <sales@goodcrypto.com>\\n      Key fingerprint = 7B68 BCA9 6AC8 1F28 4DCE  B651 07E9 3749 8DD9 4D6F\\nsub   4096R/0x2454F32D0D358942 2014-08-12 [expires: 2015-08-12]\\n      Key fingerprint = B1FE D773 7F0C BB29 BA9F  CDD7 2454 F32D 0D35 8942'
        >>> parse_id_fingerprint_pairs(output)
        [('sales@goodcrypto.com', '7B68 BCA9 6AC8 1F28 4DCE  B651 07E9 3749 8DD9 4D6F')]

        >>> parse_id_fingerprint_pairs(None)
    '''

    def add_pair_and_reset(email, fingerprint):
        ''' Add the id and fingerprint pair to the list. '''
        ids_fingerprints.append((email, fingerprint))
        
        # reset the info
        email = fingerprint = None
        
        return email

    ids_fingerprints = []
    if output is not None:
        # pub  1024D/0x68B7AB8957548DCD 1998-07-07 Werner Koch (gnupg sig) <dd9jn@gnu.org>
        #       Key fingerprint = 6BD9 050F D8FC 941B 4341  2DCC 68B7 AB89 5754 8DCD
        # pub  1024R/0x53B620D01CE0C630 2006-01-01 Werner Koch (dist sig) <dd9jn@gnu.org>
        #       Key fingerprint = 7B96 D396 E647 1601 754B  E4DB 53B6 20D0 1CE0 C630
        # pub  2048D/0xF2AD85AC1E42B367 2007-12-31 Werner Koch <wk@g10code.com>
        #       Key fingerprint = 8061 5870 F5BA D690 3336  86D0 F2AD 85AC 1E42 B367
        # uid                            Werner Koch <wk@gnupg.org>
        # uid                            Werner Koch <werner@eifzilla.de>
        # sub  2048R/0x8117B6EBFA8FE1F9 2008-03-21 [expires: 2011-12-30]
        #       Key fingerprint = 7BF8 0623 7C8E FE18 73B3  26DE 8117 B6EB FA8F E1F9
        # sub  1024D/0x4F0540D577F95F95 2011-11-02
        #       Key fingerprint = E4B8 68C8 F90C 8964 B5AF  9DBC 4F05 40D5 77F9 5F95
        # sub  2048R/0xDF7B7722C193565B 2011-11-07 [expires: 2013-12-31]
        #       Key fingerprint = 21D7 5A35 CBCF 4A4E B5E3  84B7 DF7B 7722 C193 565B
        # sub  2048R/0x1E0FE11D664D7444 2014-01-02 [expires: 2016-12-31]
        #       Key fingerprint = 16CC 3D3B 0238 2A7F 67B5  C211 1E0F E11D 664D 7444
        # pub  2048R/0x249B39D24F25E3B6 2011-01-12 Werner Koch (dist sig)
        #       Key fingerprint = D869 2123 C406 5DEA 5E0F  3AB5 249B 39D2 4F25 E3B6
        email = fingerprint = None
        for line in output.split('\n'):
            if line.startswith(gpg_constants.PUB_PREFIX):
                full_address = ''
                parts = line.split(' ')
                for part in parts[3:]:
                    full_address += part
                if full_address:
                    _, email = parse_address(full_address)
                    _log.write('pub email: {}'.format(email))
            elif line.find(gpg_constants.FINGERPRINT_PREFIX) >= 0:
                # if an email address has been defined, then save the associated fingerprint
                if email:
                    fingerprint = line.strip()[len(gpg_constants.FINGERPRINT_PREFIX):]
                    _log.write('fingerprint: {}'.format(fingerprint))
            elif line.startswith(gpg_constants.UID_PREFIX):
                # save the previously defined email and fingerprint
                if email and fingerprint:
                    email = add_pair_and_reset(email, fingerprint)
                    _log.write('saved email before new uid: {} {}'.format(email, fingerprint))
                # get the alternative email address
                m = re.match('^uid\s+(.*)'.format(gpg_constants.UID_PREFIX), line.strip())
                if m:
                    _, email = parse_address(m.group(1))
                    # save the email address with the associated fingerprint
                    if email and fingerprint:
                        email = add_pair_and_reset(email, fingerprint)
                        _log.write('saved uid email: {} {}'.format(email, fingerprint))
            elif line.startswith(gpg_constants.SUB_PREFIX):
                # save any unsaved email and fingerprint
                if email and fingerprint:
                    email = add_pair_and_reset(email, fingerprint)
                    _log.write('saved email after finding sub: {} {}'.format(email, fingerprint))

                # set up for another email address
                email = fingerprint = None

    if len(ids_fingerprints) <= 0:
        ids_fingerprints = None
    _log.write('ids and fingerprints: {}'.format(ids_fingerprints))
                
    return ids_fingerprints
    
def get_standardized_expiration(expiration):
    '''
        Change the expiration dictionary into its 2 components: number of units and units.
        
        If the expiration is None, then use the default that the key never expires.
        Adjust any errors in formatting (e.g., units should be '' for days, 
        'w' for weeks, 'm' for months, and 'y' for years.
        
        >>> get_standardized_expiration(None)
        (0, '')
        
        >>> get_standardized_expiration({EXPIRES_IN: 1, EXPIRATION_UNIT: 'y',})
        (1, 'y')
        
        >>> get_standardized_expiration({EXPIRES_IN: 5, EXPIRATION_UNIT: 'd',})
        (5, '')
        
        >>> get_standardized_expiration({EXPIRES_IN: 99,})
        (99, 'y')

        >>> get_standardized_expiration({EXPIRATION_UNIT: 'd',})
        (0, '')
        
        >>> get_standardized_expiration({EXPIRES_IN: 2, EXPIRATION_UNIT: 'weeks',})
        (2, 'w')
        
        >>> get_standardized_expiration({EXPIRES_IN: 10, EXPIRATION_UNIT: 'j',})
        (10, 'y')
    '''

    expires_in = None
    expiration_unit = None
    
    if expiration is not None:
        if expiration.has_key(EXPIRES_IN):
            expires_in = expiration[EXPIRES_IN]
        if expiration.has_key(EXPIRATION_UNIT):
            expiration_unit = expiration[EXPIRATION_UNIT]

    if expires_in is None or expires_in == 0:
        # never have the key expire
        expires_in = 0
        expiration_unit = ''
    elif expiration_unit is None:
        # set the units to year if undefined
        expiration_unit = 'y'
    else:
        expiration_unit = expiration_unit.strip().lower()
        if len(expiration_unit) > 1:
            expiration_unit = expiration_unit[:1]
        if expiration_unit == 'd':
            expiration_unit = ''
        elif expiration_unit == 'w' or expiration_unit == 'm' or expiration_unit == 'y':
            pass
        else:
            expiration_unit = 'y'

    return expires_in, expiration_unit

def parse_fingerprint_and_expiration(output):
    '''
        Parse the output for the fingerprint and the expiration date.
        
        >>> # In honor of Tim Hudson, who co-developed the SSLeay library that OpenSSL is based.
        >>> output = 'pub   4096R/CC95031C 2014-06-14\\nKey fingerprint = 69F9 99F3 6802 4CDD FEBD  266E 95B7 2664 CC95 031C\\nuid                  Tim <Tim@goodcrypto.local>\\nsub   4096R/156739BF 2014-06-14        '
        >>> parse_fingerprint_and_expiration(output)
        ('69F999F368024CDDFEBD266E95B72664CC95031C', None)

        >>> parse_fingerprint_and_expiration(None)
        (None, None)
    '''

    fingerprint = expiration_date = None
    if output is not None:
        for line in output.split('\n'):
            if expiration_date is None:
                expiration_date = _parse_expiration_date(line)
            fingerprint = _parse_fingerprint(line)
            if fingerprint and len(fingerprint) > 0:
                break

        fingerprint = strip_fingerprint(fingerprint)
                
    return fingerprint, expiration_date
    
def _parse_expiration_date(line):
    '''
        Parse the expiration date, if there is one, from the line.

        >>> _parse_expiration_date('pub   4096R/8FD9B90B 2013-11-19 [expires: 2014-11-19]')
        '2014-11-19'
        >>> _parse_expiration_date('pub   4096R/8FD9B90B 2013-11-19') is None
        True
        >>> _parse_expiration_date('Key fingerprint = 12345678') is None
        True
    '''

    PUB_LINE = 'pub'
    EXPIRES_START = '['
    EXPIRES_END = ']'

    expiration_date = None
    try:
        if line:
            if line.startswith(PUB_LINE) and line.find(EXPIRES_START) > 0:
                index = line.find(EXPIRES_START) + len(EXPIRES_START)
                line = line[index:]
                index = line.find(EXPIRES_END)
                if index > 0:
                    line = line[:index]
                index = line.find(': ')
                if index > 0:
                    expiration_date = line[index + len(': '):].strip()
    except Exception:
        _log.write(format_exc())

    return expiration_date

def _parse_fingerprint(line):
    '''
        Parse the fingerprint from the line.

        >>> _parse_fingerprint('Key fingerprint =12345678') == '12345678'
        True
        >>> _parse_fingerprint('The GPG Key fingerprint =12345678') == '12345678'
        True
        >>> _parse_fingerprint('Key fingerprint = 12345678') == '12345678'
        True
        >>> _parse_fingerprint('key Fingerprint =12345678') == '12345678'
        True
        >>> _parse_fingerprint('Schl.-Fingerabdruck =12345678') == '12345678'
        True
        >>> _parse_fingerprint('schl.-fingerabdruck =12345678') == '12345678'
        True
        >>> _parse_fingerprint('schl.-fingerabdruck =') == None
        True
        >>> _parse_fingerprint('123456789') == None
        True
        >>> _parse_fingerprint(123) == None
        True
    '''

    FINGERPRINT_PREFIX1 = 'key fingerprint ='
    FINGERPRINT_PREFIX2 = 'key fingerprint='
    FINGERPRINT_PREFIX3 = 'schl.-fingerabdruck ='
    FINGERPRINT_PREFIX4 = 'schl.-fingerabdruck='

    fingerprint = None
    try:
        if isinstance(line, str):
            prefix = FINGERPRINT_PREFIX1
            index = line.lower().find(FINGERPRINT_PREFIX1)
            if index < 0:
                prefix = FINGERPRINT_PREFIX2
                index = line.lower().find(FINGERPRINT_PREFIX2)
            if index < 0:
                prefix = FINGERPRINT_PREFIX3
                index = line.lower().find(FINGERPRINT_PREFIX3)
            if index < 0:
                prefix = FINGERPRINT_PREFIX4
                index = line.lower().find(FINGERPRINT_PREFIX4)
    
            if index >= 0:
                offset = index + len(prefix)
                suffix = line[offset:].strip()
                if len(suffix) > 0:
                    fingerprint = suffix
    except Exception:
        _log.write('Unable to _parse: {}'.format(line))
        _log.write(format_exc())

    return fingerprint

