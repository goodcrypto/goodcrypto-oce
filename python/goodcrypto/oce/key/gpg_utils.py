'''
    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-02-17

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import re

from goodcrypto.oce import gpg_constants
from goodcrypto.oce.key.constants import EXPIRES_IN, EXPIRATION_UNIT
from goodcrypto.oce.utils import strip_fingerprint
from goodcrypto.utils import get_email
from goodcrypto.utils.exception import record_exception
from goodcrypto.utils.log_file import LogFile

_log = LogFile()


def parse_id_fingerprint_pairs(output):
    '''
        Parse the output for the user ids and fingerprints.

        Test extreme case.
        >>> parse_id_fingerprint_pairs(None)
    '''

    def add_pair_and_reset(email, fingerprint):
        ''' Add the id and fingerprint pair to the list. '''
        ids_fingerprints.append((email, fingerprint))

        # reset the info
        email = fingerprint = None

        return email

    ids_fingerprints = []
    if output is None:
        log_message('no output for parse_id_fingerprint_pairs')
    else:
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
        #
        # pub  4096R/8DD94D6F 2014-08-12 GoodCrypto Sales <sales@goodcrypto.com>
        #       Key fingerprint = 7B68 BCA9 6AC8 1F28 4DCE  B651 07E9 3749 8DD9 4D6F
        # sig       8DD94D6F 2014-08-12   [selfsig]
        email = fingerprint = None
        for line in output.split('\n'):
            if line.startswith(gpg_constants.PUB_PREFIX):
                # save the previously defined email and fingerprint
                if email and fingerprint:
                    email = add_pair_and_reset(email, fingerprint)
                    log_message('saved email before new uid: {} {}'.format(email, fingerprint))

                full_address = ''
                parts = line.split(' ')
                for part in parts[3:]:
                    full_address += part
                if full_address:
                    email = get_email(full_address)
                    log_message('pub email: {}'.format(email))
            elif line.find(gpg_constants.FINGERPRINT_PREFIX) >= 0:
                # if an email address has been defined, then save the associated fingerprint
                if email:
                    fingerprint = line.strip()[len(gpg_constants.FINGERPRINT_PREFIX):]
                    log_message('fingerprint: {}'.format(fingerprint))
            elif line.startswith(gpg_constants.UID_PREFIX):
                # save the previously defined email and fingerprint
                if email and fingerprint:
                    email = add_pair_and_reset(email, fingerprint)
                    log_message('saved email before new uid: {} {}'.format(email, fingerprint))
                # get the alternative email address
                m = re.match('^uid\s+(.*)'.format(gpg_constants.UID_PREFIX), line.strip())
                if m:
                    email = get_email(m.group(1))
                    # save the email address with the associated fingerprint
                    if email and fingerprint:
                        email = add_pair_and_reset(email, fingerprint)
                        log_message('saved uid email: {} {}'.format(email, fingerprint))
            elif line.startswith(gpg_constants.SUB_PREFIX):
                # save any unsaved email and fingerprint
                if email and fingerprint:
                    email = add_pair_and_reset(email, fingerprint)
                    log_message('saved email after finding sub: {} {}'.format(email, fingerprint))

                # set up for another email address
                email = fingerprint = None

        # save the previously defined email and fingerprint
        if email and fingerprint:
            log_message('saving the final email: {} {}'.format(email, fingerprint))
            email = add_pair_and_reset(email, fingerprint)

    if len(ids_fingerprints) <= 0:
        ids_fingerprints = None
    log_message('ids and fingerprints: {}'.format(ids_fingerprints))

    return ids_fingerprints

def parse_ids_matching_key_id(key_id, output):
    '''
        Parse the output for the user ids that match the key id.

        Test extreme case.
        >>> parse_ids_matching_key_id(None, None)
        []
    '''

    ids = []
    if output is None:
        log_message('no output for parse_ids_matching_key_id')
    elif key_id is None:
        log_message('no key_id to match in parse_ids_matching_key_id')
    else:
        # pub   4096R/0x2F102CC762C50CF8 2016-02-10 [expires: 2018-02-09]
        #       Key fingerprint = 4D58 DCB4 8F6B B667 37B0  0D58 2F10 2CC7 62C5 0CF8
        # uid                 [ultimate] Edward <edward@goodcrypto.local>
        # sub   4096R/0x5BE87B140D55FC08 2016-02-10 [expires: 2018-02-09]
        #       Key fingerprint = 4241 0612 77EF 1887 1149  6E67 5BE8 7B14 0D55 FC08
        #
        # pub   4096R/0x855978CF296DE1CD 2016-02-10 [expires: 2018-02-09]
        #       Key fingerprint = 99C4 402C AE6F 09DB 604D  4A8A 8559 78CF 296D E1CD
        # uid                 [ultimate] Chelsea <chelsea@goodcrypto.local>
        # sub   4096R/0xC9280ACCE461488E 2016-02-10 [expires: 2018-02-09]
        #       Key fingerprint = A63C 464A 8C0E 7074 FE59  DEE2 C928 0ACC E461 488E
        #
        # pub   2048D/0xF2AD85AC1E42B367 2007-12-31 [expires: 2018-12-31]
        #       Key fingerprint = 8061 5870 F5BA D690 3336  86D0 F2AD 85AC 1E42 B367
        # uid                 [ unknown] Werner Koch <wk@gnupg.org>
        # uid                 [ unknown] Werner Koch <wk@g10code.com>
        # uid                 [ unknown] Werner Koch <werner@eifzilla.de>
        # sub   2048R/0x1E0FE11D664D7444 2014-01-02 [expires: 2016-12-31]
        # sub   1024D/0x4F0540D577F95F95 2011-11-02

        found = False
        stashed_lines = []
        stripped_key_id = strip_fingerprint(key_id)
        for line in output.split('\n'):
            stashed_lines.append(line)
            if found:
                if len(line.strip()) <= 0:
                    for stashed_line in stashed_lines:
                        m = re.match('^uid\s+\[(.*)\]\s+(.*)', stashed_line)
                        if m:
                            # skip expired keys
                            if m.group(1) == 'expired':
                                pass
                            else:
                                ids.append(m.group(2))
                    break
            else:
                # reset the stashed lines everytime there's a blank line
                if len(line.strip()) <= 0:
                    stashed_lines = []
                else:
                    m = re.match('^\s+Key fingerprint = (.*)', line)
                    if m:
                        stripped_fingerprint = strip_fingerprint(m.group(1))
                        if (stripped_key_id == stripped_fingerprint or
                            stripped_fingerprint.endswith(stripped_key_id)):
                            found = True

        log_message('ids matching {}: {}'.format(key_id, ids))

    return ids

def get_standardized_expiration(expiration):
    '''
        Change the expiration dictionary into its 2 components: number of units and units.

        If the expiration is None, then use the default that the key never expires.
        Adjust any errors in formatting (e.g., units should be '' for days,
        'w' for weeks, 'm' for months, and 'y' for years.

        Test extreme case.
        >>> get_standardized_expiration(None)
        (0, '')
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

        Test extreme case.
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

        Test extreme case.
        >>> _parse_expiration_date(None) is None
        True
    '''

    PUB_LINE = 'pub'
    EXPIRES_START = '['
    EXPIRES_END = ']'

    expiration_date = None
    try:
        if line is not None:
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
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    return expiration_date

def _parse_fingerprint(line):
    '''
        Parse the fingerprint from the line.

        Test extreme case.
        >>> _parse_fingerprint(None) == None
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
        else:
            log_message('trying to parse {}'.format(type(line)))
    except Exception:
        log_message('Unable to _parse: {}'.format(line))
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
        record_exception()

    return fingerprint


def log_message(message):
    '''
        Log the message to the local log.

        >>> import os.path
        >>> from syr.log import BASE_LOG_DIR
        >>> from syr.user import whoami
        >>> log_message('test')
        >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.oce.key.gpg_utils.log'))
        True
    '''

    global _log

    if _log is None:
        _log = LogFile()

    _log.write_and_flush(message)

