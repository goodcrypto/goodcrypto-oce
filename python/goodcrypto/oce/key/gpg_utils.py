'''
    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-08-03

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import re
from datetime import date

from goodcrypto.oce import gpg_constants
from goodcrypto.oce.key import gpg_constants as gpg_key_constants
from goodcrypto.oce.key.constants import EXPIRES_IN, EXPIRATION_UNIT
from goodcrypto.oce.utils import format_fingerprint, strip_fingerprint
from goodcrypto.utils import get_email
from goodcrypto.utils.log_file import LogFile
from syr.exception import record_exception
from syr.python import is_string

_log = LogFile()

DEBUGGING = False

def parse_gen_key_results(output):
    '''
        Parse the output after creating a key.

        Test extreme case.
        >>> fingerprint = parse_gen_key_results(None)
        >>> fingerprint is None
        True
    '''

    # public and secret key created and signed.
    #
    # gpg: checking the trustdb
    # gpg: public key of ultimately trusted key 0x71D6A19BADB7E55B not found
    # gpg: 3 marginal(s) needed, 1 complete(s) needed, PGP trust model
    # gpg: depth: 0  valid:   5  signed:   0  trust: 0-, 0q, 0n, 0m, 0f, 5u
    # gpg: next trustdb check due at 2018-02-09
    # pub   4096R/0x31BED35386462D36 2016-05-15
    #       Key fingerprint = F5A9 8EAB E1F2 A614 F2EF  9DC2 31BE D353 8646 2D36
    # uid                 [ultimate] Test name <test@goodcrypto.local>
    # sub   4096R/0x181E33811295D5F6 2016-05-15

    ids_fingerprints = parse_id_fingerprint_pairs(output)
    if  ids_fingerprints is None or len(ids_fingerprints) < 1:
        fingerprint = None
    else:
        __, fingerprint = ids_fingerprints[0]

    return fingerprint

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
    uids = []
    if output is None:
        log_message('no output for parse_id_fingerprint_pairs')
    else:
        # alternative 1
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
        #
        # alternative 2
        # pub  4096R/8DD94D6F 2014-08-12 GoodCrypto Sales <sales@goodcrypto.com>
        #       Key fingerprint = 7B68 BCA9 6AC8 1F28 4DCE  B651 07E9 3749 8DD9 4D6F
        # sig       8DD94D6F 2014-08-12   [selfsig]
        #
        #
        # alternative 3
        # pub  1024D/0xDC778B074E754BED 1999-11-16
        # sig        0xDC778B074E754BED 2003-10-01   [selfsig]
        # uid                            Rainer W. Gerling <dsb@gv.mpg.de>
        # sig        0x2087478021AC6CC4 2006-03-02   [User ID not found]
        # sig        0x9710B89BCA57AD7C 2006-05-11   [User ID not found]
        # uid                            Rainer W. Gerling <dsb@mpg-gv.mpg.de>
        # sig        0xC971AE5F6EF2BDF5 1999-11-16   [User ID not found]
        # uid                            Rainer W. Gerling <gerling@gv.mpg.de>
        # sig        0x2087478021AC6CC4 2006-03-02   [User ID not found]
        # uid                            Rainer W. Gerling <gerling@mpg-gv.mpg.de>
        # sig        0x2087478021AC6CC4 2006-03-02   [User ID not found]
        # rev        0xDC778B074E754BED 2007-08-14   [selfsig]
        # sig        0x9710B89BCA57AD7C 2005-09-22   [User ID not found]
        # uid                            Rainer W. Gerling <rainer.gerling@gv.mpg.de>
        # sig        0xDC778B074E754BED 2014-03-10   [selfsig]
        # sub  1024g/0xDA53A909EFD5E354 1999-11-15 [expires: 2008-01-01]
        #      Key fingerprint = DDE4 8146 5C69 31D5 2ADF  F63F DA53 A909 EFD5 E354
        # sig        0xDC778B074E754BED 2007-07-12   [keybind]
        # sub  2048g/0x07E0826784CAA8CB 2008-01-06 [expires: 2016-12-04]
        #      Key fingerprint = 87C4 B590 AF98 0962 7988  3B53 07E0 8267 84CA A8CB
        # sig        0xDC778B074E754BED 2014-03-10   [keybind]
        email = fingerprint = key_id = None
        for line in output.split('\n'):
            if line.startswith(gpg_constants.PUB_PREFIX):
                # save the previously defined email and fingerprint
                if email and fingerprint:
                    email = add_pair_and_reset(email, fingerprint)
                    log_message('saved email before new uid: {} {}'.format(email, fingerprint))
                elif len(uids) > 0:
                    for uid in uids:
                        add_pair_and_reset(uid, key_id)
                    uids = []

                parts = line.split(' ')

                key_id = parts[2]
                m = re.match('\d+[A-Za-z]/0x(.*)', key_id)
                if m:
                    key_id = format_fingerprint(m.group(1))

                full_address = ''
                for part in parts[3:]:
                    full_address += part
                if full_address:
                    email = get_email(full_address)
                    if email is not None: log_message('pub email: {}'.format(email))
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
                    else:
                        uids.append(email)
            elif line.startswith(gpg_constants.SUB_PREFIX):
                # save any unsaved email and fingerprint
                if email and fingerprint:
                    email = add_pair_and_reset(email, fingerprint)
                    log_message('saved email after finding sub: {} {}'.format(email, fingerprint))

                elif len(uids) > 0:
                    for uid in uids:
                        add_pair_and_reset(uid, key_id)
                    uids = []

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

        if DEBUGGING: log_message('looking for email addresses for {}'.format(key_id))

        stripped_key_id = strip_fingerprint(key_id)
        for line in output.split('\n'):
            stashed_lines.append(line)
            if found:
                if DEBUGGING: log_message(line)
                if len(line.strip()) <= 0:
                    for stashed_line in stashed_lines:
                        m = re.match('^uid\s+\[(.*)\]\s+(.*)', stashed_line)
                        if m:
                            # skip expired keys
                            if m.group(1) == 'expired':
                                if DEBUGGING: log_message('exipred: {}'.format(line))
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

def parse_ids_retrieved(output):
    '''
        Parse the output of a keyserver key retrieval.

        Test extreme case.
        >>> parse_ids_retrieved(None)
        ([], [])
    '''

    imported_ids = []
    corrupted_ids = []

    if output is None:
        log_message('no output for parse_keyserver_ids_retrieved')
    else:
        # gpg: armor header: Version: SKS 1.1.5
        # gpg: armor header: Comment: Hostname: pgp.mit.edu
        # gpg: pub  2048D/0xF2AD85AC1E42B367 2007-12-31  Werner Koch <wk@gnupg.org>
        # gpg: key 0xF2AD85AC1E42B367: public key "Werner Koch <wk@gnupg.org>" imported
        # gpg: Total number processed: 1
        # gpg:               imported: 1

        ids = []
        for line in output.split('\n'):
            if not is_string(line):
                line = line.decode(error='replace')
            m = re.match(r'\s*gpg:\s+pub\s+.[0-9]+D?/0x(.*?)\s+\d\d\d\d-\d\d-\d\d\s+(.*)', line)
            if not m:
                m = re.match(r'\s*gpg:\s+key\s+0x(.*?):\spublic key\s+"(.*)"\s+imported', line)
            if m:
                user_id = m.group(2)
                if user_id not in ids:
                    ids.append(user_id)
                    imported_ids.append((user_id, m.group(1)))

        if len(imported_ids) > 0:
            log_message('imported user ids: {}'.format(imported_ids))
        else:
            # gpgkeys: key F2AD85AC1E42B367 partially retrieved (probably corrupt)
            for line in output.split('\n'):
                if not is_string(line):
                    line = line.decode(error='replace')
                m = re.match(r'\s*gpgkeys: key\s+([0-9A-F]+) \s+partially retrieved \(probably corrupt\)', line)
                if m:
                    corrupted_ids.append(m.group(1))

            if len(corrupted_ids) > 0:
                log_message('found corrupted ids: {}'.format(corrupted_ids))
            else:
                log_message('unable to find imported ids: {}'.format(output))

    return imported_ids, corrupted_ids

def parse_search_results(output):
    '''
        Parse the output of a keyserver search.

        Test extreme case.
        >>> results = parse_search_results(None)
        >>> results == None
        True
    '''

    def str2date(s):

        try:
            m = re.match(r'(\d\d\d\d)-(\d\d)-(\d\d)', s)
            d = date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        except:
            d = date.today() - timedelta(days=1)

        return d


    latest_fingerprint = None

    if output is None:
        log_message('no output for parse_keyserver_search')
    else:
        # gpg: searching for "wk@gnupg.org" from hkp server pgp.mit.edu
        # (1)	Werner Koch (ha ha test) <wk@gnupg.org>
        #         1024 bit DSA key 0x2F7998F3DBFC6AD9, created: 2008-01-08, expires: 2008-01-11 (expired)
        # (2)	Werner Koch <wk@gnupg.org>
        #       Werner Koch <wk@g10code.com>
        #       Werner Koch <werner@eifzilla.de>
        #         2048 bit DSA key 0xF2AD85AC1E42B367, created: 2007-12-31, expires: 2018-12-31
        # (3)	Werner Koch
        #       Werner Koch <wk@gnupg.org>
        #       Werner Koch <wk@g10code.com>
        #       Werner Koch <werner@fsfe.org>
        #         1024 bit DSA key 0x5DE249965B0358A2, created: 1999-03-15, expires: 2011-07-11 (expired)
        # (4)	Werner Koch <wk@gnupg.org>
        #       Werner Koch <wk@openit.de>
        #       Werner Koch <wk@g10code.com>
        #       Werner Koch <werner.koch@guug.de>
        #         1024 bit DSA key 0x6C7EE1B8621CC013, created: 1998-07-07, expires: 2004-12-31 (expired)
        # Keys 1-4 of 4 for "wk@gnupg.org".  gpg: Sorry, we are in batchmode - can't get input
        fingerprints = []
        for line in output.split('\n'):
            if not is_string(line):
                line = line.decode(error='replace')

            m = re.match(r'\s+\d\d\d\d bit \w+ key 0x(.*), created: (\d\d\d\d-\d\d-\d\d), expires: (\d\d\d\d-\d\d-\d\d).*?', line)
            if not m:
                m = re.match(r'\s+\d\d\d\d bit \w+ key 0x(.*), created: (\d\d\d\d-\d\d-\d\d)', line)
            if m:
                fingerprint = m.group(1)
                created = str2date(m.group(2))
                try:
                    expires = str2date(m.group(3))
                except:
                    expires = None
                    record_exception()

                fingerprints.append((fingerprint, created, expires,))
                log_message('found fingerprint: {} created on: {} expires: {}'.format(
                    fingerprint, created, expires))

        if len(fingerprints) > 0:
            today = date.today()
            latest_fingperint = latest_creation = latest_expiration = None
            for fingerprint, created, expires in fingerprints:

                if latest_creation is None:
                    if expires is None or expires > today:
                        latest_fingerprint = fingerprint
                        latest_creation = created
                        lastest_expiration = expires

                elif expires is None or expires > today:
                    if created > latest_creation:
                        latest_fingerprint = fingerprint
                        latest_creation = created
                        lastest_expiration = expires

    return latest_fingerprint

def parse_search_error(output, error):
    '''
        Returns an error message after failing to get a key.

        Test extreme cases.
        >>> error = parse_search_error(None, None)
        >>> error is None
        True
    '''

    server_error = None

    try:
        # gpg: searching for "unknown@example.com" from hkp server pgp.mit.edu
        # gpg: key "unknown@example.com" not found on keyserver
        #
        # gpg: searching for "unknown@example.com" from hkp server mit.edu
        # gpg: keyserver timed out
        # gpg: keyserver search failed: keyserver error
        #
        # gpg: searching for "unknown@example.com" from hkp server keyserver.ubuntu.com
        # ?: keyserver.ubuntu.com: Host not found
        # gpgkeys: HTTP search error 7: couldn't connect: Connection timed out
        # gpg: key "unknown@example.com" not found on keyserver
        # gpg: keyserver internal error
        # gpg: keyserver search failed: keyserver error

        if output is None:
            server_error = error
        else:
            combined_output = ''.join('{} {}'.format(output, error).lower())
            log_message(combined_output)
            if gpg_key_constants.KEYSERVER_CONNECTION_ERROR in combined_output:
                server_error = 'Unable to connect to server'
            elif (gpg_key_constants.KEYSERVER_CONNECTION_TIMEDOUT in combined_output or
                  gpg_key_constants.KEYSERVER_TIMEDOUT in combined_output):
                server_error = 'Timed out connecting to server'
            elif gpg_key_constants.KEYSERVER_KEY_NOT_FOUND in combined_output:
                # we don't need to record this error as it's not an error with the server
                server_error = None
                log_message('could not find key on server')
            else:
                server_error = error
                log_message('using default error: {}'.format(error))
    except:
        server_error = 'Unable to connect to server'
        record_exception()

    if server_error is None:
        log_message('key not found on server')
    else:
        log_message('search keyserver error message: {}'.format(server_error))

    return server_error

def parse_fingerprint_and_expiration(output):
    '''
        Parse the output for the fingerprint and the expiration date.

        Test extreme case.
        >>> parse_fingerprint_and_expiration(None)
        (None, None)
    '''

    fingerprint = expiration_date = None
    try:
        for line in output.split('\n'):
            if expiration_date is None:
                expiration_date = _parse_expiration_date(line)
            fingerprint = _parse_fingerprint(line)
            if fingerprint and len(fingerprint) > 0:
                break

        fingerprint = strip_fingerprint(fingerprint)
    except:
        record_exception()
        log_message('EXCEPTION -- see syr.exception.log for details')


    return fingerprint, expiration_date

def get_standardized_expiration(expiration):
    '''
        Change the expiration dictionary into its 2 components: number of units and units.

        If the expiration is None, then use the default that the key never expires.
        Adjust any errors in formatting (e.g., units should be '' for days,
        'w' for weeks, 'm' for months, and 'y' for years.

        Test extreme case.
        >>> expires_in, expiration_unit = get_standardized_expiration(None)
        >>> expires_in == 0
        True
        >>> expiration_unit == ''
        True
    '''

    expires_in = None
    expiration_unit = None

    if expiration is not None:
        expires_in_key = EXPIRES_IN in expiration
        expiration_unit_in_key = EXPIRATION_UNIT in expiration

        if expires_in_key:
            expires_in = expiration[EXPIRES_IN]
        if expiration_unit_in_key:
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
        log_message('EXCEPTION - see syr.exception.log for details')

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
        log_message('EXCEPTION - see syr.exception.log for details')
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

