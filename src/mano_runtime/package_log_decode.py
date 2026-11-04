"""Decode dpkg --log event frames as untrusted data, never transaction consent.

Format reference: https://manpages.debian.org/trixie/dpkg/dpkg.1.en.html#OPTIONS
Local timestamps have no verified timezone. Syntax alone cannot approve triggers,
package scope, chronology, side effects or the log mutation itself.
"""
import datetime
import hashlib
import re
import unicodedata

from mano_runtime.package_log_observation import MAX_LOG

MAX_EVENTS = 10_000
MAX_LINE = 8192
PACKAGE = r'[a-z0-9][a-z0-9+.-]{1,63}(?::[a-z0-9][a-z0-9-]{0,31})?'
VERSION = r'(?:<none>|[A-Za-z0-9.+:~_-]{1,256})'
STATES = {'not-installed', 'config-files', 'half-installed', 'unpacked', 'half-configured',
          'triggers-awaited', 'triggers-pending', 'installed'}
ACTIONS = {'install', 'upgrade', 'configure', 'trigproc', 'disappear', 'remove', 'purge'}
STARTUPS = {('archives', 'unpack'), ('archives', 'install'), ('packages', 'configure'),
            ('packages', 'triggers-only'), ('packages', 'remove'), ('packages', 'purge')}


def frames(raw):
    if (type(raw) is not bytes or len(raw) > MAX_LOG or raw.count(b'\n') > MAX_EVENTS
            or (raw and not raw.endswith(b'\n'))):
        raise ValueError('Bounded complete dpkg log event lines required')
    result = []
    for encoded in raw.split(b'\n')[:-1]:
        if not 0 < len(encoded) <= MAX_LINE:
            raise ValueError('Bounded nonempty dpkg event line required')
        line = encoded.decode('utf8', errors='strict')
        if any(unicodedata.category(character).startswith('C')
               or unicodedata.category(character) in {'Zl', 'Zp'} for character in line):
            raise ValueError('Control-free dpkg event text required')
        if not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} .+', line):
            raise ValueError('Exact local dpkg timestamp and event required')
        stamp, body = line[:19], line[20:]
        datetime.datetime.strptime(stamp, '%Y-%m-%d %H:%M:%S')
        words = body.split(' ')
        event = words[0]
        row = dict(local_timestamp=stamp, event=event)
        if event == 'startup' and len(words) == 3 and tuple(words[1:]) in STARTUPS:
            row.update(kind=words[1], command=words[2])
        elif (event == 'status' and len(words) == 4 and words[1] in STATES
              and re.fullmatch(PACKAGE, words[2]) and re.fullmatch(VERSION, words[3])):
            row.update(state=words[1], package=words[2], version=words[3])
        elif (event in ACTIONS and len(words) == 4 and re.fullmatch(PACKAGE, words[1])
              and all(re.fullmatch(VERSION, value) for value in words[2:])):
            row.update(package=words[1], installed_version=words[2], available_version=words[3])
        elif event == 'conffile' and body.startswith('conffile '):
            path, separator, decision = body[len('conffile '):].rpartition(' ')
            if not separator or not path.startswith('/') or len(path.encode()) > 4096 or (
                    decision not in {'install', 'keep'}):
                raise ValueError('Bounded conffile path and known decision required')
            row.update(path=path, decision=decision)
        else:
            raise ValueError('Unknown or malformed dpkg log event')
        result.append(row)
    return result


def decode_append(before, after):
    if any(type(data) is not bytes or len(data) > MAX_LOG for data in (before, after)):
        raise ValueError('Bounded actual dpkg log bytes required')
    prefix = after.startswith(before)
    suffix = after[len(before):] if prefix else None
    events = frames(suffix) if suffix is not None else None
    return dict(schema_version='1.0', prefix_preserved=prefix,
                before_sha256=hashlib.sha256(before).hexdigest(),
                after_sha256=hashlib.sha256(after).hexdigest(), events=events,
                decoded_events=len(events) if events is not None else None,
                event_frames_decoded=prefix, timestamp_timezone_verified=False,
                package_scope_verified=False, trigger_authority_verified=False,
                time_window_verified=False, log_semantics_verified=False,
                log_change_accounted=False, changes_authorized=False,
                publication_authorized=False)
