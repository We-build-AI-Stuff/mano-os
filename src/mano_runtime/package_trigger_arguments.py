"""Link observed callback arguments to recomputed declaration activation sources.

Trace bytes remain observations: this does not prove caller ancestry, complete
coverage, script contents at exec or authority for the script's effects.
"""
import base64

from mano_runtime.package_exec_decode import decode
from mano_runtime.package_postconditions import database_records
from mano_runtime.package_trigger_linkage import require_sources

SCRIPT_NAMES = {b'preinst', b'postinst', b'prerm', b'postrm', b'config'}


def require_arguments(raw, before_log, after_log, before_status, after_status,
                      baseline, candidate, records, observations, read):
    linkage = require_sources(before_log, after_log, before_status, after_status,
                              baseline, candidate, records, observations, read)
    installed = database_records(after_status)
    expected = {}
    for link in linkage['declaration_activation_links']:
        ref = link['package']
        name, arch = ref['name'], ref['architecture']
        fields = installed[(name, arch)]
        prefix = name + (':' + arch if fields.get('multi-arch') == 'same' else '')
        path = ('/var/lib/dpkg/info/' + prefix + '.postinst').encode('ascii')
        row = expected.setdefault(path, dict(package=ref, triggers=set()))
        row['triggers'].add(link['interest']['trigger'].encode('ascii'))
    trace = decode(raw, observe_exits=True)
    seen, callbacks = set(), []
    for event in trace['events']:
        if event['return_value'] != 0:
            continue
        path = base64.b64decode(event['path_base64'], validate=True)
        basename = path.rsplit(b'/', 1)[-1]
        is_script = (path.startswith(b'/var/lib/dpkg/') and
                     (basename in SCRIPT_NAMES or basename.rsplit(b'.', 1)[-1] in SCRIPT_NAMES))
        if not is_script:
            continue
        if path not in expected or path in seen:
            raise ValueError('Distinct callback with declaration activation sources required')
        argv = [base64.b64decode(arg, validate=True) for arg in event['argv_base64']]
        if len(argv) != 3 or argv[:2] != [path, b'triggered']:
            raise ValueError('Exact observed postinst triggered argument frame required')
        triggers = argv[2].split(b' ')
        if (any(not name for name in triggers) or len(set(triggers)) != len(triggers)
                or set(triggers) != expected[path]['triggers']):
            raise ValueError('Observed trigger names differ from supported activation sources')
        seen.add(path)
        callbacks.append(dict(package=expected[path]['package'], path=path.decode('ascii'),
                              triggers=sorted(name.decode('ascii') for name in triggers),
                              pid=event['pid'], process_generation=event['process_generation'],
                              exec_entry_line=event['entry_line']))
    if seen != set(expected):
        raise ValueError('Missing observed callback for declaration activation source')
    return dict(schema_version='1.0', profile='declaration-linked-callback-arguments-v1',
                callbacks=callbacks, observed_callback_arguments_linked=True,
                caller_ancestry_verified=False, all_execs_observed=False,
                script_contents_at_exec_verified=False, trigger_authority_verified=False,
                maintainer_effects_verified=False, changes_authorized=False,
                publication_authorized=False)
