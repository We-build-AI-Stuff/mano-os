"""Compare fixed-corpus native diagnostics with conditional source models.

Only the already bounded, immutable synthetic corpus is supported. Debug text
from arbitrary manuals is not a source of authority. No filesystem or codec API.
"""
import base64
import hashlib
import json

from mano_runtime.package_man_leading_source import inspect
from mano_runtime.package_man_reference_lookup import Namespace

CORPUS_SHA = '8f56a13ded65f857120fda94270e5bddb3226cd915976a7748acdf925f095269'
ROOT = 'usr/share/man'
CASES = {
    'absolute-not-followed': 'man1/absolute.1',
    'cycle': 'man1/cycle-a.1',
    'direct': 'man1/plain.1',
    'initial-blank': 'man1/blank-first.1',
    'initial-comment': 'man1/commented.1',
    'initial-hardlink': 'man1/b-hard.1',
    'initial-symlink-to-hardlink': 'man1/soft-hard.1',
    'missing': 'man1/missing.1',
    'nine-hops': 'man1/nine-0.1',
    'original-directory-recursion': 'man1/entry.1',
    'root-compression-precedence': 'man1/compressed.1',
    'so-prefix-without-separator': 'man1/attached.1',
    'ten-hops': 'man1/ten-0.1',
}


def model_packet(corpus_raw, inventory, baseline):
    """Build hypotheses from the fixed literals and observed corpus metadata.

    The two compressed fixtures use their author's literal source strings, never
    a codec or host path. Native comparison tests those hypotheses; this does
    not establish decompression or namespace equivalence for arbitrary inputs.
    """
    if type(corpus_raw) is not bytes or hashlib.sha256(corpus_raw).hexdigest() != CORPUS_SHA:
        raise ValueError('Exact fixed literal corpus required')
    declaration = json.loads(corpus_raw)
    names = {'', 'man1', 'man2'} | declaration['files'].keys() | (
        declaration['hardlinks'].keys() | declaration['symlinks'].keys())
    if type(inventory) is not dict or set(inventory) != names:
        raise ValueError('Complete observed fixed-corpus inventory required')
    entries, inputs = {}, {}
    for name, value in inventory.items():
        full = ROOT+('/'+name if name else '')
        row = {k: v for k, v in value.items() if k not in {'device', 'inode', 'children'}}
        if row['kind'] == 'file':
            row['hardlink_anchor'] = ROOT+'/'+declaration['hardlinks'].get(name, name)
        else:
            row.pop('bytes')
        entries[full] = row
    for parent in ('.', 'usr', 'usr/share'):
        entries[parent] = dict(baseline['entries'][parent])
    for name, value in declaration['files'].items():
        text = base64.b64decode(value['content_base64'], validate=True)
        if name.endswith(('.gz', '.xz')):
            description = 'gzip must win' if name.endswith('.gz') else 'xz must lose to gzip'
            text = ('.TH "ROOTPICK" "1" "2026-01-01" "mano fixture"\n'
                    '.SH NAME\nrootpick \\- '+description+'\n').encode('ascii')
        inputs[ROOT+'/'+name] = dict(compressed_sha256=value['sha256'], request=inspect(text))
    for alias, target in declaration['hardlinks'].items():
        inputs[ROOT+'/'+alias] = inputs[ROOT+'/'+target]
    digest = hashlib.sha256(json.dumps(entries, sort_keys=True, separators=(',', ':'),
                                      ensure_ascii=True, allow_nan=False).encode()).hexdigest()
    tree = dict(schema_version='1.0', entries=entries, excluded_subtrees=['.snapshots'],
                manifest_sha256=digest)
    view = Namespace(tree, tree)
    extensions = ['gz', 'z', 'Z', 'bz2', 'xz', 'lzma', 'lz', 'zst', 'zstd']
    models = {label: view.resolve_source(ROOT, ROOT+'/'+name, inputs, extensions)
              for label, name in CASES.items()}
    return dict(profile='man-fixed-corpus-model-packet-v1',
        runtime_baseline_sha256=baseline['manifest_sha256'], source_tree=tree,
        classifications=inputs, extensions=extensions, models=models,
        classification_provenance='fixed-literal-corpus-v1', compressed_fixtures_inflated=False,
        namespace_equivalence_verified=False, generated_state_validated=False,
        changes_authorized=False, publication_authorized=False)


def compare(stderr, models, *, corpus_sha256):
    if (type(stderr) is not bytes or not stderr or len(stderr) > 256*1024
            or b'\0' in stderr or b'\r' in stderr or not stderr.endswith(b'\n')
            or corpus_sha256 != CORPUS_SHA or type(models) is not dict
            or set(models) != set(CASES)):
        raise ValueError('Bounded exact fixed-corpus diagnostic comparison required')
    if len(json.dumps(models, sort_keys=True, allow_nan=False).encode()) > 1024**2:
        raise ValueError('Conditional source-model evidence budget')
    blocks, current = {}, None
    for line in stderr.splitlines(keepends=True):
        if line.startswith(b'test_manfile: considering '):
            current = line[len(b'test_manfile: considering '):-1]
            if current in blocks:
                raise ValueError('Repeated consideration has ambiguous native custody')
            blocks[current] = []
        elif current is not None:
            blocks[current].append(line)
    if len(blocks) > 128:
        raise ValueError('Bounded native consideration set required')
    results = {}
    for label, name in CASES.items():
        original = ROOT+'/'+name
        native_name = ('/'+original).encode()
        block = blocks.get(native_name)
        if block is None:
            raise ValueError('Every fixed case requires its own native consideration')
        header = b'ult_src: File '+native_name+b' in mantree /usr/share/man\n'
        if block.count(header) != 1:
            raise ValueError('Fresh explicit ultimate-source invocation required')
        model = models[label]
        if (model.get('profile') != 'man-conditional-ultimate-source-v1'
                or model.get('original') != original or model.get('mantree') != ROOT
                or model.get('resolution_state') not in {'terminal', 'unresolved'}):
            raise ValueError('Matching definitive conditional model required')
        for flag in ('filesystem_paths_opened', 'native_lookup_equivalence_verified',
                     'source_target_resolution_verified', 'complete_source_graph_verified',
                     'generated_state_validated', 'changes_authorized', 'publication_authorized'):
            if model.get(flag) is not False:
                raise ValueError('Conditional model cannot grant additional authority')
        points, hard, soft, sources, targets = [], [], [], [], []
        failures = []
        for line in block:
            if line.startswith(b'ult_src: points to '):
                points.append(line[len(b'ult_src: points to '):-1])
            elif line.startswith(b'ult_hardlink: (') and line.endswith(b')\n'):
                hard.append(line[len(b'ult_hardlink: ('):-2])
            elif line.startswith(b'ult_softlink: (') and line.endswith(b')\n'):
                soft.append(line[len(b'ult_softlink: ('):-2])
            elif line.startswith(b' source = '):
                sources.append(line[len(b' source = '):-1])
            elif line.startswith(b' target = '):
                targets.append(line[len(b' target = '):-1])
            elif line.startswith(b'ult_') and line != header:
                raise ValueError('Unknown ultimate-source diagnostic form')
            if line.startswith(b'mandb: ') and b'whatis parse for ' not in line:
                failures.append(line)
        selected = [('/'+step['selected']['path']).encode() for step in model['lookups']
                    if step['selection_state'] == 'selected']
        if points != selected:
            raise ValueError('Native reference traversal differs from the conditional model')
        chosen_hard = model['initial_hardlink_selection']
        wanted_hard = ([] if chosen_hard is None else
                       [chosen_hard['selected'].rsplit('/', 1)[1].encode()])
        wanted_soft = ([] if model['initial_lstat']['kind'] != 'symlink' else
                       [('/'+model['initial_followed_stat']['terminal_path']).encode()])
        if hard != wanted_hard or soft != wanted_soft:
            raise ValueError('Native initial-link handling differs from the model')
        if model['resolution_state'] == 'terminal':
            target = ('/'+model['terminal']['path']).encode()
            initial = (soft[-1] if soft else
                       native_name.rsplit(b'/', 1)[0]+b'/'+hard[-1] if hard else native_name)
            if target != (points[-1] if points else initial) or failures:
                raise ValueError('Native terminal outcome contradicts the model')
            # A shared native cache may omit the source/target pair. Require the
            # actual traversal plus a result or explicit NAME-parse failure;
            # do not turn an absent debug pair into a guessed cache target.
            if not any(line.startswith(b'record = ') or
                       line.startswith(b'mandb: warning: '+native_name+b': whatis parse for ')
                       for line in block):
                raise ValueError('Explicit native terminal processing result required')
            if (sources or targets) and (sources != [native_name] or targets != [target]):
                raise ValueError('Explicit native source/target pair contradicts the model')
        else:
            warning = (b'mandb: warning: '+native_name+
                       b": bad symlink or ROFF `.so' request\n")
            if model['reason'] == 'native-ten-inspection-limit':
                error = b'mandb: '+native_name+b' is self referencing\n'
            elif model['reason'] == 'no-modeled-successful-candidate':
                operand = base64.b64decode(model['lookups'][-1]['operand_base64'], validate=True)
                error = b"mandb: can't resolve "+operand+b'\n'
            else:
                raise ValueError('Fixed native failure outcome is not modeled')
            if failures != [error, warning] or sources or targets:
                raise ValueError('Explicit native reference failure differs from the model')
            target = None
        results[label] = dict(original=original, native_block_sha256=hashlib.sha256(
            b''.join(block)).hexdigest(), native_block_bytes=sum(map(len, block)),
            reference_hops=len(points), resolution_state=model['resolution_state'],
            terminal_path=target.decode()[1:] if target is not None else None,
            initial_hardlink_selected=bool(hard), initial_symlink_followed=bool(soft))
    return dict(profile='man-fixed-native-reference-comparison-v1',
        corpus_sha256=CORPUS_SHA, stderr_sha256=hashlib.sha256(stderr).hexdigest(),
        cases=results, fixed_case_count=len(results),
        fixed_native_reference_outcomes_match=True,
        native_lookup_equivalence_verified=False, complete_source_graph_verified=False,
        descriptions_verified=False, compression_filters_verified=False,
        generated_state_validated=False, changes_authorized=False, publication_authorized=False)
