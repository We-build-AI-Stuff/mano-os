"""Replay native-38 fixed-corpus diagnostics; no Linux execution or staged inflation."""
import base64
import copy
import gzip
import hashlib
import io
import json
import lzma
import unittest
from pathlib import Path

from test_package_man_sources import rehash

from mano_runtime.package_man_leading_source import inspect
from mano_runtime.package_man_reference_lookup import Namespace
from mano_runtime.package_man_reference_trace import CASES, CORPUS_SHA, ROOT, compare, model_packet

FIXTURES = Path(__file__).parent/'fixtures'


def fixture():
    raw = (FIXTURES/'man-native-reference-corpus-v1.json').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == CORPUS_SHA
    declaration = json.loads(raw)
    captured = (FIXTURES/'man-native-reference-3882227.json').read_bytes()
    assert hashlib.sha256(captured).hexdigest() == (
        '1509e49b227dfaa01b1937951d11e17c9ca8400b4f9368f3d076196d0fec96c5')
    native = json.loads(captured)
    assert native['corpus_sha256'] == CORPUS_SHA
    stderr = base64.b64decode(native['stderr']['base64'], validate=True)
    assert len(stderr) == native['stderr']['bytes']
    assert hashlib.sha256(stderr).hexdigest() == native['stderr']['sha256']
    entries, inputs = {}, {}
    for name, value in native['inventory'].items():
        full = ROOT+('/'+name if name else '')
        row = {k: v for k, v in value.items() if k not in {'device', 'inode', 'children'}}
        if row['kind'] == 'file':
            row['hardlink_anchor'] = ROOT+'/'+declaration['hardlinks'].get(name, name)
        else:
            row.pop('bytes')
        entries[full] = row
    directory = entries[ROOT]
    for parent in ('.', 'usr', 'usr/share'):
        entries[parent] = dict(directory)
    for name, value in declaration['files'].items():
        encoded = base64.b64decode(value['content_base64'], validate=True)
        expanded = encoded
        if name.endswith(('.gz', '.xz')):
            # Rebuild only our two small literal synthetic strings. Never inflate
            # corpus/staged bytes or invoke their declared compression programs.
            description = 'gzip must win' if name.endswith('.gz') else 'xz must lose to gzip'
            expanded = ('.TH "ROOTPICK" "1" "2026-01-01" "mano fixture"\n'
                        '.SH NAME\nrootpick \\- '+description+'\n').encode()
            if name.endswith('.gz'):
                # gzip.compress(mtime=0) in Python 3.11/3.12 delegates the OS
                # header byte to zlib. The streaming writer fixes it to 255.
                # Keep exact whole-fixture equality, including its fixed header.
                stream = io.BytesIO()
                with gzip.GzipFile(filename='', mode='wb', fileobj=stream,
                                   compresslevel=9, mtime=0) as writer:
                    writer.write(expanded)
                rebuilt = stream.getvalue()
            else:
                rebuilt = lzma.compress(expanded, format=lzma.FORMAT_XZ)
            assert rebuilt == encoded
        inputs[ROOT+'/'+name] = dict(compressed_sha256=value['sha256'], request=inspect(expanded))
    for alias, target in declaration['hardlinks'].items():
        inputs[ROOT+'/'+alias] = copy.deepcopy(inputs[ROOT+'/'+target])
    tree = dict(schema_version='1.0', entries=entries, excluded_subtrees=['.snapshots'])
    rehash(tree)
    view = Namespace(tree, tree)
    extensions = ['gz', 'z', 'Z', 'bz2', 'xz', 'lzma', 'lz', 'zst', 'zstd']
    models = {label: view.resolve_source(ROOT, ROOT+'/'+name, inputs, extensions)
              for label, name in CASES.items()}
    packet = model_packet(raw, native['inventory'], tree)
    assert packet['models'] == models
    assert packet['classifications'] == inputs
    assert packet['source_tree'] == tree
    return stderr, models


class FixedNativeTraceTests(unittest.TestCase):
    def test_all_thirteen_actual_native_outcomes_match_conditional_resolution(self):
        stderr, models = fixture()
        result = compare(stderr, models, corpus_sha256=CORPUS_SHA)
        self.assertEqual(result['fixed_case_count'], 13)
        self.assertEqual(result['cases']['nine-hops']['reference_hops'], 9)
        self.assertEqual(result['cases']['ten-hops']['resolution_state'], 'unresolved')
        self.assertEqual(result['cases']['initial-symlink-to-hardlink']['terminal_path'],
                         ROOT+'/man1/b-hard.1')
        self.assertEqual(result['cases']['root-compression-precedence']['terminal_path'],
                         ROOT+'/rootpick.1.gz')
        self.assertTrue(result['fixed_native_reference_outcomes_match'])
        for key in ('native_lookup_equivalence_verified', 'complete_source_graph_verified',
                    'generated_state_validated', 'publication_authorized'):
            self.assertFalse(result[key])

    def test_missing_native_call_or_repeated_consideration_cannot_be_guessed(self):
        stderr, models = fixture()
        header = b'ult_src: File /usr/share/man/man1/attached.1 in mantree /usr/share/man\n'
        for changed in (stderr.replace(header, b''), stderr+stderr):
            with self.assertRaises(ValueError):
                compare(changed, models, corpus_sha256=CORPUS_SHA)

    def test_wrong_native_hops_hardlink_target_and_failure_kind_are_rejected(self):
        stderr, models = fixture()
        changes = ((b'ult_src: points to /usr/share/man/rootpick.1.gz',
                    b'ult_src: points to /usr/share/man/rootpick.1.xz'),
                   (b'ult_hardlink: (a-hard.1)', b'ult_hardlink: (b-hard.1)'),
                   (b"mandb: can't resolve missing-target.1", b'mandb: other error'),
                   (b'ult_src: File /usr/share/man/man1/attached.1 in mantree /usr/share/man',
                    b'ult_unknown: no invocation'),
                   (b' target = /usr/share/man/man1/b-hard.1',
                    b' target = /usr/share/man/man1/a-hard.1'))
        for original, replacement in changes:
            with self.subTest(original=original), self.assertRaises(ValueError):
                compare(stderr.replace(original, replacement), models, corpus_sha256=CORPUS_SHA)

    def test_changed_model_cannot_be_relabelled_as_native_success(self):
        stderr, models = fixture()
        for change in ('terminal', 'hop', 'unknown', 'authority'):
            altered = copy.deepcopy(models)
            if change == 'terminal':
                altered['initial-symlink-to-hardlink']['terminal']['path'] = ROOT+'/man1/a-hard.1'
            elif change == 'hop':
                altered['nine-hops']['lookups'].pop()
            elif change == 'unknown':
                altered['direct']['resolution_state'] = 'unknown'
            else:
                altered['direct']['complete_source_graph_verified'] = True
            with self.subTest(change=change), self.assertRaises(ValueError):
                compare(stderr, altered, corpus_sha256=CORPUS_SHA)

    def test_wrong_corpus_unbounded_partial_or_control_bytes_refuse(self):
        stderr, models = fixture()
        for changed in (b'', stderr[:-1], stderr+b'\0', stderr+b'\r\n', b'x'*262145):
            with self.assertRaises(ValueError):
                compare(changed, models, corpus_sha256=CORPUS_SHA)
        with self.assertRaises(ValueError):
            compare(stderr, models, corpus_sha256='0'*64)


if __name__ == '__main__':
    unittest.main()
