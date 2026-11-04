"""Pure synthetic evidence only; no native or staged-source inflation on host."""
import base64
import copy
import hashlib
import io
import json
import unittest
from unittest.mock import patch

from test_package_man_gzip import member
from test_package_man_source_content import witness
from test_package_man_sources import candidate, index, rehash

from mano_runtime import package_man_gzip as codec
from mano_runtime import package_man_leading_requests as leading
from mano_runtime import package_man_source_bytes as source
from mano_runtime import package_man_source_content as content


def fixture(texts=None):
    texts = texts or {'man6/sl.6.gz': b'.so man6/other.6\n',
                      'man6/other.6.gz': b'.TH OTHER 6\n'}
    tree, primary = candidate()
    raws = {name: member(text) for name, text in texts.items()}
    for name, raw in raws.items():
        path = 'usr/share/man/'+name
        tree['entries'][path] = dict(tree['entries'][primary], hardlink_anchor=path,
                                    bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    rehash(tree)
    packet = source.prepare({'var/cache/man/index.db': index()}, tree, tree)
    stream = io.BytesIO()
    sink = content.ExpandedInputs(stream, hashlib.sha256(packet).hexdigest(),
                                  json.loads(packet)['files'])
    with patch.object(content, 'verify_gnu', side_effect=witness):
        worker = content.process_files(dict(files={name: base64.b64encode(raw).decode()
            for name, raw in raws.items()}), codec, expanded_sink=sink)
    worker['manifest_sha256'] = hashlib.sha256(packet).hexdigest()
    capture = b'{"role":"source-content"}\n'+json.dumps(worker, sort_keys=True).encode()+b'\n'
    return packet, stream.getvalue(), capture


class LeadingRequestCaptureTests(unittest.TestCase):
    def test_every_file_classified_as_bound_bytes_without_target_authority(self):
        report, encoded = leading.derive(*fixture())
        artifact = json.loads(encoded)
        self.assertEqual(report['source_files'], 2)
        self.assertEqual(report['request_kind_counts']['relative-reference'], 1)
        self.assertEqual(report['request_kind_counts']['no-leading-so-request'], 1)
        self.assertTrue(report['all_captured_files_classified'])
        self.assertEqual(report['sha256'], hashlib.sha256(encoded).hexdigest())
        self.assertEqual(report['bytes'], len(encoded))
        row = artifact['files']['man6/sl.6.gz']
        self.assertEqual(base64.b64decode(row['operand_base64']), b'man6/other.6')
        for key in ('ultimate_source_targets_resolved', 'transitive_source_graph_verified',
                    'runtime_closure_verified', 'generated_state_validated',
                    'changes_authorized', 'publication_authorized', 'staged_gzip_inflated',
                    'filesystem_source_paths_opened'):
            self.assertIs(report[key], False)

    def test_binary_mutations_refuse_even_after_outer_digest_relabel(self):
        packet, binary, capture = fixture()
        header, _, body = capture.partition(b'\n')
        original = json.loads(body)
        for offset in (0, 18, 19, 51, 55, 59, 67, 80, 112, len(binary)-1):
            changed = bytearray(binary)
            changed[offset] ^= 1
            worker = copy.deepcopy(original)
            worker['expanded_inputs']['sha256'] = hashlib.sha256(changed).hexdigest()
            relabelled = header+b'\n'+json.dumps(worker).encode()+b'\n'
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                leading.derive(packet, bytes(changed), relabelled)

    def test_missing_bytes_trailing_bytes_and_changed_capture_refuse(self):
        packet, binary, capture = fixture()
        for changed in (binary[:-1], binary+b'x', b''):
            with self.assertRaises(ValueError):
                leading.derive(packet, changed, capture)
        header, _, body = capture.partition(b'\n')
        for mutate in (lambda w: w.update(profile='man-source-gzip-content-v1'),
                       lambda w: w.update(manifest_sha256='0'*64),
                       lambda w: w.update(publication_authorized=True),
                       lambda w: w['files'].pop('man6/sl.6.gz')):
            worker = json.loads(body)
            mutate(worker)
            with self.assertRaises(ValueError):
                leading.derive(packet, binary, header+b'\n'+json.dumps(worker).encode())
        with self.assertRaises(ValueError):
            leading.derive(packet, binary, b'{}\n'+body)

    def test_unsupported_text_aborts_instead_of_claiming_complete_coverage(self):
        for text in (b'.so x\0', b'x'*16385):
            with self.subTest(text_size=len(text)), self.assertRaises(ValueError):
                leading.derive(*fixture({'man6/sl.6.gz': text}))

    def test_initial_line_evidence_budget_is_enforced(self):
        packet, binary, capture = fixture({'man6/sl.6.gz': b'x'*15000})
        with patch.object(leading, 'MAX_REPORT_BYTES', len(capture)+4096), \
                self.assertRaises(ValueError):
            leading.derive(packet, binary, capture)
