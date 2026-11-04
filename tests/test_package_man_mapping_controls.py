"""Synthetic mapping result packets only; never invoke mmap/native Linux code."""
import base64
import copy
import hashlib
import json
import unittest

import test_package_man_regeneration as regeneration

from mano_runtime.package_man_mapping_controls import CASES, inspect


def fixture():
    stages = {stage: {name: dict(allowed=True, errno=0) for name in CASES}
              for stage in ('before', 'after')}
    return dict(profile='man-cache-mapping-controls-v1', landlock_abi=6,
        kernel_release='6.12-synthetic-fixture', uid=6, gid=12,
        temporary_exec_before_allowed=True, temporary_exec_after_denied=True,
        diagnostic_mapping_bytes_executed=False, complete_runtime_closure_verified=False,
        publication_authorized=False, **stages)


def captured():
    def stream(data):
        return dict(base64=base64.b64encode(data).decode(), bytes=len(data),
                    sha256=hashlib.sha256(data).hexdigest())
    return dict(returncode=0, capture_complete=True,
                stdout=stream(json.dumps(fixture()).encode()), stderr=stream(b''))


class MappingDiagnosticTests(unittest.TestCase):
    def test_controller_checks_capture_custody_before_parsing_the_native_report(self):
        value = captured()
        raw = base64.b64decode(value['stdout']['base64'])
        self.assertEqual(regeneration.probe.inspect_mapping_result(value), inspect(raw))
        for change in ('incomplete', 'code-alias', 'count-alias', 'sha', 'base64', 'stderr'):
            altered = copy.deepcopy(value)
            if change == 'incomplete':
                altered['capture_complete'] = False
            elif change == 'code-alias':
                altered['returncode'] = False
            elif change == 'count-alias':
                altered['stdout']['bytes'] = float(altered['stdout']['bytes'])
            elif change == 'sha':
                altered['stdout']['sha256'] = '0'*64
            elif change == 'base64':
                altered['stdout']['base64'] += '\n'
            else:
                altered['stderr']['base64'] = 'eA=='
            with self.subTest(change=change), self.assertRaises(ValueError):
                regeneration.probe.inspect_mapping_result(altered)

    def test_launch_and_mapping_outcomes_are_distinct_without_full_policy_claim(self):
        value = fixture()
        result = inspect(json.dumps(value).encode())
        self.assertTrue(result['temporary_launch_denied_but_rx_mapping_allowed'])
        self.assertTrue(result['anonymous_rw_to_rx_allowed'])
        for flag in ('diagnostic_mapping_bytes_executed', 'complete_runtime_closure_verified',
                     'loader_selection_verified', 'generated_state_validated',
                     'changes_authorized', 'publication_authorized'):
            self.assertIs(result[flag], False)

    def test_permission_denials_are_retained_without_assuming_the_kernel_outcome(self):
        for name in CASES - {'baseline_read', 'baseline_exec', 'temporary_read'}:
            for error in (1, 13):
                value = fixture()
                value['after'][name] = dict(allowed=False, errno=error)
                result = inspect(json.dumps(value).encode())
                self.assertEqual(result['after'][name], dict(allowed=False, errno=error))
                self.assertFalse(result['complete_runtime_closure_verified'])

    def test_missing_failed_positive_controls_and_numeric_aliases_refuse(self):
        for mutation in ('missing', 'positive', 'allowed-alias', 'errno-alias', 'uid-alias',
                         'success-errno', 'false-success', 'memory-pressure', 'bad-kernel'):
            value = fixture()
            if mutation == 'missing':
                value['after'].pop('anonymous_to_exec')
            elif mutation == 'positive':
                value['after']['baseline_exec'] = dict(allowed=False, errno=13)
            elif mutation == 'allowed-alias':
                value['after']['temporary_exec']['allowed'] = 1
            elif mutation == 'errno-alias':
                value['after']['temporary_exec']['errno'] = False
            elif mutation == 'uid-alias':
                value['uid'] = 6.0
            elif mutation == 'success-errno':
                value['after']['temporary_exec']['errno'] = 13
            elif mutation == 'false-success':
                value['after']['temporary_exec']['allowed'] = False
            elif mutation == 'memory-pressure':
                value['after']['temporary_exec'] = dict(allowed=False, errno=12)
            else:
                value['kernel_release'] = 'not"json-safe'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                inspect(json.dumps(value).encode())

    def test_duplicates_extra_fields_oversized_or_promoted_claims_refuse(self):
        raw = json.dumps(fixture()).encode()
        with self.assertRaises(ValueError):
            inspect(raw.replace(b'"uid": 6', b'"uid": 6, "uid": 6'))
        with self.assertRaises(ValueError):
            inspect(b' '*4097)
        for flag in ('diagnostic_mapping_bytes_executed', 'complete_runtime_closure_verified',
                     'publication_authorized', 'extra'):
            value = copy.deepcopy(fixture())
            value[flag] = True
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                inspect(json.dumps(value).encode())


if __name__ == '__main__':
    unittest.main()
