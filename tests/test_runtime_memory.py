import importlib.util
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location('runtime_memory',
    Path(__file__).resolve().parents[1] / 'scripts/runtime_memory.py')
memory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(memory)


def sample(**changes):
    return dict(elapsed_seconds=1.0, read_seconds=0.001,
                bytes=dict.fromkeys(memory.GROUPS, 16) | changes)


class RuntimeMemoryTests(unittest.TestCase):
    def test_kernel_counter_rejects_invalid_and_unbounded_values(self):
        self.assertEqual(memory.counter(b'0\n'), 0)
        self.assertEqual(memory.counter(b'67108864\n'), 67108864)
        for raw in (b'', b'-1\n', b'01\n', b'1.0\n', b'max\n', b'NaN\n', b'1\n2\n',
                    b'9223372036854775808\n', b'1' * 100, '16\n', True):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                memory.counter(raw)

    def test_sampled_sum_is_not_sum_of_component_kernel_peaks(self):
        idle = [sample(**dict.fromkeys(memory.GROUPS, 8))]
        samples = [sample(broker=100), sample(launcher_and_tasks=100)]
        peaks = dict.fromkeys(memory.GROUPS, 16) | dict(broker=100, launcher_and_tasks=100)
        result = memory.summarize(idle, samples, peaks)
        self.assertEqual(result['idle_component_sum_bytes'], 40)
        self.assertEqual(result['max_sampled_component_sum_bytes'], 164)
        self.assertNotEqual(result['max_sampled_component_sum_bytes'], sum(peaks.values()))
        self.assertIsNone(result['exact_aggregate_peak_bytes'])
        self.assertIsNone(result['whole_product_peak_bytes'])
        self.assertIn('human compositor and prompt', result['exclusions'])
        self.assertFalse(result['physical_hardware'])
        for values in (dict.fromkeys(memory.GROUPS, 15), {}):
            with self.assertRaises(ValueError):
                memory.summarize(idle, samples, values)
        for changed in (dict(read_seconds=float('nan')), dict(elapsed_seconds=-1),
                        dict(bytes={}), dict(bytes=dict.fromkeys(memory.GROUPS, True))):
            with self.assertRaises(ValueError):
                memory.summarize(idle, [sample() | changed], peaks)

    def test_counter_read_uses_held_descriptor_without_reopening(self):
        with (patch.object(memory.os, 'lseek') as seek,
              patch.object(memory.os, 'read', return_value=b'123\n') as read,
              patch.object(memory.os, 'open') as opened):
            self.assertEqual(memory.read_counter(57), 123)
            seek.assert_called_once_with(57, 0, memory.os.SEEK_SET)
            read.assert_called_once_with(57, 64)
            opened.assert_not_called()

    def test_unsupported_host_rejected_before_any_counter_or_marker_read(self):
        with (patch.object(memory.sys, 'platform', 'darwin'),
              patch.object(memory.os, 'open') as opened,
              patch.object(memory.Path, 'read_text') as read):
            with self.assertRaises(PermissionError):
                memory.RuntimeMemory().__enter__()
            opened.assert_not_called()
            read.assert_not_called()

    def test_sampler_error_and_sample_limit_remain_visible(self):
        observer = memory.RuntimeMemory()
        observer.stop = Mock()
        observer.stop.wait.return_value = False
        observer.sample = Mock(return_value=sample())
        with patch.object(memory, 'MAX_SAMPLES', 3):
            observer.poll()
        self.assertEqual(len(observer.samples), 2)  # Reserve the final post-join sample.
        self.assertIsInstance(observer.error, ValueError)
        observer.error = None
        observer.sample.side_effect = OSError('counter unavailable')
        observer.poll()
        self.assertIsInstance(observer.error, OSError)
