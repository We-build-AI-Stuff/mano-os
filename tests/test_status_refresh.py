import unittest
from unittest.mock import Mock

from mano_prompt.status_refresh import INTERVAL_MS, StatusRefresh


class StatusRefreshTests(unittest.TestCase):
    def test_one_ui_timer_and_no_immediate_refresh(self):
        refresh, schedule, cancel = Mock(), Mock(return_value=17), Mock()
        timer = StatusRefresh(refresh, schedule, cancel)
        self.assertTrue(timer.start())
        self.assertFalse(timer.start())
        schedule.assert_called_once_with(INTERVAL_MS, timer.tick)
        refresh.assert_not_called()
        self.assertTrue(timer.tick())
        self.assertTrue(timer.tick())
        self.assertEqual(refresh.call_count, 2)

    def test_close_cancels_once_and_late_ticks_do_nothing(self):
        refresh, schedule, cancel = Mock(), Mock(return_value=17), Mock()
        timer = StatusRefresh(refresh, schedule, cancel)
        timer.start()
        timer.close()
        timer.close()
        cancel.assert_called_once_with(17)
        self.assertFalse(timer.tick())
        self.assertFalse(timer.start())
        refresh.assert_not_called()

    def test_close_before_start_allocates_no_timer(self):
        refresh, schedule, cancel = Mock(), Mock(), Mock()
        timer = StatusRefresh(refresh, schedule, cancel)
        timer.close()
        self.assertFalse(timer.start())
        self.assertFalse(timer.tick())
        schedule.assert_not_called()
        cancel.assert_not_called()
        refresh.assert_not_called()

    def test_closing_during_callback_does_not_reschedule(self):
        timer = StatusRefresh(lambda: timer.close(), Mock(return_value=17), Mock())
        timer.start()
        self.assertFalse(timer.tick())
        timer.cancel.assert_called_once_with(17)
