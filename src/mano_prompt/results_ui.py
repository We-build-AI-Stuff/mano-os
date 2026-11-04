"""Literal read-only preview of an acknowledged task's verified snapshot."""

import gi

gi.require_version('Gtk', '4.0')
from gi.repository import GLib, Gtk, Pango  # noqa: E402

from .dispatch import SubmissionWorker  # noqa: E402
from .results import display, parse_result, read_result  # noqa: E402


class ResultWindow(Gtk.Window):
    def __init__(self, parent, prompt_id, task_id, *, valid, read=None):
        super().__init__(title='Verified result', transient_for=parent, modal=True)
        self.parent_window = parent
        self.restore_fullscreen = parent.is_fullscreen()
        if self.restore_fullscreen:
            parent.unfullscreen()
        self.set_application(parent.get_application())
        self.set_default_size(800, 600)
        self.alive, self.valid = True, valid
        self.result = None
        self.worker = SubmissionWorker(read or read_result, GLib.idle_add)
        self.connect('close-request', self.closed)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        for edge in ('top', 'bottom', 'start', 'end'):
            getattr(box, 'set_margin_' + edge)(20)
        heading = Gtk.Label(label='Verified result')
        heading.add_css_class('subtitle')
        self.summary = Gtk.Label(label='Reading verified snapshot…', wrap=True, xalign=0,
                                 selectable=True)
        self.summary.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
        self.summary.set_max_width_chars(80)
        self.content = Gtk.TextView(editable=False, cursor_visible=False, monospace=True)
        self.content.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.content.update_property([Gtk.AccessibleProperty.LABEL], ['Result preview'])
        scroll = Gtk.ScrolledWindow(vexpand=True)
        scroll.set_child(self.content)
        close = Gtk.Button(label='Close result')
        close.connect('clicked', lambda _button: self.close())
        for widget in (heading, self.summary, scroll, close):
            box.append(widget)
        self.set_child(box)

        def finished(value, error):
            if not self.alive or not self.valid():
                return
            try:
                if error:
                    raise ValueError('Result unavailable')
                checked = parse_result(value, prompt_id)
                if checked['prompt']['task_id'] != task_id:
                    raise ValueError('Acknowledged result task changed')
                summary, content = display(checked)
            except ValueError:
                self.summary.set_text('Result unavailable. Your request was not resubmitted.')
            else:
                self.result = checked
                self.summary.set_text(summary)
                self.content.get_buffer().set_text(content)

        try:
            self.worker.start(prompt_id, finished)
        except RuntimeError:
            self.summary.set_text('Result read could not start. Close this window and retry.')

    def closed(self, _window):
        self.alive = False
        if self.restore_fullscreen and self.parent_window.get_visible():
            self.parent_window.fullscreen()
        return False
