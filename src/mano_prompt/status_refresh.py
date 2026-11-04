"""UI-owned periodic read-only refresh; no submission or approval operation."""

INTERVAL_MS = 5000


class StatusRefresh:
    def __init__(self, refresh, schedule, cancel):
        self.refresh, self.schedule, self.cancel = refresh, schedule, cancel
        self.source = None
        self.closed = False

    def start(self):
        if self.closed or self.source is not None:
            return False
        self.source = self.schedule(INTERVAL_MS, self.tick)
        return True

    def tick(self):
        if self.closed:
            return False
        self.refresh()
        return not self.closed

    def close(self):
        if not self.closed:
            self.closed = True
            if self.source is not None:
                self.cancel(self.source)
                self.source = None
