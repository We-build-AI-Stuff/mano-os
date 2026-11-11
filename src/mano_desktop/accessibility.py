"""Read a bounded accessibility snapshot from the task-owned session bus."""

import json
import os
from collections import deque


def snapshot(registry):
    """Collect labels and roles without reading document text or invoking actions."""
    desktop = registry.getDesktop(0)
    queue = deque([desktop])
    nodes = []
    truncated = False
    used = 0
    while queue and len(nodes) < 16:
        node = queue.popleft()
        if node is None:
            continue
        item = dict(name=str(node.name or '')[:64], role=str(node.getRoleName())[:32])
        used += len(json.dumps(item, separators=(',', ':'))) + 1
        if used > 6500:
            truncated = True
            break
        nodes.append(item)
        remaining = 16 - len(nodes) - len(queue)
        children = node.childCount
        count = min(children, max(0, remaining))
        truncated |= count < children
        for index in range(count):
            queue.append(node.getChildAtIndex(index))
    return dict(nodes=nodes, truncated=truncated)


def main():
    """Use only the explicitly inherited private D-Bus address."""
    address = os.environ.get('DBUS_SESSION_BUS_ADDRESS', '')
    runtime = os.environ.get('XDG_RUNTIME_DIR', '')
    expected = f'unix:path={runtime}/session-bus'
    if not runtime.startswith('/tmp/mano-desktop-') or address != expected:
        raise PermissionError('Private desktop D-Bus address required')
    import pyatspi

    print(json.dumps(snapshot(pyatspi.Registry), ensure_ascii=False))


if __name__ == '__main__':
    main()
