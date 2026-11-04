"""Human-owned verified snapshots, never live workspace reads or execution."""

import base64
import hashlib
import json

from .prompts import Prompts
from .protocol import identifier, relative_path
from .state import Denied

PREVIEW_BYTES = 4096


def preview(state, *, human_uid, prompt_id, boot_id):
    if type(human_uid) is not int or human_uid < 1000:
        raise Denied('Expected native human identity')
    with state.transaction():
        prompt = Prompts(state).status(prompt_id, human_uid=human_uid, boot_id=boot_id)
        response = dict(prompt=prompt, result=None)
        task_id = prompt['task_id']
        if task_id is None:
            return response
        task = state.db.execute('SELECT human_uid,boot_id FROM tasks WHERE id=?',
                                (task_id,)).fetchone()
        if task is None or tuple(task) != (human_uid, boot_id):
            raise Denied('Result task does not belong to this human and boot')
        action = state.db.execute(
            "SELECT id,evidence_json FROM actions WHERE task_id=? AND state='done' "
            'AND verified=1 ORDER BY rowid DESC LIMIT 1', (task_id,)).fetchone()
        if action is None:
            return response
        evidence = json.loads(action['evidence_json'])
        if not isinstance(evidence, list) or not evidence:
            raise Denied('Verified result has no original artifact evidence')
        selected = evidence[0]
        if not isinstance(selected, dict) or set(selected) != {'artifact_id', 'sha256'}:
            raise Denied('Invalid verified artifact reference')
        artifact_id = identifier(selected['artifact_id'])
        row = state.db.execute('SELECT metadata_json,data FROM artifacts '
            'WHERE id=? AND action_id=?', (artifact_id, action['id'])).fetchone()
        if row is None:
            raise Denied('Verified artifact custody unavailable')
        meta, data = json.loads(row['metadata_json']), bytes(row['data'])
        if (not isinstance(meta, dict)
                or meta.get('task_id') != task_id or meta.get('action_id') != action['id']
                or meta.get('artifact_id') != artifact_id or meta.get('boot_id') != boot_id
                or type(meta.get('size')) is not int or meta['size'] != len(data)
                or meta.get('sha256') != selected['sha256']
                or hashlib.sha256(data).hexdigest() != selected['sha256']):
            raise Denied('Verified artifact identity or integrity mismatch')
        path = relative_path(meta['relative_path'])
        part = data[:PREVIEW_BYTES]
        response['result'] = dict(action_id=action['id'], artifact_id=artifact_id,
            path=path, size=len(data), sha256=selected['sha256'],
            data=base64.b64encode(part).decode('ascii'),
            preview_sha256=hashlib.sha256(part).hexdigest(), truncated=len(data) > len(part))
        return response
