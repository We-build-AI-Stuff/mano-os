"""Release only this GitHub CI job's completed first-VM images, never user data."""

import json
import os
import re
import shutil
import stat
import sys
from pathlib import Path

IMAGES = ('debian-13-genericcloud-amd64.qcow2', 'data.qcow2', 'root.qcow2')
PRISTINE = 'runtime-pristine.qcow2'
STAMP = '.ci-image-ownership.json'
ROOT = Path(__file__).resolve().parents[1]


def eligible(environment, platform, uid, root):
    return (platform == 'linux' and uid != 0
        and environment.get('MANO_DISPOSABLE_CI') == '1'
        and environment.get('GITHUB_ACTIONS') == 'true'
        and re.fullmatch('[0-9]+', environment.get('GITHUB_RUN_ID', '')) is not None
        and bool(environment.get('GITHUB_JOB'))
        and Path(environment.get('GITHUB_WORKSPACE', '/nonexistent')).resolve() == root.resolve())


def context(environment, uid):
    return dict(run=environment['GITHUB_RUN_ID'],
                attempt=environment.get('GITHUB_RUN_ATTEMPT', '1'),
                job=environment['GITHUB_JOB'], uid=uid)


def identity(path, uid):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_nlink != 1:
        raise ValueError('CI image must be an owned regular file without links')
    return dict(device=info.st_dev, inode=info.st_ino)


def snapshot(directory, uid, job):
    return dict(context=job, images={name: identity(directory / name, uid) for name in IMAGES},
                pristine=identity(directory / PRISTINE, uid))


def validate(directory, uid, job, recorded):
    if (not isinstance(recorded, dict) or set(recorded) != {'context', 'images', 'pristine'}
            or recorded['context'] != job or set(recorded['images']) != set(IMAGES)
            or snapshot(directory, uid, job) != recorded):
        raise ValueError('CI image ownership no longer matches this job')
    if (directory / PRISTINE).stat().st_mode & 0o222:
        raise ValueError('Untouched stock base must remain read-only')
    return list(IMAGES)


def write_json(fd, value):
    data = (json.dumps(value, indent=2) + '\n').encode()
    os.lseek(fd, 0, os.SEEK_SET)
    with os.fdopen(os.dup(fd), 'wb') as stream:
        stream.write(data)
        stream.flush()
    os.ftruncate(fd, len(data))
    os.fsync(fd)


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in {'record', 'release'}:
        raise ValueError('Expected record or release of fixed CI images')
    uid = os.geteuid()
    if not eligible(os.environ, sys.platform, uid, ROOT):
        print('Retaining VM images: not an eligible non-root GitHub disposable workspace.')
        return 0
    directory = ROOT / 'work/vm'
    for parent in (ROOT, ROOT / 'work', directory):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid:
            raise ValueError('CI image directory is not owned by this job')
    job = context(os.environ, uid)
    flags = os.O_CLOEXEC | os.O_NOFOLLOW
    if sys.argv[1] == 'record':
        recorded = snapshot(directory, uid, job)
        fd = os.open(directory / STAMP, os.O_RDWR | os.O_CREAT | os.O_EXCL | flags, 0o600)
        try:
            write_json(fd, recorded)
        finally:
            os.close(fd)
        print('Recorded ownership of three first-VM images for this CI job.')
        return 0
    identity(directory / STAMP, uid)
    fd = os.open(directory / STAMP, os.O_RDONLY | flags)
    try:
        raw = os.read(fd, 16385)
        if len(raw) > 16384:
            raise ValueError('Oversized CI ownership record')
        recorded = json.loads(raw)
    finally:
        os.close(fd)
    names = validate(directory, uid, job, recorded)
    receipt = dict(context=job, created_images=recorded['images'], retained=PRISTINE,
                   status='planned', released=[], free_before_bytes=shutil.disk_usage(ROOT).free)
    report = ROOT / 'evidence/released-vm-images.json'
    fd = os.open(report, os.O_RDWR | os.O_CREAT | os.O_EXCL | flags, 0o600)
    try:
        write_json(fd, receipt)  # Keep the plan even if an interruption stops the release.
        for name in names:
            if identity(directory / name, uid) != recorded['images'][name]:
                raise ValueError('CI image changed before release')
            (directory / name).unlink()
            receipt['released'].append(name)
    finally:
        receipt['status'] = 'released' if len(receipt['released']) == len(IMAGES) else 'partial'
        receipt['free_after_bytes'] = shutil.disk_usage(ROOT).free
        write_json(fd, receipt)
        os.close(fd)
    print(json.dumps(receipt))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
