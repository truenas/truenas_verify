from hashlib import file_digest
from collections import namedtuple
from os import lstat
from stat import S_ISDIR, S_ISREG, S_ISLNK, S_IMODE


MTREE_FILE_PATH = '/conf/rootfs.mtree'
MTREE_ENTRY = namedtuple('MtreeEntry', ['fname', 'mode', 'uid', 'gid', 'type', 'link', 'size', 'sha256'])


def parse_mtree_entry(line):
    if line.startswith('#'):
        return None

    fname, mode, gid, uid, extra = line[1:].split(maxsplit=4)
    if extra.startswith('type=dir'):
        entry = MTREE_ENTRY(
            fname,
            mode.split('=')[1],
            int(uid.split('=')[1]),
            int(gid.split('=')[1]),
            'dir',
            None,
            None,
            None
        )
    elif extra.startswith('type=link'):
        ftype, link = extra.split()
        entry = MTREE_ENTRY(
            fname,
            mode.split('=')[1],
            int(uid.split('=')[1]),
            int(gid.split('=')[1]),
            'link',
            link.split('=')[1],
            None,
            None
        )
    else:
        ftype, size, shasum = extra.split()
        entry = MTREE_ENTRY(
            fname,
            mode.split('=')[1],
            int(uid.split('=')[1]),
            int(gid.split('=')[1]),
            ftype.split('=')[1],
            None,
            int(size.split('=')[1]),
            shasum.split('=')[1]
        )

    return entry


def validate_file_sha256sum(entry, errors):
    with open(entry.fname, 'rb', buffering=0) as f:
        hash = file_digest(f, 'sha256').hexdigest()
        if hash != entry.sha256:
            errors.append(f'{entry.fname}: expected: {entry.sha256}, got: {hash}')


def validate_mtree_entry(entry, errors):
    try:
        st = lstat(entry.fname)
    except FileNotFoundError:
        errors.append(f'{entry.fname}: file does not exist.')
        return

    assert st.st_uid == entry.uid, entry.fname
    assert st.st_gid == entry.gid, entry.fname

    match entry.type:
        case 'dir':
            if not S_ISDIR(st.st_mode):
                errors.append(f'{entry.fname}: incorrect file type.')
        case 'file':
            if not S_ISREG(st.st_mode):
                errors.append(f'{entry.fname}: incorrect file type.')

            validate_file_sha256sum(entry, errors)
        case 'link':
            if not S_ISLNK(st.st_mode):
                errors.append(f'{entry.fname}: incorrect file type.')

    if oct(S_IMODE(st.st_mode))[2:] != entry.mode:
        errors.append(f'{entry.fname}: got mode {oct(S_IMODE(st.st_mode))}, expected: {entry.mode}')


def load_mtree_file():
    with open(MTREE_FILE_PATH, 'r') as f:
        for line in f:
            yield line


def main():
    errors = []

    for line in load_mtree_file():
        if (entry := parse_mtree_entry(line)) is not None:
            validate_mtree_entry(entry, errors)

    with open('/var/log/truenas_verify.log', 'w') as f:
        f.write('\n'.join(errors))
