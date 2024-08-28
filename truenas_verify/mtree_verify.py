from collections import namedtuple
from hashlib import file_digest
import itertools
from multiprocessing import cpu_count, Pool
from os import lstat
from stat import S_ISDIR, S_ISREG, S_ISLNK, S_IMODE
import sys


LOG_PATH = '/var/log/truenas_verify.log'
MTREE_FILE_PATH = '/conf/rootfs.mtree'
CHUNK_SIZE = 1000
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


def validate_mtree_entry(entry) -> list[str]:
    try:
        st = lstat(entry.fname)
    except FileNotFoundError:
        return [f'{entry.fname}: file does not exist.']

    errors = []
    if st.st_uid != entry.uid:
        errors.append(f'{entry.fname}: got uid {st.st_uid}, expected: {entry.uid}')
    if st.st_gid != entry.gid:
        errors.append(f'{entry.fname}: got gid {st.st_gid}, expected: {entry.gid}')

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

    return errors


def process_chunk(chunk) -> list[str]:
    errors = []
    for line in chunk:
        if (entry := parse_mtree_entry(line)) is not None:
            errors.extend(validate_mtree_entry(entry))
    return errors


def batched(iterable, n):
    """Batch data from the `iterable` into tuples of length `n`. The last batch may be shorter than `n`.

    batched iter recipe from python 3.11 documentation. Python 3.12 adds a cpython variant of this to `itertools` and
    so this method should be replaced when TrueNAS python version upgrades to 3.12.

    Copied from middlewared.utils.itertools module.

    """
    if n < 1:
        raise ValueError('n must be at least one')

    it = iter(iterable)
    while batch := tuple(itertools.islice(it, n)):
        yield batch


def main():
    with Pool(min(cpu_count(), 6)) as pool, open(MTREE_FILE_PATH, 'r') as f:
        results = pool.imap_unordered(process_chunk, batched(f, CHUNK_SIZE))
        errors = [e for r in results for e in r]

    if errors:
        with open(LOG_PATH, 'w') as f:
            f.write('\n'.join(errors))
        sys.exit(f'{len(errors)} discrepancies found. Logged in {LOG_PATH}')


if __name__ == '__main__':
    main()
