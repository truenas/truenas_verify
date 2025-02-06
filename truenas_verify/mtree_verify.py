from collections import namedtuple
from hashlib import file_digest
import itertools
from multiprocessing import cpu_count, Pool
from os import lstat
from stat import S_ISDIR, S_ISREG, S_ISLNK, S_IMODE
import re
import sys


LOG_PATH = '/var/log/truenas_verify.log'
MTREE_FILE_PATH = '/conf/rootfs.mtree'
CHUNK_SIZE = 1000
MTREE_FIELDS = ['fname', 'mode', 'uid', 'gid', 'type', 'link', 'size', 'sha256']
MTREE_ENTRY = namedtuple('MtreeEntry', MTREE_FIELDS, defaults=(None,) * len(MTREE_FIELDS))

# We want to initially split the line into 6 parts with the first being the file name.
# Following the type field entries may contain 'link' or 'size', but not both.
# The 'link' or 'size' field is the anchor for the pseudo 'extra' field.
MTREE_ENTRY_FIELDS = [' mode=', ' gid=', ' uid=', ' type=', ' link=', ' size=']

# The 'extra' field is type dependent.
MTREE_FILE_FIELDS = [' size=', ' sha256digest=']


def split_at_fields(line, fields):
    """
    Split the input into it's major parts: fname, mode, gid, uid, extra (includes type).

    Sample of a simple decoded mtree entry:
        ./boot mode=755 gid=0 uid=0 type=dir

    Sample of a more complicated decoded mtree entry:
        ./usr/lib/python3/dist-packages/setuptools/script (dev).tmpl mode=644 gid=0 uid=0 type=file size=218 sha256digest=454cd0cc2414697b7074bb581d661b21098e6844b906baaad45bd403fb6efb92
    """

    regex_pattern = '|'.join(re.escape(field) for field in fields)

    return re.split(regex_pattern, line)


def parse_mtree_entry(line: str) -> tuple:
    """
    Process a decoded mtree line into a normalized MTREE_ENTRY tuple
    """

    if line.startswith('#'):
        return None

    # Get the standard fields with fix-up for the short 'dir' entries.
    split_entry = split_at_fields(line[1:], MTREE_ENTRY_FIELDS)
    fname, mode, gid, uid, type, extra = split_entry[:6] if len(split_entry) > 5 else split_entry + [None]

    match type:
        case 'dir':
            entry = MTREE_ENTRY(fname, mode, int(uid), int(gid), type)
        case 'link':
            entry = MTREE_ENTRY(fname, mode, int(uid), int(gid), type, link=extra)
        case 'file':
            size_field, sha256_field = split_at_fields(extra, MTREE_FILE_FIELDS)
            entry = MTREE_ENTRY(fname, mode, int(uid), int(gid), type, size=int(size_field), sha256=sha256_field)
        case _:
            # Should not get here.  Send it up for reporting.
            entry = MTREE_ENTRY(fname, mode, int(uid), int(gid), type, link=extra)

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
        case _:
            # Report unhandled file types
            errors.append(f"{entry.fname}: unhandled type '{entry.type}'.  extra={entry.link}")

    if oct(S_IMODE(st.st_mode))[2:] != entry.mode:
        errors.append(f'{entry.fname}: got mode {oct(S_IMODE(st.st_mode))}, expected: {entry.mode}')

    return errors


def process_chunk(chunk) -> list[str]:
    errors = []
    for eline in chunk:
        # Crazy but effective decode process.
        line = eline.encode('latin-1').decode('unicode_escape').encode('latin-1').decode('utf-8').strip()
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
