from collections import namedtuple
from datetime import datetime, UTC
from hashlib import file_digest
import itertools
from multiprocessing import cpu_count, Pool
from os import lstat
from stat import S_ISDIR, S_ISREG, S_ISLNK, S_IMODE
import re
import sys
import syslog


LOG_PATH_NAME = '/var/log/audit/truenas_verify'
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
    """
    Validate the root file system.
    Passing in 'syslog' as a parameter will direct all output to syslog.
    Default will output a message to console and data to RESULT_LOG_PATH.
    """
    use_syslog = False
    create_init = False
    log_path = f"{LOG_PATH_NAME}.log"
    try:
        match sys.argv[1]:
            case 'syslog':
                use_syslog = True
            case 'init':
                create_init = True
                log_path = f"{LOG_PATH_NAME}.{sys.argv[2]}.log"
            # ignore bogus parameters
    except Exception:
        pass

    with Pool(min(cpu_count(), 6)) as pool, open(MTREE_FILE_PATH, 'r') as mtree_file:
        results = pool.imap_unordered(process_chunk, batched(mtree_file, CHUNK_SIZE))
        detected_changes = [e for r in results for e in r]

    msg = f"{len(detected_changes)} discrepancies found."
    if use_syslog:
        # Log all results to syslog
        syslog.openlog(ident="truenas_verify")
        try:
            syslog.syslog(msg)
            for entry in detected_changes:
                syslog.syslog(entry)
        finally:
            syslog.closelog()
    else:
        # Log headline results to console and details to LOG_PATH
        with open(log_path, 'w') as f:
            f.write(f"{str(datetime.now(UTC))}: {msg}")
            f.write('\n'.join(detected_changes))
            f.write('\n')  # Add closing CR
        if not create_init:
            # Output a message if not an init call
            sys.exit(f'{msg} Logged in {log_path}')


if __name__ == '__main__':
    main()
