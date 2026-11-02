#!/usr/bin/env python3
"""Deterministic extension ZIP creation and validated, fresh-directory extraction."""
import argparse
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys
import zipfile

MAX_FILES = 10000
MAX_TOTAL = 1024 * 1024 * 1024


def open_regular_source(path):
    """Open without following a final symlink/reparse point on either platform."""
    if os.name != 'nt':
        return os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb')
    import ctypes
    from ctypes import wintypes
    import msvcrt
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.GetFileInformationByHandleEx.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
    class Attributes(ctypes.Structure):
        _fields_ = [('attributes', wintypes.DWORD), ('tag', wintypes.DWORD)]
    # Read sharing only prevents replacement or writes while the file is read.
    # OPEN_REPARSE_POINT opens the link itself rather than its target.
    handle = kernel.CreateFileW(str(path), 0x80000000, 1, None, 3, 0x00200000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        attributes = Attributes()
        if not kernel.GetFileInformationByHandleEx(handle, 9, ctypes.byref(attributes), ctypes.sizeof(attributes)):
            raise ctypes.WinError(ctypes.get_last_error())
        if attributes.attributes & (0x400 | 0x10):
            raise ValueError('Source file is a reparse point or directory')
        descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except BaseException:
        kernel.CloseHandle(handle)
        raise
    return os.fdopen(descriptor, 'rb')


def safe_name(name):
    parts = name.split('/')
    if not name or '\\' in name or ':' in name or any(ord(c) < 32 for c in name) or any(p in ('', '.', '..') for p in parts) or PurePosixPath(name).is_absolute():
        raise ValueError('Unsafe archive path: ' + repr(name))
    return name


def inventory(archive):
    entries = archive.infolist()
    names = set()
    total = 0
    for entry in entries:
        name = safe_name(entry.filename)
        mode = entry.external_attr >> 16
        if name in names or (mode and stat.S_IFMT(mode) not in (0, stat.S_IFREG)) or entry.is_dir() or entry.flag_bits & 1:
            raise ValueError('Duplicate, encrypted or non-file entry: ' + repr(name))
        names.add(name)
        total += entry.file_size
        if len(names) > MAX_FILES or total > MAX_TOTAL:
            raise ValueError('Archive exceeds package limits')
    # A file must never also be a parent directory.
    for name in names:
        if any('/'.join(name.split('/')[:i]) in names for i in range(1, len(name.split('/')))):
            raise ValueError('Conflicting archive paths')
    return sorted(entries, key=lambda entry: entry.filename)


def create(source, target):
    source = Path(source)
    if source.is_symlink() or not source.is_dir() or getattr(source.lstat(), 'st_file_attributes', 0) & 0x400:
        raise ValueError('Source must be a real directory')
    source = source.resolve()
    target = Path(target).absolute()
    if target.is_relative_to(source):
        raise ValueError('Archive output must be outside the source')
    files = []
    for directory, folders, names in os.walk(source, followlinks=False):
        for name in folders + names:
            path = Path(directory) / name
            info = path.lstat()
            mode = info.st_mode
            if getattr(info, 'st_file_attributes', 0) & 0x400 or stat.S_ISLNK(mode) or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                raise ValueError('Source contains a non-file/directory entry')
        for name in names:
            path = Path(directory) / name
            files.append((safe_name(path.relative_to(source).as_posix()), path))
    if not files or len(files) > MAX_FILES or sum(p.stat().st_size for _, p in files) > MAX_TOTAL:
        raise ValueError('Invalid package size')
    # Exclusive create prevents replacing any existing file or following a link.
    try:
        with target.open('xb') as output, zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for name, path in sorted(files):
                info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                # O_NOFOLLOW also protects the final path from symlink replacement.
                with open_regular_source(path) as payload:
                    if not stat.S_ISREG(os.fstat(payload.fileno()).st_mode):
                        raise ValueError('Source file changed type')
                    with archive.open(info, 'w') as destination:
                        shutil.copyfileobj(payload, destination)
        with zipfile.ZipFile(target) as archive:
            inventory(archive)
            if archive.testzip() is not None:
                raise ValueError('Archive CRC verification failed')
    except Exception:
        # Delete only the new output owned by this call, never a preexisting path.
        if 'output' in locals():
            target.unlink(missing_ok=True)
        raise


def extract(source, destination):
    destination = Path(destination)
    with zipfile.ZipFile(source) as archive:
        entries = inventory(archive)
        # Refuse existing directories, including symlinks, to prevent traversal
        # through preexisting filesystem entries or overwriting user files.
        destination.mkdir()
        try:
            for entry in entries:
                target = destination / entry.filename
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(entry) as payload, target.open('xb') as output:
                    shutil.copyfileobj(payload, output)
        except Exception:
            shutil.rmtree(destination)
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='mode', required=True)
    for mode in ('create', 'extract'):
        command = commands.add_parser(mode)
        command.add_argument('source')
        command.add_argument('destination')
    listing = commands.add_parser('list')
    listing.add_argument('source')
    args = parser.parse_args()
    if args.mode == 'create':
        create(args.source, args.destination)
    elif args.mode == 'extract':
        extract(args.source, args.destination)
    else:
        with zipfile.ZipFile(args.source) as archive:
            print(json.dumps([{'path': e.filename, 'size': e.file_size} for e in inventory(archive)]))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError) as error:
        print('Extension archive: ' + str(error), file=sys.stderr)
        sys.exit(1)
