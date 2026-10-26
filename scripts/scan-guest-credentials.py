"""Read regular guest files without blocking on container control FIFOs."""
import hashlib
import os
import re
import stat


def credential_hits(needle, root="/"):
    if not needle:
        raise ValueError("empty credential: cannot check")
    skip = {os.path.join(root, name) for name in ("proc", "sys", "dev")}
    hits = set()
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [name for name in dirs if os.path.join(directory, name) not in skip]
        for name in files:
            path = os.path.join(directory, name)
            if name == "ca.key":
                hits.add(path)
            try:
                # NONBLOCK prevents a file-type race from hanging on a FIFO;
                # fstat also excludes devices, sockets, and other special files.
                fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
                with os.fdopen(fd, "rb") as stream:
                    if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                        continue
                    overlap = b""
                    while chunk := stream.read(1024 * 1024):
                        if needle in overlap + chunk:
                            hits.add(path)
                            break
                        overlap = chunk[-(len(needle) - 1):] if len(needle) > 1 else b""
            except (OSError, ValueError):
                pass
    return sorted(hits)


def ca_key_files(root="/"):
    """Find forbidden gateway CA key filenames without reading their contents."""
    skip = {os.path.join(root, name) for name in ("proc", "sys", "dev")}
    found = []
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [name for name in dirs if os.path.join(directory, name) not in skip]
        if "ca.key" in files:
            found.append(os.path.join(directory, "ca.key"))
    return sorted(found)


def token_digests(root="/"):
    """Hash guest token candidates; no provider value or query enters the VM."""
    skip = {os.path.join(root, name) for name in ("proc", "sys", "dev")}
    tokens = re.compile(rb"[A-Za-z0-9_-]{20,512}")
    digests = set()
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [name for name in dirs if os.path.join(directory, name) not in skip]
        for name in files:
            try:
                fd = os.open(os.path.join(directory, name),
                             os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
                with os.fdopen(fd, "rb") as stream:
                    if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                        continue
                    tail = b""
                    while chunk := stream.read(1024 * 1024):
                        data = tail + chunk
                        digests.update(hashlib.sha256(match.group()).digest()[:8]
                                       for match in tokens.finditer(data))
                        tail = data[-512:]
            except (OSError, ValueError):
                pass
    return digests
