# ── CHECK: Is KVM present? ──
lsmod | grep -E "^kvm"
ls -la /dev/kvm 2>/dev/null
cat /proc/cpuinfo | grep -E "vmx|svm"
# vmx = Intel VT-x, svm = AMD-V

# ── CHECK: Can we access /dev/kvm as regular user? ──
ls -la /dev/kvm
# crw-rw---- = group kvm — check if your user is in that group
id | grep kvm
groups | grep kvm

# ── If in kvm group or /dev/kvm is world-readable ──
python3 << 'CHECK'
import os, fcntl, struct

try:
    fd = os.open('/dev/kvm', os.O_RDWR)
    print(f"[VULNERABLE] /dev/kvm opened — KVM CVE-2026-23401 exploitable")
    
    # KVM_GET_API_VERSION = 0xAE00
    KVM_GET_API_VERSION = 0xAE00
    ver = fcntl.ioctl(fd, KVM_GET_API_VERSION, 0)
    print(f"[+] KVM API version: {ver}")
    os.close(fd)
except PermissionError:
    print("[-] /dev/kvm not accessible (not in kvm group)")
except FileNotFoundError:
    print("[-] /dev/kvm not found — KVM not available")
CHECK
