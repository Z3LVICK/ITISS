# ── CHECK: Bonding driver ──
lsmod | grep bonding
cat /proc/net/bonding/bond0 2>/dev/null

# Try loading bonding module
modprobe bonding 2>/dev/null && echo "[+] Bonding module loaded" \
    || echo "[-] Cannot load bonding module"

# Check if bonding interface exists
ip link show type bond 2>/dev/null
ls /sys/class/net/*/bonding/ 2>/dev/null

# Create a bonding interface to test (no root needed in some configs)
python3 << 'CHECK'
import socket, struct, fcntl

# Try to interact with bonding via ioctl
SIOCBONDENSLAVE = 0x8990
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    # Query bonding info
    ifr = struct.pack("16sH", b"bond0", 0) + b'\x00' * 22
    result = fcntl.ioctl(s, 0x8913, ifr)  # SIOCGIFFLAGS
    print("[+] Bonding interface accessible — UAF surface reachable")
    s.close()
except Exception as e:
    print(f"[i] Bonding check: {e}")
CHECK
