# ── CHECK: tc (traffic control) subsystem ──
tc qdisc show 2>/dev/null    # list queue disciplines
tc filter show 2>/dev/null   # list filters
lsmod | grep -E "act_ct|cls_|sch_"

# Check if unprivileged tc access possible
python3 << 'CHECK'
import socket, struct

# Try netlink RTM_GETQDISC (read-only)
NETLINK_ROUTE = 0
RTM_GETQDISC = 38

try:
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_ROUTE)
    nlmsg = struct.pack("IHHII", 20, RTM_GETQDISC, 0x301, 1, 0) + \
            struct.pack("BBH", 0, 0, 0) + b'\x00' * 8
    s.send(nlmsg)
    resp = s.recv(65536)
    print(f"[+] Traffic control accessible — act_ct UAF surface reachable")
    print(f"[+] Response: {len(resp)} bytes")
    s.close()
except Exception as e:
    print(f"[-] tc netlink: {e}")
CHECK

# check conntrack (act_ct depends on it)
cat /proc/net/nf_conntrack 2>/dev/null | head -5 \
    && echo "[+] conntrack active — act_ct UAF exploitable"
lsmod | grep nf_conntrack
