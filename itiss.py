# ── CHECK 1: Are the vulnerable modules loaded? ──
lsmod | grep -E "^esp4|^esp6|^rxrpc"
# Any output = attack surface exists

# ── CHECK 2: Detailed module status ──
for mod in esp4 esp6 rxrpc xfrm4_tunnel xfrm6_tunnel; do
    if lsmod | grep -q "^$mod"; then
        echo "[LOADED] $mod — VULNERABLE"
    else
        # Try loading it
        modprobe $mod 2>/dev/null && echo "[LOADABLE] $mod — can be loaded"
    fi
done

# ── CHECK 3: Is XFRM/IPsec subsystem active? ──
cat /proc/net/xfrm_stat 2>/dev/null | head -10
ip xfrm state list 2>/dev/null
ip xfrm policy list 2>/dev/null

# ── CHECK 4: Kernel config — compiled-in or module? ──
cat /boot/config-$(uname -r) | grep -E "CONFIG_INET_ESP|CONFIG_RXRPC" 2>/dev/null
# =m  = loadable module (can be loaded for attack)
# =y  = compiled-in (always present — harder to disable)

# ── CHECK 5: Check page cache drop defense ──
# If we can drop caches, confirms kernel-level memory access
cat /proc/sys/vm/drop_caches  # check current value
cat /proc/sys/vm/vfs_cache_pressure  # memory pressure settings

# ── VERIFY EXPLOITABILITY ──
python3 << 'CHECK'
import socket, struct

# Try creating raw socket for fragment crafting
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    print("[+] Raw socket created — can craft malformed fragments")
    s.close()
except PermissionError:
    print("[-] Raw socket blocked (needs root or CAP_NET_RAW)")
    
# Check if ESP protocol is accessible
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, 50)  # IPPROTO_ESP=50
    print("[+] ESP raw socket accessible — Dirty Frag surface confirmed")
    s.close()
except Exception as e:
    print(f"[i] ESP socket: {e}")
CHECK

# ── DOCUMENT ──
uname -r > /dev/shm/finding_DirtyFrag.txt
lsmod | grep -E "esp4|esp6|rxrpc" >> /dev/shm/finding_DirtyFrag.txt
echo "CVE-2026-43284 + CVE-2026-43500: Check module status above" >> /dev/shm/finding_DirtyFrag.txt
