python3 << 'PS03_MASTER'
import subprocess, os, json, glob, gzip

results = {"findings": [], "info": {}}
CRITICAL, HIGH, MEDIUM, LOW = "CRITICAL","HIGH","MEDIUM","LOW"

def run(cmd, timeout=5):
    try:
        return subprocess.check_output(
            cmd, shell=True, stderr=subprocess.DEVNULL,
            timeout=timeout).decode().strip()
    except: return ""

def finding(severity, cve, title, detail, evidence=""):
    results["findings"].append({
        "severity": severity, "cve": cve,
        "title": title, "detail": detail, "evidence": evidence
    })
    sev_color = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}
    print(f"\n{sev_color.get(severity,'⚪')} [{severity}] {cve}")
    print(f"   Title  : {title}")
    print(f"   Detail : {detail}")
    if evidence: print(f"   Evidence: {evidence[:200]}")

def check(label, cmd):
    out = run(cmd)
    print(f"  [CHECK] {label}: {out[:120] if out else '(empty)'}")
    return out

print("=" * 60)
print("  PS-03: PACKAGE MANAGEMENT & SUPPLY CHAIN AUDIT")
print("=" * 60)

# ───────────────────────────────────────────────
# 1. CVE-2026-41651 Pack2TheRoot
# ───────────────────────────────────────────────
print("\n[1/10] CVE-2026-41651 — Pack2TheRoot (PackageKit TOCTOU LPE)")

pk_ver = check("PackageKit version",
    "dpkg-query -W -f='${Version}' packagekit 2>/dev/null")
pk_running = check("PackageKit daemon",
    "systemctl is-active packagekit 2>/dev/null || "
    "dbus-send --system --dest=org.freedesktop.DBus "
    "--type=method_call /org/freedesktop/DBus "
    "org.freedesktop.DBus.ListNames 2>/dev/null | grep -c PackageKit")
pk_dbus = check("D-Bus activation file",
    "ls /usr/share/dbus-1/system-services/*PackageKit* 2>/dev/null")

if pk_ver:
    # Parse version — vulnerable: 1.0.2 to 1.3.4
    import re
    m = re.search(r'(\d+)\.(\d+)\.(\d+)', pk_ver)
    if m:
        major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
        if (major == 1 and minor <= 3 and
            not (minor == 3 and patch >= 5)):
            finding(CRITICAL, "CVE-2026-41651",
                "PackageKit TOCTOU LPE (Pack2TheRoot)",
                f"Installed version {pk_ver} is in vulnerable range "
                f"1.0.2–1.3.4. Any local user can get root in seconds "
                f"via D-Bus transaction race condition.",
                f"Version: {pk_ver} | D-Bus: {pk_dbus}")
        else:
            print(f"  ✅ PackageKit {pk_ver} — patched (≥ 1.3.5)")
    else:
        print(f"  ⚠️  Could not parse version: {pk_ver}")
else:
    print("  ℹ️  PackageKit not installed")
    # But check if it can be D-Bus activated
    if pk_dbus:
        finding(HIGH, "CVE-2026-41651",
            "PackageKit D-Bus activation file present",
            "PackageKit not installed as package but D-Bus activation "
            "file exists — daemon may auto-start on demand",
            pk_dbus)

# ───────────────────────────────────────────────
# 2. APT Signature & Repository Security
# ───────────────────────────────────────────────
print("\n[2/10] APT Repository Signature Verification")

apt_ver = check("APT version", "apt-get --version | head -1")

# Check each repo for [trusted=yes] or missing signed-by
sources = run("cat /etc/apt/sources.list "
              "/etc/apt/sources.list.d/*.list "
              "/etc/apt/sources.list.d/*.sources 2>/dev/null")
if "trusted=yes" in sources:
    finding(HIGH, "APT-NOSIG",
        "APT repo with [trusted=yes] — no signature verification",
        "A repository is marked trusted=yes which bypasses GPG "
        "signature checking entirely. Any MITM can serve malicious packages.",
        [l for l in sources.split('\n') if 'trusted=yes' in l][0])

if "allow-insecure=yes" in sources.lower():
    finding(HIGH, "APT-INSECURE",
        "APT repo with allow-insecure=yes",
        "Repository explicitly allows unsigned/unverified packages.",
        "")

# Check repos without signed-by (only warn for non-Debian repos)
for line in sources.split('\n'):
    if line.startswith('deb ') and 'debian.org' not in line \
       and 'bosslinux.in' in line and 'signed-by' not in line:
        finding(MEDIUM, "APT-UNSIGNED",
            f"BOSS/CDAC repository without signed-by= constraint",
            f"Repository '{line[:60]}' lacks explicit signed-by= key "
            f"constraint — any key in the keyring can sign packages.",
            line)

# Check if HTTP (not HTTPS) repos exist
for line in sources.split('\n'):
    if line.startswith('deb http://') and 'localhost' not in line:
        finding(HIGH, "CVE-2019-3462",
            "APT repo using plain HTTP (MITM attack surface)",
            f"HTTP repo allows man-in-the-middle attacks. "
            f"CVE-2019-3462 uses HTTP redirect to bypass GPG validation.",
            line[:80])

# ───────────────────────────────────────────────
# 3. Installed Package Integrity (debsums)
# ───────────────────────────────────────────────
print("\n[3/10] Package Integrity Verification (debsums)")

debsums_out = run("debsums -c 2>/dev/null | head -20", timeout=30)
if debsums_out:
    count = len(debsums_out.strip().split('\n'))
    finding(HIGH, "PKG-INTEGRITY",
        f"Package file checksum failures detected ({count} files)",
        "debsums found files that don't match their package checksums. "
        "This indicates either CDAC modification or potential tampering.",
        debsums_out[:300])
else:
    print("  ✅ debsums: No checksum failures (or debsums not installed)")

# dpkg --verify for permission changes
dpkg_verify = run("dpkg --verify --verify-format rpm 2>/dev/null | "
                  "grep '^.M\\|^.U\\|^.G' | head -20", timeout=20)
if dpkg_verify:
    finding(MEDIUM, "PKG-PERMS",
        "Package files with modified permissions/ownership",
        "dpkg --verify found files where permissions or ownership differ "
        "from the original package — CDAC may have changed security-relevant "
        "permissions.",
        dpkg_verify)

# ───────────────────────────────────────────────
# 4. CVE-2024-3094 — XZ/liblzma Backdoor
# ───────────────────────────────────────────────
print("\n[4/10] CVE-2024-3094 — XZ Utils / liblzma Backdoor")

xz_ver = check("xz/liblzma version",
    "dpkg-query -W -f='${Version}' xz-utils 2>/dev/null")
liblzma_ver = check("liblzma5 version",
    "dpkg-query -W -f='${Version}' liblzma5 2>/dev/null")

# Vulnerable: 5.6.0 and 5.6.1 (the backdoored versions)
for name, ver in [("xz-utils", xz_ver), ("liblzma5", liblzma_ver)]:
    if ver and any(v in ver for v in ["5.6.0", "5.6.1"]):
        finding(CRITICAL, "CVE-2024-3094",
            f"XZ Utils BACKDOOR found in {name}!",
            f"Version {ver} contains a malicious backdoor inserted via "
            f"supply chain attack. Allows SSH auth bypass on affected systems.",
            f"Package: {name} Version: {ver}")
    elif ver:
        print(f"  ✅ {name} {ver} — not backdoored version")

# Also check binary for backdoor indicators
xz_backdoor = run(
    "strings /usr/lib/*/liblzma.so.5 2>/dev/null | "
    "grep -iE 'RSA|N098|sshd' | head -5")
if xz_backdoor:
    finding(HIGH, "CVE-2024-3094",
        "Suspicious strings in liblzma binary",
        "liblzma.so.5 contains strings associated with the XZ backdoor.",
        xz_backdoor)

# ───────────────────────────────────────────────
# 5. postinst/preinst Script Security Audit
# ───────────────────────────────────────────────
print("\n[5/10] Package Maintainer Script Security Audit")

risky_patterns = [
    ("world-writable created",   r"chmod.*777|chmod.*o+w"),
    ("SUID binary created",      r"chmod.*[+]s|chmod.*4[0-9]{3}"),
    ("curl piped to shell",      r"curl.*\|.*sh|wget.*\|.*sh|curl.*\|.*bash"),
    ("hardcoded password",       r"password\s*=\s*['\"][^'\"]{4,}"),
    ("eval of user input",       r"eval.*\$[^(]"),
    ("PATH manipulation",        r"export PATH=/tmp|PATH=/tmp:"),
    ("writes to /tmp no check",  r">\s*/tmp/[a-z]"),
    ("no signature verification",r"--no-check-certificate|--insecure"),
]

script_findings = []
script_dirs = ["/var/lib/dpkg/info/"]

for script_dir in script_dirs:
    for ext in ["postinst", "preinst", "postrm", "prerm"]:
        pattern = f"{script_dir}*.{ext}"
        for script_path in glob.glob(pattern):
            try:
                with open(script_path, 'r', errors='ignore') as f:
                    content = f.read()
                pkg_name = os.path.basename(script_path).rsplit('.', 1)[0]
                for risk_name, risk_pattern in risky_patterns:
                    import re
                    if re.search(risk_pattern, content, re.IGNORECASE):
                        script_findings.append(
                            (pkg_name, ext, risk_name, script_path))
            except: pass

if script_findings:
    for pkg, ext, risk, path in script_findings[:10]:
        finding(HIGH, "PKG-SCRIPT",
            f"Risky pattern in {pkg}.{ext}: {risk}",
            f"Package maintainer script {path} contains a potentially "
            f"dangerous pattern '{risk}' that runs as root during install.",
            f"File: {path}")
else:
    print("  ✅ No obviously risky patterns in maintainer scripts")

# Specifically check BOSS/CDAC scripts
boss_scripts = run(
    "ls /var/lib/dpkg/info/boss-*.postinst "
    "/var/lib/dpkg/info/cdac-*.postinst 2>/dev/null")
if boss_scripts:
    print(f"  ⚠️  BOSS-specific scripts found: {boss_scripts}")
    for script in boss_scripts.split('\n'):
        if script:
            content = run(f"cat '{script}' 2>/dev/null")
            if content:
                finding(MEDIUM, "CDAC-SCRIPT",
                    f"BOSS-specific install script: {script}",
                    "CDAC custom postinst script runs as root — audit "
                    "for logic bugs, hardcoded credentials, unsafe operations.",
                    content[:400])

# ───────────────────────────────────────────────
# 6. PATH Injection via Package Install
# ───────────────────────────────────────────────
print("\n[6/10] PATH Injection Attack Surface")

# Check for world-writable directories in $PATH
path_dirs = os.environ.get('PATH', '').split(':')
for d in path_dirs:
    if os.path.exists(d):
        mode = oct(os.stat(d).st_mode)
        if mode.endswith(('7', '6', '3', '2')):  # world-writable
            finding(HIGH, "PATH-INJECT",
                f"World-writable directory in PATH: {d}",
                f"Directory {d} (mode {mode}) is in $PATH and writable "
                f"by all users. Can hijack any command run by package scripts.",
                f"Directory: {d} Mode: {mode}")

# System-wide PATH used by cron/scripts
system_path = run("grep -r '^PATH=' /etc/crontab /etc/environment "
                  "/etc/profile /etc/profile.d/* 2>/dev/null | head -10")
for line in system_path.split('\n'):
    if '/tmp' in line or '/var/tmp' in line:
        finding(HIGH, "PATH-INJECT",
            "System PATH includes /tmp or /var/tmp",
            f"System-wide PATH setting includes a world-writable directory: "
            f"{line}",
            line)

# ───────────────────────────────────────────────
# 7. dpkg Lock File & Race Conditions
# ───────────────────────────────────────────────
print("\n[7/10] dpkg Lock File & Race Condition Checks")

lock_files = ["/var/lib/dpkg/lock",
              "/var/lib/dpkg/lock-frontend",
              "/var/cache/apt/archives/lock"]

for lf in lock_files:
    if os.path.exists(lf):
        stat = os.stat(lf)
        mode = oct(stat.st_mode)
        readable = os.access(lf, os.R_OK)
        if readable:
            finding(MEDIUM, "DPKG-LOCK",
                f"dpkg lock file readable by unprivileged user: {lf}",
                f"Lock file {lf} is readable. Monitoring this file allows "
                f"timing attacks during package operations (used in Pack2TheRoot).",
                f"File: {lf} Mode: {mode}")

# ───────────────────────────────────────────────
# 8. APT Cache & Temp Directory Security
# ───────────────────────────────────────────────
print("\n[8/10] APT Cache Directory Security")

apt_dirs = ["/var/cache/apt/archives/", "/var/cache/apt/",
            "/var/lib/apt/lists/", "/tmp/apt-*"]

for d in apt_dirs[:3]:
    if os.path.exists(d):
        mode = oct(os.stat(d).st_mode)
        if mode[-1] in ('7', '6', '5', '3', '2', '1'):
            finding(MEDIUM, "APT-CACHE",
                f"APT cache directory has unexpected permissions: {d}",
                f"APT directory {d} has permissions {mode} — "
                f"may allow package tampering or information disclosure.",
                f"Mode: {mode}")

# Check if partial download dir is writable
partial_dir = "/var/cache/apt/archives/partial/"
if os.path.exists(partial_dir) and os.access(partial_dir, os.W_OK):
    finding(HIGH, "APT-PARTIAL",
        "APT partial download dir writable by current user",
        "The partial downloads directory is writable — allows replacing "
        "in-progress package downloads before verification.",
        partial_dir)

# ───────────────────────────────────────────────
# 9. CDAC/BOSS Custom Package Analysis
# ───────────────────────────────────────────────
print("\n[9/10] CDAC/BOSS Custom Package Security Audit")

boss_pkgs = run("dpkg -l | grep -iE 'boss|cdac|nrcfoss' | awk '{print $2,$3}'")
if boss_pkgs:
    print(f"  Found BOSS/CDAC packages:\n  {boss_pkgs[:300]}")
    
    # Check each BOSS package for SUID files
    for pkg_line in boss_pkgs.split('\n'):
        if not pkg_line.strip(): continue
        pkg_name = pkg_line.split()[0]
        
        # List all files in the package
        pkg_files = run(f"dpkg -L {pkg_name} 2>/dev/null")
        
        # Check for SUID files in this package
        for f in pkg_files.split('\n'):
            if f.strip() and os.path.isfile(f):
                try:
                    mode = os.stat(f).st_mode
                    if mode & 0o4000:  # SUID
                        finding(HIGH, "BOSS-SUID",
                            f"BOSS package {pkg_name} installs SUID binary: {f}",
                            f"Custom CDAC package installs a SUID binary. "
                            f"CDAC-written SUID binaries are prime targets for "
                            f"logic bugs and PS-02 overlap findings.",
                            f"File: {f} Mode: {oct(mode)}")
                    if mode & 0o2000:  # SGID
                        finding(MEDIUM, "BOSS-SGID",
                            f"BOSS package {pkg_name} installs SGID binary: {f}",
                            f"Custom CDAC package installs a SGID binary.",
                            f"File: {f} Mode: {oct(mode)}")
                except: pass

# Check BOSS repo GPG key strength
boss_keys = run("apt-key list 2>/dev/null | grep -A2 'BOSS\\|CDAC\\|NRC-FOSS'")
if boss_keys:
    if "1024" in boss_keys:
        finding(HIGH, "WEAK-GPG",
            "BOSS/CDAC GPG key is only 1024-bit (weak)",
            "A 1024-bit RSA key is considered cryptographically weak and "
            "can be factored. Package signatures using this key are not secure.",
            boss_keys[:200])

# ───────────────────────────────────────────────
# 10. Package Downgrade Attack Surface
# ───────────────────────────────────────────────
print("\n[10/10] Package Downgrade & Version Pinning Check")

# Check if APT allows downgrades
apt_conf = run("cat /etc/apt/apt.conf /etc/apt/apt.conf.d/* 2>/dev/null")
if "AllowDowngrades" in apt_conf and "true" in apt_conf:
    finding(MEDIUM, "APT-DOWNGRADE",
        "APT AllowDowngrades is enabled",
        "APT configuration allows package downgrades. An attacker could "
        "downgrade security-critical packages to older vulnerable versions.",
        "AllowDowngrades=true found in APT config")

# Check if any packages are held (pinned) — these may be outdated intentionally
held = run("apt-mark showhold 2>/dev/null")
if held:
    finding(MEDIUM, "PKG-HELD",
        f"Packages held back from updates: {held}",
        "Held packages do not receive security updates. If any held "
        "package has known CVEs, they remain permanently vulnerable.",
        held)

# Check for significantly outdated packages with known CVEs
old_pkgs = run("apt list --upgradable 2>/dev/null | "
               "grep -iE 'sudo|openssh|openssl|apt|dpkg|packagekit' | head -10")
if old_pkgs:
    finding(HIGH, "PKG-OUTDATED",
        "Security-critical packages have available upgrades",
        "The following security-relevant packages are not at their "
        "latest version and may contain known CVEs.",
        old_pkgs)

# ───────────────────────────────────────────────
# FINAL SUMMARY
# ───────────────────────────────────────────────
print("\n" + "=" * 60)
print(f"  PS-03 SUMMARY: {len(results['findings'])} findings")
print("=" * 60)

sev_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
for f in results["findings"]:
    sev_count[f["severity"]] = sev_count.get(f["severity"], 0) + 1

for sev, count in sev_count.items():
    if count > 0:
        emoji = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}[sev]
        print(f"  {emoji} {sev}: {count}")

# Save to /dev/shm
import json
with open('/dev/shm/ps03_findings.json', 'w') as f:
    json.dump(results, f, indent=2)
print("\n  [*] Full results → /dev/shm/ps03_findings.json")

PS03_MASTER
