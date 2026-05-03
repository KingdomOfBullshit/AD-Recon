# AD Recon

Active Directory enumeration scanner with a portable offline dashboard.

## What it does

Authenticates to a domain controller via LDAP and enumerates:
- All users, computers, and privileged group memberships (paged, no 1000-user limit)
- Kerberoastable and AS-REP roastable accounts
- SMB share access (read/write per share, local admin confirmation)
- WinRM availability and auth status per host
- MSSQL presence and sysadmin check per host
- ADCS certificate authorities and ESC1-vulnerable templates
- RBCD viability (MachineAccountQuota, existing delegation, T2A4D accounts)
- Password policy and domain trusts

Results are written to `scan_results.json` incrementally (saved after each host).

## Usage

```bash
pip install ldap3 impacket dnspython
python scanner.py -u jsmith -p 'Password123' -d contoso.local -dc-ip 10.10.10.5 -dns 10.10.10.5
```

## Dashboard

Open `dashboard.html` in any browser. No install required — just serve the folder:

```bash
python -m http.server 8080
```

Then load `scan_results.json` from the dashboard UI.

## Requirements

- Python 3.8+
- ldap3
- impacket
- dnspython
- Network access to DC on port 389 (LDAP) and 445 (SMB)

## Notes

- Keep your clone private — output JSON will contain credential context and internal hostnames
- Tested on Python 3.10/3.13, Windows and Linux
