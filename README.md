# ADCSAudit

> Single-file, dependency-free PowerShell auditor for **Active Directory Certificate Services (AD CS)** ESC misconfigurations — run it straight from a domain-joined management/jump server. No modules, no RSAT, no binaries to drop.

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?logo=powershell&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Read--only](https://img.shields.io/badge/Mode-Read--only-blue.svg)

`ADCSAudit` enumerates certificate templates, Enterprise CAs and domain controllers, then flags the standard "ESC" privilege-escalation paths popularised by SpecterOps' *Certified Pre-Owned* research. It is **enumeration only** — it never requests a certificate and never changes anything.

---

## Why this exists

The established AD CS tools are excellent, but each carries a deployment cost that is awkward on a hardened management server:

| Tool | Friction on a locked-down box |
|------|-------------------------------|
| **Certipy** | Python + impacket — you have to drop a Python runtime or run it remotely. |
| **Certify** | Compiled C# binary — drop-to-disk / AMSI / EDR exposure. |
| **PSPKIAudit** | PowerShell, but requires installing the `PSPKI` module first. |
| **Locksmith** | Mature PowerShell tool, but you install it from the PSGallery / import a module. |

Sometimes you just want **one `.ps1` you can paste into an existing PowerShell session** on the management server you already have — no install, no internet, no binary on disk, nothing for EDR to flag as a known offensive tool. That is the entire point of this script:

- **One file.** Copy it over, run it. Done.
- **Zero dependencies.** Only `System.DirectoryServices` and `certutil.exe` — both built into every domain-joined Windows host. No `ActiveDirectory` RSAT module required.
- **Read-only.** It reads AD objects and CA registry values. It makes no changes.
- **Live SID + nested-group resolution.** It resolves who *actually* can enroll, including principals reachable through nested group membership (`LDAP_MATCHING_RULE_IN_CHAIN`) — something an offline template export can't tell you.

It is **not** trying to replace Certipy or Locksmith. It's the lightweight "first look" you run when dropping tooling isn't an option. See the [comparison](#comparison) below for when to reach for what.

---

## What it checks

**Certificate templates**

| ESC | Check |
|-----|-------|
| **ESC1** | Enrollee-supplies-subject + client-auth EKU, enrollable by a low-priv principal |
| **ESC2** | Any-Purpose (or no) EKU, enrollable by a low-priv principal |
| **ESC3** | Certificate Request Agent EKU, enrollable by a low-priv principal |
| **ESC4** | Low-priv principal owns or has write/control (WriteDacl/WriteOwner/GenericWrite/GenericAll) over a template |
| **ESC9** | `CT_FLAG_NO_SECURITY_EXTENSION` on a client-auth template |
| **ESC13** | Template's issuance policy is linked to a group (`msDS-OIDToGroupLink`) |
| **ESC15** | Schema v1 template with enrollee-supplies-subject (CVE-2024-49019) |

**Certificate Authorities**

| ESC | Check |
|-----|-------|
| **ESC6** | `EDITF_ATTRIBUTESUBJECTALTNAME2` enabled (any enroller can specify the SAN) |
| **ESC7** | Low-priv principal holds `ManageCA` / `ManageCertificates` |
| **ESC8** | HTTP(S) web enrollment endpoints reachable (NTLM relay surface) |
| **ESC11** | ICPR (RPC) request encryption not enforced |
| **ESC16** | Security extension globally disabled on the CA |

**Domain controllers**

| ESC | Check |
|-----|-------|
| **ESC10** | Weak certificate mapping (`SCHANNEL\CertificateMappingMethods`, `Kdc\StrongCertificateBindingEnforcement`) |

It also surfaces **non-default template owners** (delegated control = latent ESC4) and prints the full enrollment-rights picture per template.

### Threat model

A finding is raised when a **low-privileged principal** can reach it — `Everyone`, `Anonymous`, `Authenticated Users`, `BUILTIN\Users`, `Domain Users`, `Domain Computers`, `Domain Guests` — either directly or through nested group membership. This mirrors how Certipy's `find -vulnerable` reasons about exposure.

---

## Usage

```powershell
# from the folder containing the script, on a domain-joined host
powershell -ExecutionPolicy Bypass -File .\Invoke-ADCSAudit.ps1

# only show objects with findings
.\Invoke-ADCSAudit.ps1 -VulnerableOnly

# stay quiet on the network (no /certsrv probes, no DC remote-registry)
.\Invoke-ADCSAudit.ps1 -SkipWebEnrollment -SkipDCChecks
```

| Parameter | Effect |
|-----------|--------|
| `-OutputDir <path>` | Where to write the reports (default `.\ADCSAudit_<timestamp>`) |
| `-VulnerableOnly` | Only print templates/CAs that have at least one finding |
| `-SkipCAConfig` | Skip the `certutil` queries against each CA (ESC6/7/11/16) |
| `-SkipWebEnrollment` | Skip the HTTP(S) `/certsrv` probes (ESC8) |
| `-SkipDCChecks` | Skip the remote-registry ESC10 check against DCs |

### Output

Colored console summary plus machine-readable files in the output folder:

```
findings.csv      # every finding (ESC, severity, object, detail, principals)
findings.json     # same, as JSON
templates.csv     # full per-template matrix (flags, EKUs, owner, enrollers)
cas.csv           # per-CA results
```

---

## Requirements

- Windows PowerShell **5.1+** (the version shipped with Windows; PowerShell 7 also works)
- Run as a **domain user** — enough for all template checks
- For **ESC7** (CA security) you need at least **Read** on the CA; the check degrades gracefully if denied
- ESC8 makes outbound HTTP(S) to the CA; ESC10 uses remote registry to DCs — use the `-Skip*` switches to stay quiet

---

## Comparison

| | **ADCSAudit** | Certipy | Certify | PSPKIAudit | Locksmith |
|---|:---:|:---:|:---:|:---:|:---:|
| Language / runtime | PowerShell | Python | C# (.NET) | PowerShell | PowerShell |
| Install footprint | **single `.ps1`** | python+impacket | drop binary | `PSPKI` module | PSGallery module |
| Needs RSAT / modules | **No** | n/a | n/a | Yes (PSPKI) | Imports module |
| Enumeration | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Exploitation** (request/forge certs) | ❌ | ✅ | ✅ | ❌ | ❌ |
| **Remediation** (fix mode) | ❌ | ❌ | ❌ | ❌ | ✅ |
| Offline parse (registry/BOF) | ❌ | ✅ (`parse`) | ❌ | ❌ | ❌ |
| Runs from Windows w/o dropping a binary | ✅ | ❌ | ❌ | ✅ | ✅ |
| Read-only by default | ✅ | n/a | n/a | ✅ | ✅ (audit mode) |

**When to use what**

- **Reach for `ADCSAudit`** when you want a quick, dependency-free read of an environment from a box where you can't (or won't) install a module or drop a binary.
- **Use [Certipy](https://github.com/ly4k/Certipy)** when you need to actually *prove* exploitability (request/forge certificates, relay, offline-parse a registry export).
- **Use [Locksmith](https://github.com/TrimarcJake/Locksmith)** when you want a mature auditor that can also *remediate* the findings for you.
- **Use [Certify](https://github.com/GhostPack/Certify) / [PSPKIAudit](https://github.com/GhostPack/PSPKIAudit)** if you're already in the GhostPack/SpecterOps workflow.

These are complementary. A common flow: `ADCSAudit` for the fast triage → Certipy to weaponise the confirmed paths → Locksmith to fix them.

---

## Limitations

- **Enumeration only.** It identifies misconfigurations; it does not request certificates or prove exploitation. Confirm with Certipy/Certify.
- **ESC7** requires read access to the CA's configuration registry.
- **ESC13** detection covers the OID→group link; full ESC13 exploitability depends on additional factors.
- It will flag **ESC11** on many CAs because request encryption is off by default — that matches Certipy's model, but treat it as informational unless the rest of the chain lines up.
- Not a substitute for the more mature tools above; it is the convenient first pass.

---

## How it works (notes for the curious)

- Templates and CAs are read from the **Configuration partition** (`CN=Public Key Services,CN=Services,CN=Configuration,...`) via `System.DirectoryServices.DirectorySearcher`, requesting the `nTSecurityDescriptor` with the appropriate `SecurityMasks`.
- Each template's DACL is parsed with `ActiveDirectorySecurity`, mapping object-ACEs to the **Enroll** (`0e10c968-78fb-11d2-90d4-00c04f79dc55`) and **All-Extended-Rights** GUIDs. Composite rights are tested with `.HasFlag()` (not bitwise-AND) so a principal that merely has *Read* is never mistaken for having *Write*.
- CA-side flags (`EditFlags`, `InterfaceFlags`, `DisableExtensionList`, `Security`) come from `certutil -getreg`; the CA security descriptor is parsed with `RawSecurityDescriptor` and mapped to `ManageCA`/`ManageCertificates`.
- ESC10 reads `SCHANNEL` / `Kdc` registry values from each DC over the remote-registry service.

---

## Legal / authorized use

This tool is intended for **authorized security assessments** of environments you own or have explicit written permission to test. It is read-only, but you are responsible for ensuring you have authorization before running it. The authors accept no liability for misuse.

---

## Credits

- ESC taxonomy: **[Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2)** — Will Schroeder & Lee Christensen (SpecterOps).
- Inspired by [Certipy](https://github.com/ly4k/Certipy), [Certify](https://github.com/GhostPack/Certify), [PSPKIAudit](https://github.com/GhostPack/PSPKIAudit) and [Locksmith](https://github.com/TrimarcJake/Locksmith).

## License

[MIT](LICENSE)
