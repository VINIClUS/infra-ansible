# S6 — new client pilots and scoped policy

This source implements the manual client backend. It is disabled by default and
does not claim that a template, license, domain join, policy or runtime test has
passed. Runtime results must be collected after the source review and the actual
S1/S3/S4/S5 deployment. Existing workstations and LAN DHCP/DNS are outside this
flow. Municipal inventory, backup, DR and external custody are not readiness gates.

## Manual boundary

Use `playbooks/samba-ad-pilots.yml`, exact `--limit TARGET_PVE_NODE`, and only
`--tags samba_ad_pilots`. `samba_ad_pilots_enabled` and
`samba_ad_pilots_apply` default to false. The requested resource must belong to
that exact target node; the command cannot fall back to running client code on
the PVE host. There is no automatic-main integration.

The private request has schema `samba-ad-pilot/v1`; its closed fields are validated
in `tools/samba_ad/pilots.py`. The canonical S0 manifest and S1 lifecycle request
are reused without changing their ownership, digest, network or exact-identity
guards. The client is a full new QEMU clone; it must not have pre-existing domain
membership, a foreign keytab, a foreign AD computer object or an unowned state file.

S1 accepts the separate `samba-ad-pilot-substrate/v1` consumer for
`linux_pilot` and `windows_pilot`. It never accepts that bundle for a DC or CA.
Its reviewed raw template observation binds the actual OS, template digest,
target placement, platform versions, reset/generalization facts, disk, policy,
source machine identity and fresh clone UUID. The private review reference and
raw artifact hash are provenance, not self-authenticating approval. No positive
operational bundle or runtime receipt is provided in this repository.

The template qualification must be measured on a disposable owned clone on the
actual destination node. Record raw QGA/CIM/OS facts, including source identity
before reset, and the offline generalized template state afterward. A Windows
template must deliver the declared static address and hostname on its new clone
(for example, a separately qualified Cloudbase-Init/unattend configuration).
Neither its name nor PVE `ostype` is evidence of its Windows edition or support.
S1 assigns the private fresh SMBIOS UUID before first boot; QGA checks that UUID,
MAC, static address, hostname, machine ID and boot identity again before secrets.

## Stages and evidence

1. `prepare` operates only inside the new owned client. Linux uses reviewed,
   version-pinned offline `.deb` assets and `apt-get --no-download`; Windows uses
   pinned Microsoft-signed offline feature assets and DISM `-LimitAccess`.
   Neither backend installs packages on PVE or performs unbounded discovery.
   Public root/intermediate certificates are installed, with exact SHA-256 pins.
2. `join` requires fresh host-local results from both exact DCs. Each checks
   hostname/MAC/address, machine and boot identity, signed Samba package pins,
   expected forest SID, levels 7/7, schema 88, service state, SYSVOL ACL checks,
   and successful inbound replication of all five naming contexts from the peer
   within 900 seconds. DC02 also requires its S5 timer and root-owned successful
   status within 600 seconds, with no partial sync. Both full SYSVOL content
   hashes must agree. The transported results expire after 300 seconds and bind
   the exact request; the request has no `passed` or bypass field.
3. DC01 atomically creates only the dedicated pilot OU and new computer object,
   with the S1 target ownership marker. The measured computer objectGUID is
   carried to the join. The client checks that exact DN/GUID/marker immediately
   before and after joining. Existing foreign accounts are never reset. A failed
   initial join that left a reserved account needs explicit owned-object recovery;
   another run will not silently adopt it.
4. Linux joins with `adcli --stdin-password`, enables SSSD/NSS/PAM, and tests
   machine membership, fresh Kerberos credentials and signed SYSVOL reads through
   both explicitly configured DCs. Kerberos uses isolated `/run` caches and exactly
   one approved KDC per test, then destroys the cache. PAM account checks and NSS
   lookups exercise the configured stack. It does not claim Windows GPO execution.
5. Windows joins with `Add-Computer -Server DC01 -OUPath OWNED_OU`, without WinRM
   or ADWS. It reports `joined_reboot_required`; reboot only this new owned client
   and update its private observed boot pin before `verify` or `policy`. Reruns
   with matching local/AD ownership, SID and computer GUID verify membership and
   never rejoin. Secure-channel, LDAPS SID and actual SYSVOL reads use both DCs.
6. `policy` uses GPMC against DC01 only. The new owned GPO can link only to the
   pilot OU; foreign names, descriptions, links or policy files stop the run.
   After S5 has copied its GPT/Registry.pol to DC02, acceptance compares those
   files through both DCs, runs real `gpupdate`/`gpresult`, checks the GPO GUID,
   the reported DC and effective registry values. If DC Locator does not honor
   the requested secure-channel selection, the check fails pending diagnosis;
   two identical refresh commands are not evidence of two-DC acceptance.

**S4 dependency ruling:** Linux `prepare` may run before DC02 exists, solely to
prepare the new owned Linux pilot as the external S4 protocol test driver. That
stage takes no join credential, performs no LDAP write or GPO operation, and
does not assert membership or full S6 acceptance. `join`, `verify`, and `policy`
retain the two-DC gate. This avoids the S4/S6 dependency cycle.

## Windows support, baseline and conditional controls

The initial native implementation supports actual Windows Server 2025 Standard
or Datacenter, x86-64, build 26100. It queries CIM, DISM edition, ImageState, local
SID, MachineGuid and SoftwareLicensingProduct activation state. Activation is an
observed technical fact, not an invented license key or legal ownership claim.
The private operator remains responsible for the applicable license entitlement.
Windows 11 is not qualified here: the existing S1 device guard intentionally does
not yet permit its additional TPM/UEFI device requirements.

The baseline request pins the reviewed Microsoft download URL, publisher,
Server 2025 title, archive SHA-256, every extracted file hash and an explicit
registry-policy setting allowlist. The backend reads the pinned Registry.pol
binary and requires each chosen value to exist there before applying it with
`Set-GPRegistryValue`. It does not execute downloaded scripts or import the full
baseline. This is an explicit reviewed **baseline subset**, not a claim that all
Microsoft recommendations have been applied. Additional baseline settings require
an expanded reviewed parser/allowlist and corresponding acceptance tests.

The initial allowlist is restricted to signing/guest-access and PowerShell logging
registry values. Some Microsoft settings may be represented in security templates
rather than Registry.pol; such values remain unavailable until a reviewed adapter
exists. The actual private artifact must match the selected OS and source file.
Missing assets or mismatched values stop before policy mutation. Default Domain
Policy and Default Domain Controllers Policy are never targeted.

Encrypted LAPS, WHfB, AES-only, and complete NTLM disablement remain conditional
P1 work. The allowlist cannot import these settings or weaken the existing NTLMv2
floor. No broad blanket baseline exception is inferred.

## Secret and trust transport

Populate the exact protected reference
`/run/samba-ad-pilot-credentials/{linux_pilot,windows_pilot}/join.json` on the
target PVE node from the approved fully encrypted private `vault.yml` workflow.
The file contains only `username` and `password`. Both parent directories must
be root-owned mode 0700; the file must be root-owned, mode 0600, single-link and
not a symlink. It is outside Git and transient `/run` storage. Use the domain-admin
secret profile declared in S0 or a separately reviewed delegated account; never
put the resolved values in public inventory, extra-vars or shell arguments.

The PVE backend reads that file only after canonical live S1 checks and a fresh
QGA nonce/identity probe. `qm guest exec --pass-stdin 1` forwards credential JSON
to a fixed public PowerShell/Python program. No passwords, keys, Base64 secrets,
EncodedCommand payloads, tokens or `pvesh --input-data` values appear in argv.
Windows reads `[Console]::In.ReadToEnd()` and uses PSCredential/LDAP/native logon
APIs in memory. Linux passes passwords through stdin or a library call. Native
errors are generic, Ansible tasks are `no_log`, Python core dumps are disabled,
and the new Windows pilot disables local Windows Error Reporting before secrets.
Timeouts do not automatically retry an operation that may still be running.

Each client validates certificate chain, hostname and pinned leaf hash against
only the two manifest-bound DC endpoints before credentials. Linux finishes and
pins the actual LDAP TLS connection with an empty anonymous bind before the real
bind. Windows checks the pin in its LDAP TLS verification callback. Only public
CA certificates cross this interface; no CA or DC private key is transported.

## Validation and limits

Synthetic pytest fixtures cover closed contract drift, foreign memberships,
secret-free argv, truncated/failed QGA results, wrong QGA identity, TLS-before-bind,
stale/mismatched DC evidence, DRS failure/peer/context checks, baseline restrictions,
bootstrap dependency loading and real disabled/manual Ansible guards. PowerShell
is parsed with its AST parser without executing the Windows backend. S1 and CA
lifecycle regressions are included in the focused test run.

These tests do not qualify an OS image, a license, Microsoft assets, a transport
version, Windows account-reuse policy, RSAT/GPMC impersonation behavior, policy
propagation or Linux/Windows runtime acceptance. Those require the real new
clients and both DCs. No runtime pass receipt is manufactured by local tests.

Current official references consulted (2026-11-08; Context7 quota was exhausted):

- [Proxmox qm manual](https://pve.proxmox.com/pve-docs/qm.1.html): `guest exec`
  `--pass-stdin`, EOF forwarding, 1 MiB input limit and synchronous timeout.
- [Samba 4.25.1 DRS implementation](https://github.com/samba-team/samba/blob/samba-4.25.1/python/samba/netcmd/drs.py):
  `repsFrom`, naming contexts, failure fields and native time strings.
- [Samba Group Policy](https://wiki.samba.org/index.php/Group_Policy): GPMC/RSAT
  and SYSVOL-backed policy; no assumption of native ADWS support.
- [Windows Server 2025 lifecycle](https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2025).
- [Microsoft Security Compliance Toolkit](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10).
- [Add-Computer](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/add-computer?view=powershell-5.1),
  [Set-GPRegistryValue](https://learn.microsoft.com/en-us/powershell/module/grouppolicy/set-gpregistryvalue?view=windowsserver2025-ps),
  [gpupdate](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/gpupdate).
- [adcli documentation](https://www.freedesktop.org/software/realmd/adcli/adcli.html).
