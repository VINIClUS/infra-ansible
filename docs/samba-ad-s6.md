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

### Managed Windows firmware and virtualization

The Windows-only `report.hardware` qualification is mandatory. It contains exact
`bios: ovmf`, versioned `machine: pc-q35-X.Y`, `cpu: host`, the source EFI
`efi_sha256`, and separate exact `template_volumes`, `clone_volumes` and
`destination_volumes` maps for `scsi0` and `efidisk0`. The maps record observed
allocation behavior of the qualified PVE version; clone/migration disk indices
are not assumed to match the template. Each volume must identify the exact
source template or new owned VM and declared storage. Additional disks,
cloud-init drives, shared roots, TPM state, passthrough and hooks remain refused
on this path. Linux/DC/CA keep their existing device guards. Production
`stop`/`absent` remain forbidden; this does not introduce a destruction path.

The source EFI must be 4m with pre-enrolled keys. S1 hashes its actual volume
before cloning, then verifies the full clone's exact owned disk identities before
configuration/migration and again at the destination. Firmware/CPU values remain
checked on re-execution/start. This copies only the explicitly qualified EFI
variable image, never TPM identity or a foreign volume. The private image review
must establish its clean generalized state and UEFI-lock capability. No image or
positive hardware report is supplied here.

`hardware.nodes` records each source/destination node's CPU vendor/model,
`extension` (`vmx` or `svm`), `slat` (`ept` or `npt`), `nested: true`, boot ID and
raw observation artifact SHA-256. Vendor/model must agree across the two nodes.
The live read-only probe checks every CPU's features, the existing KVM nested
parameter and boot ID, in addition to S1's pinned PVE/kernel fingerprint; it does
not load modules, enable nesting or change any host setting. A host reboot or
hardware/version drift requires new reviewed qualification. The destination is
rechecked immediately before boot.

`hardware.native` binds observed Secure Boot, available VBS properties and
UEFI-lock capability to the template observation. Before any GPO mutation the
actual client must pass `Confirm-SecureBootUEFI` and expose hypervisor, Secure
Boot and NX support in `Win32_DeviceGuard.AvailableSecurityProperties` (1, 2, 5).
Policy acceptance still requires running CG/HVCI; capability alone never passes
acceptance. TPM is recommended by Microsoft but is not required by these
selected controls, and no TPM state is created or cloned. Actual KVM/firmware/
Windows support, drivers and reboot behavior remain part of native qualification.

## Stages and evidence

1. `prepare` operates only inside the new owned client. Linux uses reviewed,
   version-pinned offline `.deb` assets and `apt-get --no-download`; Windows uses
   pinned Microsoft-signed offline feature assets and DISM `-LimitAccess`.
   Neither backend installs packages on PVE or performs unbounded discovery.
   Public root/intermediate certificates are installed, with exact SHA-256 pins.
2. Windows `prepare`, and every client `join`, `verify` or `policy`, require
   fresh host-local results from both exact DCs. Windows `prepare` creates no OU
   or computer account. Each checks
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
   one approved KDC per test, then destroys the cache. A direct Linux-PAM call to `pam_acct_mgmt` on the sshd stack preserves
   the actual PAM return code; any denial, expired-password state, incomplete
   start or failed cleanup rejects acceptance. `sssctl` diagnostic exit status
   is not authorization evidence. NSS lookups also exercise the configured stack. It does not claim Windows GPO execution.
5. Windows joins with `Add-Computer -Server DC01 -OUPath OWNED_OU`, without WinRM
   or ADWS. It reports `joined_reboot_required`; reboot only this new owned client
   and update its private observed boot pin before `verify` or `policy`. Reruns
   with matching local/AD ownership, SID and computer GUID verify membership and
   never rejoin. Secure-channel, LDAPS SID and actual SYSVOL reads use both DCs.
6. `policy` uses GPMC against DC01 only. Every component has a separately named
   new owned GPO; a seventh owned GPO enables loopback Merge so the vendor's user
   policies apply only to sessions on the pilot computers. Before the first
   write, and again before each import/link, the backend queries reverse links
   by GUID across the domain subtree and Sites. Any link outside the exact pilot
   OU, disabled/enforced link, duplicate, foreign description or unknown direct
   OU link stops the flow. Existing GPOs require exact content and enabled links;
   they are not reimported or reset. Partially created unlinked GPOs need explicit
   owned-object recovery.
7. Acceptance compares all selected policy files and GPT.INI through both DCs.
   A fresh `gpupdate`/`gpresult` is paired with native `RSOP_GPO` and
   `RSOP_ExtensionStatus` observations for that same refresh. The exact GUID must
   be enabled, valid, unfiltered and not denied in ComputerResults/UserResults;
   native versions must agree, every required extension must report error zero
   and complete logging within the refresh window, and the DC in that scope
   must match the requested DC. A GUID merely appearing in XML never passes.
   The effective registry, security export, audit policy and running Credential
   Guard/HVCI are checked. User policies are tested in a profile-loaded process
   using LogonUser/CreateProcessAsUser under the LocalSystem QGA token, with the actual domain SID verified. No password
   appears in its script, arguments or public input file. Both computer and user
   policy must pass through both DCs before the `policy` action returns `verified`;
   membership-only actions return `membership_verified`.

**S4 dependency ruling:** Linux `prepare` may run before DC02 exists, solely to
prepare the new owned Linux pilot as the external S4 protocol test driver. That
stage takes no join credential, performs no LDAP write or GPO operation, and
does not assert membership or full S6 acceptance. `join`, `verify`, and `policy`
retain the two-DC gate. This avoids the S4/S6 dependency cycle.

## Windows support, baseline and conditional controls

The initial native implementation supports actual Windows Server 2025 Standard
or Datacenter (including `ServerStandardEval` and `ServerDatacenterEval`), x86-64,
build 26100. The requested edition must match the qualified template and native
DISM observation. It queries CIM, DISM edition, ImageState, local SID, MachineGuid
and SoftwareLicensingProduct. Activation and purchased-license entitlement are
not pilot gates: unactivated supported images and evaluation images are allowed.
Probe/action results include the observed edition, evaluation flag and raw Windows
product IDs, numeric license statuses and remaining grace minutes; an empty
product list remains empty, and entitlement is explicitly `not_attested`. These
facts do not assert a purchased license or extend an evaluation period. No key
is collected or supplied, and no activation, rearm or edition conversion occurs.
The Server 2025 lifecycle date does not represent evaluation expiry or entitlement.
Placeholders can describe source preparation only; they cannot satisfy the real
image, identity, hardware, authentication or policy observations. The baseline
remains Server 2025-specific, including its mandatory CG/HVCI controls.
Windows 11 is not qualified here. The managed EFI exception below is restricted
to the reviewed Server 2025 pilot contract; TPM state remains forbidden.

The mandatory baseline is Microsoft's **Windows Server 2025 v2602** member-server
set, retrieved from the current official Security Compliance Toolkit page. The
exact public ZIP SHA-256 is
`a66dffbe2622c3c4dd70e44a7f2080f362fb2d6f9208c50678671cbb046a286f`.
The source-pinned catalog is reproducible with `pilot_baseline.catalog()` and
records every archive file hash and every setting in these six vendor components:

- Member Server: 103 Registry.pol records, 54 security settings, 24 audit settings.
- Internet Explorer Computer: 133 Registry.pol records.
- Domain Security: 8 security settings.
- Member Server Credential Guard: 8 Registry.pol records.
- Defender Antivirus: 27 Registry.pol records.
- Internet Explorer User: 3 Registry.pol records.

This covers 360 vendor policy records. The request cannot choose a subset or
supply an arbitrary exclusion list. Parsers reject unknown policy-bearing file
formats, unsupported Registry.pol records and duplicate settings. The native
adapter validates the complete archive and all extracted hashes, transforms only
the two approved S4 conflicts, then checks each complete prepared backup against
the source catalog before `Import-GPO` into a new owned target. Downloaded scripts
are never executed and arbitrary/unvalidated backups are never imported.

There are exactly two baseline substitutions, with S4 as the existing authority:
`PasswordHistorySize=24` becomes `30`, and `LockoutBadCount=3` becomes `10`.
Both original values must match the pinned vendor artifact, and transformed
GptTmpl.inf bytes have an exact expected hash. Other security values, privileges,
audit policies, computer policies and user policies remain mandatory. No domain
root link or Default Domain Policy/Default Domain Controllers Policy mutation is
performed; Domain Security settings are linked only to the pilot OU.

Encrypted LAPS, WHfB, AES-only and complete NTLM disablement remain conditional
P1 work. These controls are absent from the selected pinned vendor set, so this
release makes **no blanket omission** on their behalf. NTLM auditing and the
NTLMv2 floor remain in the mandatory settings. A future artifact containing a
conditional control requires a separate exact reviewed exception; it cannot be
silently added or excluded by private request fields. Credential Guard is part
of this vendor baseline and is **not** deferred: native hardware, reboot and
running-service requirements must pass. Current templates are not thereby
qualified for it.

RSoP acceptance has a fixed `server2025-gpmc-rsop-v1` parser profile. Before any
pilot GPO mutation, private SHA-256 pins and a review reference
must identify real `rsop-computer.xml` and `rsop-user.xml` samples under
`C:\SambaADAssets`, bound to the qualified template's observation artifact. The
samples must match the exact namespace/structure and contain positive applied-GPO
records. Preparation and membership can run with `rsop: null`; collect the real
computer/user reports from the newly joined owned pilot and review their pins
before `policy`. This avoids requiring domain RSoP before the client can join.
These are schema-qualification inputs, **not runtime acceptance**;
current acceptance additionally requires fresh native CIM results and the exact
current GPOs/versions/DC. Missing real samples, unrecognized schemas, stale
extensions, logging-incomplete extensions, or missing assets fail closed. No
synthetic test XML is shipped as a qualified receipt.

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
Only the fixed public source is gzip/Base64 compressed to fit the Windows
CreateProcess command-line limit; private inputs remain exclusively on stdin.
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

The user-policy worker explicitly requires LocalSystem and uses `LogonUserW`
(interactive primary token), `LoadUserProfileW`, `CreateEnvironmentBlock` and
`CreateProcessAsUserW`. It enables only the required process privileges during
the operation and restores them afterward. The password is marshalled from
SecureString only for the logon call and its unmanaged buffer is zeroed. Worker
argv/JSON contains public paths and policy assertions only. The worker has
read-only access to its script/input and write access only to a results folder.
No global QGA account change is made.

Creation is suspended without inherited handles; the worker is assigned to a
kill-on-close job before resuming. Wait is bounded to 180 seconds; failure or
timeout terminates the worker tree, then bounded cleanup drains the job,
closes thread/process/job handles, destroys the user environment, unloads the
profile, closes the token and restores privileges. Cleanup attempts every owned
resource even after another cleanup fails, and any failure rejects acceptance.
This source path still needs validation on the actual Windows service token,
profile/rights and native API implementation.

Official API/firmware references for this path:
- https://pve.proxmox.com/pve-docs/qm.1.html
- https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/
- https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity
- https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw
- https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw
- https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-loaduserprofilew

## Validation and limits

Synthetic pytest fixtures cover closed contract drift, foreign memberships,
secret-free argv, truncated/failed QGA results, wrong QGA identity, TLS-before-bind,
stale/mismatched DC evidence, DRS failure/peer/context checks, complete baseline coverage, inverse GPO scope, denied/filtered/stale RSoP,
real PAM denial codes, canonical UUIDs, Linux-only preparation exceptions,
bootstrap dependency loading and real disabled/manual Ansible guards. PowerShell
is parsed with its AST parser without executing the Windows backend. S1 and CA
lifecycle regressions are included in the focused test run.

These tests do not qualify an OS image, a license, Microsoft assets, a transport
version, Windows account-reuse policy, RSAT/GPMC impersonation behavior, policy
propagation or Linux/Windows runtime acceptance. Those require the real new
clients and both DCs. The current source is Server 2025-specific; a Windows 11
image/name does not satisfy its edition, baseline or hardware contract. No runtime pass receipt is manufactured by local tests.

Initial official references consulted (2026-11-08; Context7 quota was exhausted):

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

Round 2 documentation (2026-11-09): Context7's current Windows Server documentation
confirms the `Eval` edition suffix via DISM in
[upgrade/conversion options](https://learn.microsoft.com/en-us/windows-server/get-started/upgrade-conversion-options).
That reference is used only to identify the installed edition; this workflow
does not perform the documented conversion or activation operations.
The native license fields are documented by Microsoft's
[SoftwareLicensingProduct class](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/sppwmi/softwarelicensingproduct).
The Win32 references above were read directly as well: CreateProcessAsUser
requires explicit profile/environment management and LoadUserProfile requires
backup/restore privileges under an administrator or LocalSystem caller.

Additional primary evidence for the first review fixes:

- [Official v2602 artifact](https://download.microsoft.com/download/e99be2d2-e077-4986-a06b-6078051999dd/Windows%20Server%202025%20Security%20Baseline%20-%202602.zip).
  Its WSMember selection was read from the vendor script without executing it.
- [SSSD 2.10.1 diagnostic implementation](https://github.com/SSSD/sssd/blob/2.10.1/src/tools/sssctl/sssctl_user_checks.c):
  sssctl's diagnostic return status does not preserve PAM denial.
- [RSOP_GPO](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/rsop-gpo)
  and [RSOP_ExtensionStatus](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/rsop-extensionstatus):
  native version/authorization fields and numeric error/logging status.
