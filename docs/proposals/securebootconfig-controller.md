# `SecureBootConfig` Controller Design

This document specifies the API types, state machine, controller structure, and
interaction model for the `SecureBootConfig` resource in the
metal-maintenance-operator (MMO). It is the implementation companion to the
trust-model and Redfish-layer design in `secure-boot-gardenlinux-v2.md`.

---

## 1. Scope

This document covers:

- `SecureBootConfig` and `SecureBootConfigSet` CRD definitions
- The `SecureBootConfig` reconciler state machine (full lifecycle: enroll, enable,
  disable, drift detection)
- Interaction with `ServerMaintenance` (maintenance window sequencing)
- Interaction with `FirmwareUpdate` (disable-before-patch / re-enroll-after-patch)
- `bmc/` interface additions required in metal-operator
- Server label/condition surface exposed to metal-operator and `ServerClaim`
- The signed probe image: construction, dual-role use, and validation semantics

Out of scope: key generation, `db.auth` construction, attestation. Those are covered
in `secure-boot-gardenlinux-v2.md`.

---

## 2. API Group and Placement

`SecureBootConfig` belongs under `system.metal.ironcore.dev`, the same API group as
`BIOSSettings` and `FirmwareUpdate`. Secure Boot enrollment is a server-level
configuration operation of the same class.

Package path: `api/system/v1alpha1/`
Controller path: `internal/controller/system/securebootconfig_controller.go`

---

## 3. CRD: `SecureBootConfig`

### 3.1 Spec

```go
// SecureBootDesiredState is the top-level goal for the controller.
// +kubebuilder:validation:Enum=Enabled;Disabled
type SecureBootDesiredState string

const (
    // SecureBootDesiredStateEnabled instructs the controller to enroll operator
    // keys and enable Secure Boot. This is the production steady state.
    SecureBootDesiredStateEnabled SecureBootDesiredState = "Enabled"

    // SecureBootDesiredStateDisabled instructs the controller to disable Secure
    // Boot and clear all key databases. Used before firmware updates to prevent
    // a firmware NVRAM reset from leaving the server in an inconsistent state.
    SecureBootDesiredStateDisabled SecureBootDesiredState = "Disabled"
)

// SecureBootConfigSpec defines the desired state of SecureBootConfig.
type SecureBootConfigSpec struct {
    // ServerRef is the server to manage Secure Boot on. Immutable once set.
    // +kubebuilder:validation:XValidation:rule="self == oldSelf",message="serverRef is immutable"
    // +required
    ServerRef *corev1.LocalObjectReference `json:"serverRef"`

    // KeySecretRef names the cluster-scoped Secret holding pre-signed .auth
    // payloads: pk.auth, kek.auth, db.auth, and optionally dbx.auth.
    // The Secret is read at enrollment time; rotating it and patching
    // DesiredState back to Enabled triggers re-enrollment.
    // +required
    KeySecretRef corev1.LocalObjectReference `json:"keySecretRef"`

    // DesiredState controls the top-level goal.
    // +kubebuilder:default=Enabled
    DesiredState SecureBootDesiredState `json:"desiredState,omitempty"`

    // ServerMaintenancePolicy controls whether maintenance windows require
    // owner approval before the server is parked.
    // +kubebuilder:default=Enforced
    // +kubebuilder:validation:Enum=OwnerApproval;Enforced
    ServerMaintenancePolicy maintenancev1alpha1.ServerMaintenancePolicy `json:"serverMaintenancePolicy,omitempty"`

    // RetryPolicy defines automatic retry behaviour on transient failures.
    // +optional
    RetryPolicy *api.RetryPolicy `json:"retryPolicy,omitempty"`

    // ProgressDeadlineSeconds is the maximum time in seconds to wait without
    // observable forward progress before the resource is marked Failed.
    // +kubebuilder:default=3600
    // +optional
    ProgressDeadlineSeconds *int32 `json:"progressDeadlineSeconds,omitempty"`

    // ReadinessGates lists Server conditions that must be True before this
    // controller starts acting. Evaluated once at the Pending→active boundary.
    // +optional
    ReadinessGates []metalv1alpha1.ConditionRequirement `json:"readinessGates,omitempty"`

    // CompletionConditionType, if set, is the condition Type patched onto the
    // Server once this resource reaches its terminal success state (Enabled or
    // Disabled). Downstream resources can gate on it via their ReadinessGates.
    // Immutable once set.
    // +optional
    // +kubebuilder:validation:XValidation:rule="oldSelf == '' || self == oldSelf",message="completionConditionType is immutable once set"
    CompletionConditionType string `json:"completionConditionType,omitempty"`

    // SecureBootProbeImageRef is the OCI image reference for a signed probe
    // image used to validate end-to-end Secure Boot during the Enabling phase.
    // The image must be PE-signed with a cert present in the cluster's db.auth
    // so that UEFI will accept it under SB enforcement.
    //
    // The probe image serves two roles:
    //   1. Bootstrap fingerprinting (pre-enrollment, unsigned run): boot the
    //      image once per server model before SB is enforced to collect option
    //      ROM PCR2 measurements and cert chains needed to build db.auth.
    //   2. Post-enrollment validation (signed run): after the Enabling phase
    //      reboot, UEFI either accepts or rejects the signed image. The
    //      controller confirms success by reading SecureBootCurrentBoot=true
    //      from the BMC — no phone-home from the image is required.
    //
    // The same image binary is used for both roles. Signing happens once at
    // cluster bootstrap alongside operator key generation, producing a signed
    // variant pushed to the cluster registry.
    //
    // If omitted, the controller skips the probe boot and reads
    // SecureBootCurrentBoot directly from the BMC after the standard reboot.
    // This is a weaker validation (confirms the SB flag is set but does not
    // exercise the full signed boot chain) and is intended only as a fallback
    // before the probe image is available.
    // +optional
    SecureBootProbeImageRef string `json:"secureBootProbeImageRef,omitempty"`
}
```

### 3.2 Status

```go
// SecureBootConfigState is the top-level lifecycle state.
type SecureBootConfigState string

const (
    SecureBootConfigStatePending      SecureBootConfigState = "Pending"
    SecureBootConfigStateClearingKeys SecureBootConfigState = "ClearingKeys"
    SecureBootConfigStateEnrolling    SecureBootConfigState = "Enrolling"
    SecureBootConfigStateEnrolled     SecureBootConfigState = "Enrolled"
    SecureBootConfigStateEnabling     SecureBootConfigState = "Enabling"
    SecureBootConfigStateEnabled      SecureBootConfigState = "Enabled"
    SecureBootConfigStateDisabled     SecureBootConfigState = "Disabled"
    SecureBootConfigStateFailed       SecureBootConfigState = "Failed"
)

// SecureBootConfigStatus defines the observed state of SecureBootConfig.
type SecureBootConfigStatus struct {
    // State is the current reconciliation state.
    // +optional
    State SecureBootConfigState `json:"state,omitempty"`

    // ServerMaintenanceRef is the maintenance window currently held, if any.
    // +optional
    ServerMaintenanceRef *metalv1alpha1.ObjectReference `json:"serverMaintenanceRef,omitempty"`

    // CurrentMode is the SecureBootMode last read from the BMC
    // (SetupMode / UserMode / AuditMode / DeployedMode).
    // +optional
    CurrentMode string `json:"currentMode,omitempty"`

    // EnabledKeySecret records the ResourceVersion of the KeySecretRef Secret
    // at the time of the last successful enrollment and enabling. Used to
    // detect whether the secret has been updated and re-enrollment is needed.
    // +optional
    EnabledKeySecret string `json:"enabledKeySecret,omitempty"`

    // LastEnabledTime is when the Enabled state was last reached.
    // +optional
    LastEnabledTime *metav1.Time `json:"lastEnabledTime,omitempty"`

    // LastProgressTime records the last observed forward progress. Used with
    // ProgressDeadlineSeconds to detect stalled reconciliation.
    // +optional
    LastProgressTime *metav1.Time `json:"lastProgressTime,omitempty"`

    // FailedAttempts counts automatic retries after entering Failed state.
    // +optional
    FailedAttempts int32 `json:"failedAttempts,omitempty"`

    // ObservedGeneration is the spec generation last acted on.
    // +optional
    ObservedGeneration int64 `json:"observedGeneration,omitempty"`

    // Conditions holds per-phase conditions for observability.
    // +patchStrategy=merge
    // +patchMergeKey=type
    // +optional
    Conditions []metav1.Condition `json:"conditions,omitempty"`
}
```

### 3.3 Conditions

| Condition type | Set when |
|---|---|
| `ServerMaintenanceCreated` | maintenance window requested (reuses shared constant) |
| `ServerMaintenanceWaiting` | waiting for maintenance approval or InMaintenance |
| `KeysCleared` | ClearingKeys phase completed, SetupMode confirmed |
| `KeysEnrolled` | Enrolling phase completed, pk/kek/db posted and reboot done, UserMode confirmed |
| `SecureBootEnabled` | Enabling phase completed, `SecureBootCurrentBoot=true` confirmed (`Enabled` state) |
| `SecureBootDrifted` | SB observed off post-reboot (`HardwareChange`) or key Secret updated (`KeySecretUpdated`) while in `Enabled` state; human action required via `re-enroll` annotation |
| `ReadinessGatesSatisfied` | readiness gates evaluated (reuses shared pattern) |
| `ProgressDeadlineExceeded` | stall detected (reuses shared constant) |

---

## 4. CRD: `SecureBootConfigSet`

Follows the standard MMO Set pattern: holds a template and a server selector;
stamps out one `SecureBootConfig` per matching server; propagates spec changes to
owned objects; deletes owned objects when a server no longer matches.

```go
type SecureBootConfigSetSpec struct {
    // SecureBootConfigTemplate is the template applied to each matched server.
    SecureBootConfigTemplate `json:",inline"`

    // ServerSelector selects the servers to manage. An empty selector matches
    // no servers.
    // +required
    ServerSelector metav1.LabelSelector `json:"serverSelector"`
}

type SecureBootConfigTemplate struct {
    // KeySecretRef, DesiredState, ServerMaintenancePolicy, RetryPolicy,
    // ProgressDeadlineSeconds — all fields from SecureBootConfigSpec except
    // ServerRef (which is filled in per-server by the Set controller) and
    // CompletionConditionType (not meaningful at the Set level).
    KeySecretRef            corev1.LocalObjectReference                    `json:"keySecretRef"`
    DesiredState            SecureBootDesiredState                         `json:"desiredState,omitempty"`
    ServerMaintenancePolicy maintenancev1alpha1.ServerMaintenancePolicy    `json:"serverMaintenancePolicy,omitempty"`
    RetryPolicy             *api.RetryPolicy                               `json:"retryPolicy,omitempty"`
    ProgressDeadlineSeconds *int32                                         `json:"progressDeadlineSeconds,omitempty"`
}
```

The `SecureBootConfigSet` controller is a simple fan-out reconciler (~300 lines,
matching `BIOSSettingsSet`). It does not interact with the BMC directly.

---

## 5. State Machine

The controller is purely reactive: it acts only when a `SecureBootConfig` object
exists. It does not scan for servers to act on.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  DesiredState = Enabled                                                     │
│                                                                             │
│  Pending ──inspect BMC──────────────────────────────────────────────────── │
│    │  already Enabled: keys match + SB on + UserMode   ──────────► Enabled │
│    │  SetupMode (no PK)                                ──────────► Enrolling│
│    └─ UserMode, foreign PK or SB off                  ──────────► Clearing │
│                                                                             │
│  ClearingKeys (maintenance window A)                                        │
│    PATCH SecureBootEnable=false                                             │
│    ResetKeys: db, dbx, KEK, then PK  →  SetupMode                          │
│    reboot  →  verify SetupMode                                              │
│    release window A                   ──────────────────────────► Enrolling│
│                                                                             │
│  Enrolling (maintenance window B)                                           │
│    POST pk.auth → POST kek.auth → POST db.auth → POST dbx.auth (optional)  │
│    reboot  →  verify UserMode (operator owns PK)                            │
│    release window B                   ──────────────────────────► Enrolled │
│                                                                             │
│  Enrolled (keys in NVRAM, SB not yet active)                                │
│    → immediately transitions to Enabling (no maintenance window released)  │
│                                                                             │
│  Enabling (maintenance window C)                                            │
│    PATCH SecureBootEnable=true                                              │
│    if SecureBootProbeImageRef set:                                          │
│      set Server.Spec.BootConfigurationRef to signed probe image             │
│    reboot                                                                   │
│    wait for Server.Status.PowerState=On                                     │
│    verify GetSecureBootState returns CurrentBoot=true (direct BMC read)     │
│      true  → SB validated end-to-end via signed probe boot chain           │
│      false → Failed (SB flag set but boot chain rejected by UEFI)          │
│    clear BootConfigurationRef (if probe image was set)                      │
│    patch Server label: metal.ironcore.dev/secure-boot-enabled=true         │
│    patch Server condition: CompletionConditionType=True (if set)            │
│    release window C                   ──────────────────────────► Enabled  │
│                                                                             │
│  Enabled (terminal success)                                                 │
│    on resync: GetSecureBootState                                            │
│    no drift (SB on + keys match keySecret ResourceVersion)  →  requeue     │
│    drift detected                                           →  Pending      │
│    spec.DesiredState patched to Disabled                    →  Pending      │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│  DesiredState = Disabled                                                    │
│                                                                             │
│  Pending ──inspect BMC──────────────────────────────────────────────────── │
│    │  SB already off + SetupMode (keys already clear)  ────────► Disabled  │
│    └─ SB on or keys present                            ────────► Clearing  │
│                                                                             │
│  ClearingKeys (maintenance window)                                          │
│    PATCH SecureBootEnable=false                                             │
│    ResetKeys: db, dbx, KEK, then PK  →  SetupMode                          │
│    reboot  →  verify SetupMode + SB off                                     │
│    patch Server label: metal.ironcore.dev/secure-boot-enabled=false        │
│    patch Server condition: CompletionConditionType=True (if set)            │
│    release window                     ──────────────────────────► Disabled │
│                                                                             │
│  Disabled (terminal success for DesiredState=Disabled)                      │
│    spec.DesiredState patched to Enabled  →  Pending                        │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│  Failed (both paths)                                                        │
│    FailedAttempts < RetryPolicy.MaxAttempts  →  auto-retry to Pending       │
│    FailedAttempts exhausted: stays Failed; manual retry via                 │
│      metal.ironcore.dev/operation=retry annotation                          │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 5.1 Pending phase detail

The Pending phase reads the BMC state before deciding which path to take. It
never holds a maintenance window — the inspection is read-only. Readiness gates
are evaluated here; if unsatisfied the controller parks in Pending until they
are met.

```
Pending:
  1. evaluate ReadinessGates against Server.Status.Conditions
     → gates not satisfied: update ReadinessGatesSatisfied condition, requeue
  2. GetSecureBootState(ctx, server.Spec.SystemURI)
     → BMC unavailable: requeue (transient)
     → manufacturer not in supported set: → Failed (UnsupportedVendor)
  3. read keySecret ResourceVersion
  4. branch on DesiredState and observed state (see state machine above)
```

### 5.2 Drift detection (`Enabled` state)

Both forms of drift are handled the same way: alert and wait for explicit
operator action. Re-enrollment requires a maintenance window and a reboot and
must not be triggered automatically — each case warrants human review before
committing to a trust chain change on a production server.

**1. SB observed off after a reboot (hardware change)**

`CurrentBoot` is a read-only UEFI variable set at POST; it cannot change on a
running server. Disabling SB via Redfish also requires a subsequent reboot to
take effect. So a change to the persisted `SecureBootEnable` flag can only take
effect after a reboot. The controller detects this on its periodic reconcile:
`handleEnabled` calls `GetSecureBootState` directly against the BMC. No Server
watch is needed — `Server.Status.SecureBoot` is not used for drift detection.

**2. Key Secret updated (PK / KEK / db / dbx change)**

When the operator updates the `keySecretRef` Secret, Kubernetes increments the
Secret's `ResourceVersion`. The server continues booting normally with its
current NVRAM. The controller stores the `ResourceVersion` at last successful
enrollment in `status.enabledKeySecret`; on each reconcile of an `Enabled`
resource it compares this against the current ResourceVersion.

**Response (identical for both cases)**

The controller does not self-remediate. Instead it:

- sets `SecureBootDrifted=True` on the `SecureBootConfig` with a reason
  (`HardwareChange` or `KeySecretUpdated`) and timestamp
- emits a Kubernetes Event
- remains in `Enabled` state

An external alert fires on the condition. A human reviews, determines cause, and
triggers re-enrollment by annotating the resource:

```
metal.ironcore.dev/operation=re-enroll
```

The controller clears `SecureBootDrifted`, records the current Secret
`ResourceVersion` into `status.enabledKeySecret`, and transitions to `Pending`.

Full cert fingerprint comparison (reading the actual enrolled certs from the BMC
via Redfish `SecureBootDatabases`) is deferred — expensive and vendor support is
inconsistent. The ResourceVersion approach covers the primary operational case
with no extra BMC round-trips.

### 5.3 Probe image

The `SecureBootProbeImageRef` image serves two roles across its lifecycle:

**Role 1 — Pre-enrollment option ROM fingerprinting (run unsigned)**

Before SB is enforced, boot the image on each server to determine which signing
certs need to be in `db` for the PCIe cards present in that server. The image
reads the TPM PCR2 event log (`/sys/kernel/security/tpm0/binary_bios_measurements`
via `tpm2_eventlog`) and inspects PCI ROM binaries via `sbverify --list` to
determine the signing cert chain for each card. The image runs *before* SB is
enabled so no signing is required for this role.

**Frequency and db construction:** Fingerprinting runs once per server. There is
no automated way to determine upfront which servers have identical card
configurations, so each server is treated independently. Results are merged: the
cluster `db.auth` in `keySecretRef` is the **union across every server in the
fleet**. Extra entries for cards a server does not have are harmless. The union
`db.auth` is then enrolled on all servers identically.

**Cert entries vs. hash entries per card:** For each card found during
fingerprinting, the choice of `db` entry type depends on its signing chain:

- **`EFI_CERT_X509` (vendor cert):** used when the option ROM chains to a
  vendor-owned cert (e.g. NVIDIA NDIS Device Identity root, Broadcom leaf). This
  is the preferred approach — stable across card firmware updates and narrowly
  scoped to that vendor.
- **`EFI_CERT_SHA256` (binary hash):** used when the option ROM chains *only* to
  the **Microsoft 3rd-party UEFI CA**. Enrolling that CA would be too broad —
  it transitively trusts all firmware Microsoft has ever cosigned. In that case,
  the specific ROM binary's SHA-256 hash is enrolled instead.

Hash entries are per-server (a different unit may have a different ROM version)
and are invalidated by card firmware updates. This is an accepted cost; the
alternative of enrolling the Microsoft CA is not acceptable given our trust model
(see v2 proposal §2.5). Fingerprinting must be re-run after a card firmware
update on any server carrying hash-based ROMs, and the cluster `db.auth` rebuilt.

Fingerprinting must also be re-run on each newly added server if it introduces a
cert or hash not yet present in the union.

**Role 2 — Post-enrollment boot chain validation (run signed, after each
enrollment)**

After `PATCH SecureBootEnable=true` and the `Enabling` phase reboot, the
controller sets `Server.Spec.BootConfigurationRef` to boot the signed probe
image. UEFI either accepts or rejects the image's boot chain against `db`. The
controller observes the outcome purely from the BMC:

- `Server.Status.PowerState` transitions to `On` — server came back up
- `SecureBootInspector.GetSecureBootState` returns `CurrentBoot=true` — SB was
  active on that boot (read directly from BMC, not from `Server.Status`)

If both are true, the full signed boot chain validated. If `CurrentBoot` is
`false` after the server comes back, the boot chain was rejected by UEFI (wrong
cert, missing cert, or tampered binary) and the controller transitions to
`Failed`. No phone-home from the image is required — UEFI's accept/reject
decision is already reflected in `CurrentBoot`.

**Image construction**

The probe image is a minimal Linux image containing `tpm2-tools`, `tpm2-tss`,
`lspci`, and `sbsigntools`. It is built once and shared across both roles. At
cluster bootstrap, alongside operator key generation, the image's bootloader and
UKI are PE-signed with the operator db key and pushed to the cluster registry as
the `SecureBootProbeImageRef`. The unsigned build artifact is retained as the
operator fingerprinting tool; the signed registry image is the validation probe.

---

## 6. Maintenance Window Sequencing

Each active phase (ClearingKeys, Enrolling, Enabling) holds exactly one
`ServerMaintenance` object. The window is created at phase entry, used for its
reboot, and deleted before the next state is entered — the controller never holds
two windows simultaneously.

### 6.1 Priority assignments

Priority determines which window wins when multiple controllers compete for the
same server. Higher number = processed first.

| Resource | Priority | Rationale |
|---|---|---|
| `SecureBootConfig` (ClearingKeys / Disable path) | 20 | Must disable SB before firmware touches NVRAM |
| `FirmwareUpdate` | 10 | Runs after SB is off; must complete before re-enroll |
| `SecureBootConfig` (Enrolling / Enabling path) | 5 | Runs last; re-establishes SB after firmware |
| `BIOSSettings` | 0 (default) | Standard settings; lowest priority |

Only one `ServerMaintenance` is `InMaintenance` at a time per server. When a
higher-priority window exists, lower-priority windows remain in `Pending`.

### 6.2 Reboot within a maintenance window

The reboot pattern follows `FirmwareUpdate` exactly:

```
handleBMCReset call:
  IssueReset  → POST ComputerSystem.Reset (GracefulRestart or ForceRestart)
  ResetPending → poll Server.Status.PowerState until Off then On
  RecentlyReset → guard against issuing two resets in MinBMCResetInterval
  Persist → update LastProgressTime to prevent deadline expiry during reboot
```

The server is parked (via the `ServerMaintenance` owner annotation on the
`Server` object) for the duration. Normal state-machine progression, boot, and
power healing on the MO side are suspended while parked.

---

## 7. Firmware Update Interaction

### 7.1 The correct ordering

```
1. SecureBootConfig (DesiredState=Disabled)  →  ClearingKeys  →  Disabled
2. FirmwareUpdate                            →  InProgress    →  Completed
3. SecureBootConfig (DesiredState=Enabled)   →  Enrolling     →  Enabled
```

### 7.2 Wiring with ReadinessGates and CompletionConditionType

The three resources are decoupled via Server conditions. Neither controller reads
the other's CRD.

```yaml
# Resource 1: disable SB; signal when done
apiVersion: system.metal.ironcore.dev/v1alpha1
kind: SecureBootConfig
spec:
  serverRef: { name: server-xyz }
  keySecretRef: { name: cluster-secureboot-keys }
  desiredState: Disabled
  completionConditionType: system.metal.ironcore.dev/SecureBootDisabled

# Resource 2: update firmware; wait for SB off; signal when done
apiVersion: system.metal.ironcore.dev/v1alpha1
kind: FirmwareUpdate
spec:
  serverRef: { name: server-xyz }
  readinessGates:
    - conditionType: system.metal.ironcore.dev/SecureBootDisabled
  completionConditionType: system.metal.ironcore.dev/FirmwareUpToDate
  # ... vendor-specific update fields ...

# Resource 3: re-enroll SB; wait for firmware done
apiVersion: system.metal.ironcore.dev/v1alpha1
kind: SecureBootConfig
spec:
  serverRef: { name: server-xyz }
  keySecretRef: { name: cluster-secureboot-keys }
  desiredState: Enabled
  readinessGates:
    - conditionType: system.metal.ironcore.dev/FirmwareUpToDate
```

Resources 1 and 3 can be the **same `SecureBootConfig` object** if the operator
patches `spec.desiredState` rather than creating two objects. The controller
detects the spec change via `ObservedGeneration` and re-evaluates from `Pending`.

### 7.3 What triggers the disable

The `SecureBootConfig` controller is reactive — it does not watch `FirmwareUpdate`
objects. The actor that changes `spec.desiredState` to `Disabled` is:

- **Manual:** the platform operator patches the object before creating a
  `FirmwareUpdate`.
- **Automated:** an external controller or script watches `FirmwareUpdate`
  creation events and patches the corresponding `SecureBootConfig`. This lives
  outside MMO to avoid cross-controller coupling.

---

## 8. `bmc/` Interface Additions (metal-operator)

Two narrow interfaces are added to `metal-operator/bmc/bmc.go`.

### 8.1 `SecureBootInspector` (used by MO server reconciler)

```go
// SecureBootInspector is a read-only interface used by the metal-operator server
// reconciler to populate Server.Status.SecureBoot, and by the MMO
// SecureBootConfig controller for direct BMC reads during enrollment phases.
type SecureBootInspector interface {
    GetSecureBootState(ctx context.Context, systemURI string) (*SecureBootState, error)
}

type SecureBootState struct {
    Enabled       bool   // SecureBootEnable (persisted flag)
    EnabledOnBoot bool   // SecureBootCurrentBoot (was SB active on last boot?)
    Mode          string // SetupMode | UserMode | AuditMode | DeployedMode
}
```

### 8.2 `SecureBootManager` (used by MMO `SecureBootConfig` controller)

```go
// SecureBootManager is the write interface used by the MMO SecureBootConfig
// controller. It embeds SecureBootInspector so the controller only needs to
// accept one interface.
type SecureBootManager interface {
    SecureBootInspector

    // EnrollSecureBootAuth posts a pre-signed EFI_VARIABLE_AUTHENTICATION_2
    // blob to the named database (pk, kek, db, dbx).
    EnrollSecureBootAuth(ctx context.Context, systemURI, database string, authBlob []byte) error

    // ResetSecureBootKeys resets one or more key databases.
    ResetSecureBootKeys(ctx context.Context, systemURI string, resetType SecureBootResetType) error

    // SetSecureBootEnabled patches SecureBootEnable on the BMC.
    SetSecureBootEnabled(ctx context.Context, systemURI string, enable bool) error
}

// SecureBootResetType mirrors the Redfish SecureBoot.ResetKeys action values.
type SecureBootResetType string

const (
    SecureBootResetDeletePK           SecureBootResetType = "DeletePK"
    SecureBootResetDeleteAllKeys      SecureBootResetType = "DeleteAllKeys"
    SecureBootResetResetAllKeysToDefault SecureBootResetType = "ResetAllKeysToDefault"
)
```

Vendor implementation notes:
- **Dell iDRAC:** key enrollment may be queued as a Lifecycle Controller job;
  `EnrollSecureBootAuth` must poll the job to completion before returning.
- **HPE iLO:** a BIOS (not BMC) reset is required to commit key changes; the
  controller's reboot step covers this.
- **Lenovo XCC:** does not support Redfish-based Secure Boot key enrollment.
  Configuration is only possible via the F1 firmware setup menu. Lenovo servers
  are out of scope for automated `SecureBootConfig` enrollment.

---

## 9. Server Label and Condition Surface

The `SecureBootConfig` controller writes two things onto the `Server` object that
MO and `ServerClaim` scheduling can consume.

### 9.1 Label

| Label | Value | Written when |
|---|---|---|
| `metal.ironcore.dev/secure-boot-enabled` | `"true"` | Enabling phase completes (`Enabled` state reached) |
| `metal.ironcore.dev/secure-boot-enabled` | `"false"` | ClearingKeys phase completes (`Disabled` state reached) |

The MO server reconciler additionally writes:

| Label | Value | Written when |
|---|---|---|
| `metal.ironcore.dev/secure-boot-capable` | `"true"` | Discovery: `GetSecureBootState` succeeds (BMC exposes Redfish SecureBoot) |

### 9.2 Server.Status.SecureBoot (metal-operator addition)

```go
type SecureBootStatus struct {
    // Enabled is the persisted SecureBootEnable flag from the BMC.
    Enabled bool `json:"enabled"`
}

// Added to ServerStatus:
SecureBoot *SecureBootStatus `json:"secureBoot,omitempty"`
```

MO's server reconciler populates this on every reconcile using `SecureBootInspector`.
Absent on servers whose BMC does not expose the Redfish SecureBoot resource.

`CurrentBoot` and `Mode` are not surfaced here. `CurrentBoot` is only relevant
during the `Enabling` phase validation reboot — the controller reads it directly
from the BMC via `SecureBootInspector` at that point. `Mode` is always `UserMode`
in steady state and has no value as a persistent status field.

### 9.3 How ServerClaim uses this

For a cluster-wide SB enforcement model (all servers enrolled via
`SecureBootConfigSet`), no `ServerClaim` change is needed — every claimable
server already has the label. For selective enforcement, a claim uses:

```yaml
spec:
  serverSelector:
    matchLabels:
      metal.ironcore.dev/secure-boot-enabled: "true"
```

---

## 10. Controller Struct and Watches

```go
type SecureBootConfigReconciler struct {
    client.Client
    ManagerNamespace        string
    DefaultProtocol         metalv1alpha1.ProtocolScheme
    SkipCertValidation      bool
    Scheme                  *runtime.Scheme
    BMCOptions              bmc.Options
    ResyncInterval          time.Duration
    Conditions              *conditionutils.Accessor
    DefaultFailedAutoRetryCount int32
    ProgressDeadlineSeconds int32
}
```

Watches:
- `SecureBootConfig` (primary)
- `ServerMaintenance` (enqueues owning `SecureBootConfig` on state change —
  needed to detect when a window becomes `InMaintenance`)
- `Secret` (enqueues `SecureBootConfig` objects referencing the secret by name —
  needed for key-rotation drift detection via ResourceVersion change)

Hardware drift (SB disabled out-of-band) is detected on the periodic reconcile
driven by `ResyncInterval`: the `handleEnabled` path calls `GetSecureBootState`
directly against the BMC rather than reading `Server.Status`.

---

## 11. Reconciler Skeleton

```go
func (r *SecureBootConfigReconciler) Reconcile(ctx, req) (ctrl.Result, error) {
    sbc := &systemv1alpha1.SecureBootConfig{}
    if err := r.Get(ctx, req.NamespacedName, sbc); err != nil {
        return ctrl.Result{}, client.IgnoreNotFound(err)
    }
    return r.reconcileExists(ctx, sbc)
}

func (r *SecureBootConfigReconciler) reconcileExists(ctx, sbc) (ctrl.Result, error) {
    if shouldDelete { return r.delete(ctx, sbc) }
    return r.reconcile(ctx, sbc)
}

func (r *SecureBootConfigReconciler) reconcile(ctx, sbc) (ctrl.Result, error) {
    // 1. ensure finalizer
    // 2. ensure progressDeadline not exceeded
    // 3. transitionState
}

func (r *SecureBootConfigReconciler) transitionState(ctx, sbc) (bool, error) {
    server  := getServer(sbc.Spec.ServerRef)
    bmcClient := getBMCClient(server)   // type-assert to SecureBootManager

    switch sbc.Status.State {
    case "", Pending:   return r.handlePending(ctx, bmcClient, sbc, server)
    case ClearingKeys:  return r.handleClearingKeys(ctx, bmcClient, sbc, server)
    case Enrolling:     return r.handleEnrolling(ctx, bmcClient, sbc, server)
    case Enrolled:      return r.handleEnrolled(ctx, bmcClient, sbc, server)
    case Enabling:      return r.handleEnabling(ctx, bmcClient, sbc, server)
    case Enabled:       return r.handleEnabled(ctx, bmcClient, sbc, server)
    case Disabled:      return r.handleDisabled(ctx, sbc)
    case Failed:        return r.handleFailed(ctx, bmcClient, sbc, server)
    }
}
```

---

## 12. Open Questions

These are deferred from the initial implementation:

- **Full cert fingerprint drift detection:** reading `SecureBootDatabases` entries
  from the BMC and comparing against the expected cert fingerprints in the
  `keySecret`. Covers the case where a vendor firmware update modifies `db`
  without wiping it entirely (ResourceVersion comparison would miss this).
  Deferred until real-hardware testing confirms vendor `SecureBootDatabases`
  read support.
- **DPU own Secure Boot:** the BlueField DPU has an independent UEFI SB stack
  (`Systems/Bluefield/SecureBoot`). This is a separate follow-up; the host SB
  design is independent of it.
- **`SecureBootConfigSet` deletion policy:** when a server is removed from the
  selector (e.g. decommissioned), should the owned `SecureBootConfig` be deleted
  (leaving SB enabled but unmanaged) or should it first disable SB? Current
  proposal: delete the object without disabling SB — SB state is persistent in
  firmware NVRAM and the server is leaving the cluster anyway.
- **Probe image PCR2 output format:** define the structured format the probe
  image uses to report option ROM measurements (JSON to a known endpoint, or
  written to a well-known path the operator retrieves). Needed before the
  fingerprinting role can be automated rather than driven manually.
