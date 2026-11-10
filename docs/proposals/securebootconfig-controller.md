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

Out of scope: PK/KEK key generation, option ROM fingerprinting, attestation. Those are covered
in `secure-boot-gardenlinux-v2.md` and `secureboot-setup.md`.

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

    // KeySecretRef names the Secret holding the Secure Boot key material.
    // The Secret must contain pk.crt, kek.crt, and one or more db.crt.N
    // and/or db.sha256.N entries (see §6 for the full key naming convention).
    // The Secret is read at enrollment time; updating it and annotating with
    // metal.ironcore.dev/operation=re-enroll triggers re-enrollment.
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
│    POST pk.crt → POST kek.crt → POST db.crt.* → POST db.sha256.*          │
│    reboot  →  verify UserMode (operator owns PK)                            │
│    release window B                   ──────────────────────────► Enrolled │
│                                                                             │
│  Enrolled (keys in NVRAM, SB not yet active)                                │
│    → immediately transitions to Enabling (no maintenance window released)  │
│                                                                             │
│  Enabling (maintenance window C)                                            │
│    PATCH SecureBootEnable=true                                              │
│    reboot                                                                   │
│    wait for Server.Status.PowerState=On                                     │
│    verify GetSecureBootState returns CurrentBoot=true (direct BMC read)     │
│      true  → SB active, enrollment confirmed                                │
│      false → Failed (SB flag set but CurrentBoot not active)                │
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

---

## 6. Populating the `keySecretRef` Secret (prerequisite)

The controller treats the `keySecretRef` Secret as opaque pre-built input. Before
a `SecureBootConfig` can be created, an operator must build the Secret and place
it in the same namespace. This section documents that offline process.

### 6.1 What the Secret must contain

The Redfish `SecureBootDatabases` API accepts individual PEM certificates and
SHA-256 hashes — not pre-signed `.auth` blobs. The Secret therefore contains
raw key material, one entry per Secret key:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: cluster-secureboot-keys
  namespace: metal-operator-system
type: Opaque
data:
  pk.crt:       <base64 PEM>   # operator Platform Key cert
  kek.crt:      <base64 PEM>   # operator Key Exchange Key cert
  db.crt.0:     <base64 PEM>   # GL bootloader signing cert
  db.crt.1:     <base64 PEM>   # NVIDIA option ROM signing cert
  db.crt.2:     <base64 PEM>   # Broadcom option ROM signing cert
  db.sha256.0:  <base64 hex>   # SHA-256 hash of a ROM that only chains to MS CA
  db.sha256.1:  <base64 hex>   # … additional ROM hashes
  dbx.sha256.0: <base64 hex>   # revoked binary hash (optional)
```

Key naming rules:
- `pk.crt` and `kek.crt` are fixed single keys
- `db.crt.N` — any suffix after `db.crt.` is valid; order is not significant
- `db.sha256.N` — any suffix after `db.sha256.` is valid
- `dbx.sha256.N` — optional revocation hashes
- Private keys (`pk.key`, `kek.key`) are **not** stored in this Secret — they
  are only needed when the PK/KEK certs themselves were generated and are not
  required by the controller for Redfish enrollment

The Secret is **per-cluster**: PK and KEK are generated once per cluster and
re-used across all `SecureBootConfig` resources. The `db` entries are the union
of all certs and hashes needed across the entire fleet.

### 6.2 Step 1 — Generate PK and KEK keypairs

```bash
# Platform Key
openssl req -newkey rsa:2048 -nodes -keyout PK.key -new -x509 -sha256 \
  -subj "/CN=Operator Platform Key" -out PK.crt
# Key Exchange Key
openssl req -newkey rsa:2048 -nodes -keyout KEK.key -new -x509 -sha256 \
  -subj "/CN=Operator KEK" -out KEK.crt
```

Store `PK.key` and `KEK.key` sealed (e.g. cluster KMS / sealed secret). The
`.crt` files are public and can be stored in version control.

### 6.3 Step 2 — Collect db entries from each server

For each server in the fleet, determine which entries are needed in `db`:

**GL bootloader cert** (same for all servers, all GL variants):
```bash
# Extract from a running GL OS
sbverify --list /boot/efi/EFI/BOOT/BOOTX64.EFI | grep "^Certificate"
# or from the GL release artefact directly
```

**Option ROM entries** — for each server, inspect each PCIe card's option ROM:
```bash
# From the running OS, extract ROM via sysfs
for dev in /sys/bus/pci/devices/*/rom; do
  echo 1 > "$dev"
  sbverify --list "$(dirname $dev)/rom" 2>/dev/null
  echo 0 > "$dev"
done
```

For each ROM found:
- If it chains to a vendor-owned cert (NVIDIA, Broadcom, etc.): record the cert
- If it chains only to the Microsoft 3rd-party UEFI CA: record the ROM's
  SHA-256 hash instead (see v2 proposal §2.5 for rationale)

Repeat on every server. The fleet `db` is the **union** of all entries collected.

### 6.4 Step 3 — Collect the db entries into the Secret

For each cert found:
```bash
# number sequentially starting from 0
kubectl create secret generic cluster-secureboot-keys \
  --from-file=pk.crt=PK.crt \
  --from-file=kek.crt=KEK.crt \
  --from-literal=db.crt.0="$(cat gl-db.crt)" \
  --from-literal=db.crt.1="$(cat nvidia.crt)" \
  --from-literal=db.crt.2="$(cat broadcom.crt)" \
  --from-literal=db.sha256.0="b1ee3fa0e98fadd50e6457ef739f018580ab6e9ed..." \
  --from-literal=db.sha256.1="9f3a2c..." \
  --dry-run=client -o yaml | kubectl apply -f -
```

Adding a new cert or hash = adding a new `db.crt.N` or `db.sha256.N` key and
applying the updated Secret. No signing step is required.

### 6.5 Updating the Secret (adding a new server or rotating keys)

When a new server introduces a cert or hash not yet in the fleet `db`:

1. Collect the new entries from the new server (§6.3)
2. Add new `db.crt.N` / `db.sha256.N` keys to the Secret
3. Apply the updated Secret — Kubernetes increments its `ResourceVersion`
4. The controller detects the change, sets `SecureBootDrifted=True` on all
   affected `SecureBootConfig` resources, and waits for the
   `metal.ironcore.dev/operation=re-enroll` annotation before acting

For a full key rotation (PK/KEK compromise): replace `pk.crt` and `kek.crt`,
and note that servers still holding the old PK require a Setup-Mode transition
before the new PK can be enrolled (see v2 proposal §2.3 key-loss table).

> **Private keys** (`PK.key`, `KEK.key`) are generated when creating the certs
> but are **not** stored in `keySecretRef`. They are not needed by the
> controller. Store them separately, sealed (cluster KMS / sealed secret).

---

## 7. Maintenance Window Sequencing


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

## 8. Firmware Update Interaction

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

## 9. `bmc/` Interface Additions (metal-operator)

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

    // EnrollCertificate posts a PEM certificate to the named Secure Boot
    // database (pk, kek, db, dbx) via the Redfish SecureBootDatabases
    // Certificates endpoint.
    EnrollCertificate(ctx context.Context, systemURI, database, pemCert string) error

    // EnrollHash posts a SHA-256 hash to the named Secure Boot database
    // via the Redfish SecureBootDatabases Signatures endpoint.
    // hash must be a 64-character lowercase hex string.
    EnrollHash(ctx context.Context, systemURI, database, hash string) error

    // ResetSecureBootKeys resets one or more key databases.
    ResetSecureBootKeys(ctx context.Context, systemURI string, resetType SecureBootResetType) error

    // SetSecureBootEnabled patches SecureBootEnable on the BMC.
    SetSecureBootEnabled(ctx context.Context, systemURI string, enable bool) error
}

// SecureBootResetType mirrors the Redfish SecureBoot.ResetKeys action values.
type SecureBootResetType string

const (
    SecureBootResetDeletePK              SecureBootResetType = "DeletePK"
    SecureBootResetDeleteAllKeys         SecureBootResetType = "DeleteAllKeys"
    SecureBootResetResetAllKeysToDefault SecureBootResetType = "ResetAllKeysToDefault"
)
```

Vendor implementation notes:
- **Dell iDRAC:** `EnrollCertificate` posts to `.../Certificates` with
  `{"CertificateString": "<PEM>", "CertificateType": "PEM"}`. `EnrollHash`
  posts to `.../Signatures` with `{"SignatureTypeRegistry": "UEFI",
  "SignatureType": "EFI_CERT_SHA256_GUID", "SignatureOwner":
  "00000000-0000-0000-0000-000000000000", "SignatureString": "<hex>"}`.
  Both return `SYS430` on success. All changes are staged and applied on reboot.
  Note: after reboot the `Certificates` and `Signatures` endpoints return
  `count: 0` due to a known iDRAC bug — verify via OS efivars instead.
- **HPE iLO:** same endpoint structure as Dell. PK enrollment requires a
  session token (`X-Auth-Token`) — Basic auth returns 401. All SB changes are
  deferred to reboot; never reboot mid-sequence between enrollment calls and the
  `SetSecureBootEnabled` call.
- **Lenovo XCC:** does not support Redfish-based Secure Boot key enrollment.
  Configuration is only possible via the F1 firmware setup menu. Lenovo servers
  are out of scope for automated `SecureBootConfig` enrollment.

---

## 10. Server Label and Condition Surface

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

## 11. Controller Struct and Watches

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

## 12. Reconciler Skeleton

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

## 13. Open Questions

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

