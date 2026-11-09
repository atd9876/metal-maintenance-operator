# Secure Boot Setup for GardenLinux — Bare Metal Servers

This document describes how to configure Secure Boot on a bare metal server using a signed OS image. It covers the full process: understanding the trust chain, extracting the signing certificate, determining which option ROM hashes are required, enrolling everything via the BMC Redfish API, and verifying the result.

The approach described here targets **minimal db enrollment** — only the exact entries the firmware will actually verify at boot, no vendor CA certificates.

Procedures are documented for two hardware vendors. Jump to the relevant section:
- [Dell (iDRAC)](#dell-idrac) — Steps 1–6 below
- [HPE (iLO)](#hpe-ilo) — separate section after the Dell steps

---

## Dell (iDRAC)

## Overview

UEFI Secure Boot works by checking loaded EFI binaries against the **db** (allowed signatures database) before executing them. Two categories of code are checked:

1. **PCI option ROMs** — firmware loaded from PCIe cards (NICs, storage controllers). The UEFI PCI bus driver checks these against db.
2. **The boot application** — the first EFI executable on the boot path (e.g. `BOOTX64.EFI`, typically a bootloader).

Internal firmware DXE drivers (code baked into the UEFI flash image) are **not** checked against db — they are implicitly trusted via the firmware's own signature.

Each db entry is either:
- An **X.509 certificate** (`EFI_CERT_X509_GUID`) — authorises any binary signed by that cert.
- A **SHA-256 hash** (`EFI_CERT_SHA256_GUID`) — authorises one specific binary image.

The minimal db for a GardenLinux server therefore needs:
- **1 cert**: the cert that signed `BOOTX64.EFI`
- **N hashes**: one per distinct PCI option ROM image that the firmware SB-verifies

---

## Prerequisites

- iDRAC access (Redfish API) with credentials
- The signed OS image or the signing certificate used to sign `BOOTX64.EFI`
- `openssl`, `sbverify` (from `sbsigntool`), `tpm2-tools` on the OS
- Python 3 (for hash extraction scripts)

Set up environment variables before running any Redfish calls:

```sh
export BMC_USER="$(kubectl get bmcsecret <node> -o jsonpath='{.data.username}' | base64 -d)"
export BMC_PASS="$(kubectl get bmcsecret <node> -o jsonpath='{.data.password}' | base64 -d)"
export IDRAC="https://<idrac-ip>"
export SYS="$IDRAC/redfish/v1/Systems/System.Embedded.1"
export SB="$SYS/SecureBoot"
```

---

## Step 1 — Extract the bootloader signing certificate

The cert that signed `BOOTX64.EFI` must be enrolled in db. Get it from either the signed image or your signing infrastructure.

### From a running OS

```sh
# Check what cert signed the bootloader
sbverify --list /efi/EFI/BOOT/BOOTX64.EFI
```

This prints the certificate chain. The leaf cert (CN=...) is the one to enroll.

### From your signing infrastructure

If you control the signing key (e.g. a test/dev setup), you already have `db-gl.crt`. Confirm it matches:

```sh
# Fingerprint of the cert you plan to enroll
openssl x509 -in db-gl.crt -noout -fingerprint -sha256

# Fingerprint of the signer on the binary
sbverify --list BOOTX64.EFI 2>&1 | grep -A5 'Certificate'
```

They must match. If the binary is signed by an intermediate, enroll the cert that directly signed it (the leaf), not the CA — unless you want that CA to authorise all its future binaries too.

### One cert entry covers the full boot chain

If `BOOTX64.EFI` (systemd-boot) and the UKI are both signed with the same cert, a single db cert entry authorises both. systemd-boot loads the UKI via `LoadImage()`, which triggers firmware SB verification — but once the cert is matched for `BOOTX64.EFI`, the firmware caches the result and does not produce a second `EV_EFI_VARIABLE_AUTHORITY` event in PCR7 for the UKI. You do **not** need a separate db entry (cert or hash) for the UKI.

If you sign the UKI with a different cert (e.g. to allow independent revocation), enroll that cert as a second db entry.

---

## Step 2 — Determine the required option ROM hashes

Boot the server **with Secure Boot disabled** and capture the TPM event log. This tells you exactly which option ROM images the firmware loaded.

```sh
# On the OS
sudo tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements > tpm-eventlog.txt
```

Extract the hashes of PCI option ROMs (device path type `02 01` = Hardware/PCI):

```python
import re, json

log = open('tpm-eventlog.txt').read()
events = re.split(r'(?=^- EventNum:)', log, flags=re.MULTILINE)

hashes = {}
for ev in events:
    type_m  = re.search(r'EventType:\s+(\S+)', ev)
    pcr_m   = re.search(r'PCRIndex:\s+(\d+)', ev)
    digest_m = re.search(r'Digest:\s+"([0-9a-f]{64})"', ev)
    dp_m    = re.search(r'DevicePath:\s+\'([0-9a-f]+)\'', ev)
    if not all([type_m, pcr_m, digest_m, dp_m]):
        continue
    if (type_m.group(1) == 'EV_EFI_BOOT_SERVICES_DRIVER'
            and pcr_m.group(1) == '2'
            and dp_m.group(1).startswith('02010c00')):  # PCI device path
        h = digest_m.group(1)
        hashes[h] = {'size': None, 'events': []}

# deduplicate (same ROM loaded on multiple ports has the same hash)
print(json.dumps(list(hashes.keys()), indent=2))
```

The device path discriminator is the first 4 bytes of the EFI device path:
- `02 01` (type=Hardware, sub=PCI) → **PCI option ROM** → must be in db
- `01 03` + `04 06` (ACPI + Firmware Volume File) → internal FV driver → **not checked by SB**, do not need to enroll

> **Key insight**: even with SB disabled, the TPM log faithfully records which images were loaded and from where. You can enumerate the complete required hash set from a SB-off boot.

### Verify after a SB-on boot

After enabling SB, the TPM event log will include `EV_EFI_VARIABLE_AUTHORITY` events in PCR7 for every db entry that was matched. The number of these events must equal the number of distinct PCI option ROMs loaded, plus 1 for the bootloader cert. Any enrolled db entry that never appears in PCR7 is unnecessary.

```sh
grep -c 'EV_EFI_VARIABLE_AUTHORITY' tpm-eventlog-sb-on.txt
```

---

## Step 3 — Enroll the signing cert into db

Use the iDRAC Redfish `SecureBootDatabases/db/Certificates` endpoint.

```sh
CERT_PEM=$(cat db-gl.crt)

curl -sk -u "$BMC_USER:$BMC_PASS" -X POST \
  -H "Content-Type: application/json" \
  -d "{\"CertificateString\": $(python3 -c "import json,sys; print(json.dumps(open('db-gl.crt').read()))"), \"CertificateType\": \"PEM\"}" \
  "$SB/SecureBootDatabases/db/Certificates"
```

Expected response: `IDRAC.2.16.SYS430` (operation successful, reboot required).

---

## Step 4 — Enroll the option ROM hashes into db

Use the `SecureBootDatabases/db/Signatures` endpoint. Note the required field names for Dell iDRAC:

- `SignatureTypeRegistry`: must be `"UEFI"`
- `SignatureType`: `"EFI_CERT_SHA256_GUID"`
- `SignatureOwner`: any valid GUID; use all-zeros for hashes with no specific owner
- `SignatureString`: the 64-character hex SHA-256 digest (no `0x` prefix)

```python
import subprocess, json, os, time

BMC_USER = os.environ['BMC_USER']
BMC_PASS = os.environ['BMC_PASS']
IDRAC    = os.environ['IDRAC']
SIG_URL  = f"{IDRAC}/redfish/v1/Systems/System.Embedded.1/SecureBoot/SecureBootDatabases/db/Signatures"

hashes = [
    "b1ee3fa0e98fadd50e6457ef739f018580ab6e9ed9afa161ed0ff8222ae7c287",
    # ... add all hashes from Step 2
]

for h in hashes:
    body = json.dumps({
        "SignatureTypeRegistry": "UEFI",
        "SignatureType": "EFI_CERT_SHA256_GUID",
        "SignatureOwner": "00000000-0000-0000-0000-000000000000",
        "SignatureString": h,
    })
    r = subprocess.run(
        ["curl", "-sk", "-u", f"{BMC_USER}:{BMC_PASS}", "-m", "30",
         "-X", "POST", "-H", "Content-Type: application/json",
         "-d", body, SIG_URL],
        capture_output=True, text=True)
    resp = json.loads(r.stdout)
    msgs = [x.get("MessageId") for x in resp.get("@Message.ExtendedInfo", [])]
    ok = any("SYS430" in m for m in msgs)
    print(f"  {'OK' if ok else 'FAIL'}  {h[:16]}...  {msgs}")
    time.sleep(0.5)
```

---

## Step 5 — Enable Secure Boot and reboot

```sh
# Stage the BIOS setting
curl -sk -u "$BMC_USER:$BMC_PASS" -X PATCH \
  -H "Content-Type: application/json" \
  -d '{"Attributes": {"SecureBoot": "Enabled"}}' \
  "$SYS/Bios/Settings" \
  | python3 -c "import json,sys; [print(x['MessageId']) for x in json.load(sys.stdin).get('@Message.ExtendedInfo',[])]"

# Reboot to apply
curl -sk -u "$BMC_USER:$BMC_PASS" -X POST \
  -H "Content-Type: application/json" \
  -d '{"ResetType": "GracefulRestart"}' \
  "$SYS/Actions/ComputerSystem.Reset"
```

The BIOS setting change (`SecureBoot=Enabled`) only takes effect on reboot; the cert/hash enrollments staged earlier are committed at the same time.

---

## Step 6 — Verify

### Confirm SB is enforcing

```sh
# From OS — byte at offset 4 should be 0x01
od -A x -t x1z /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c
# Expected: 06 00 00 00 01
```

### Confirm db contents

```python
import struct, subprocess

raw = open('/sys/firmware/efi/efivars/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f', 'rb').read()
d = raw[4:]  # skip 4-byte EFI variable attributes
off = 0
certs, hashes = [], []

while off + 28 <= len(d):
    g = d[off:off+16]
    lsz, hsz, ssz = struct.unpack('<III', d[off+16:off+28])
    if lsz == 0:
        break
    body = d[off+28+hsz:off+lsz]
    if g == bytes.fromhex('a159c0a5e494a74a87b5ab155c2bf072'):  # EFI_CERT_X509_GUID
        for i in range(0, len(body), 16+ssz):
            der = body[i+16:i+16+ssz]
            open('/tmp/c.der', 'wb').write(der)
            subj = subprocess.run(
                ['openssl','x509','-inform','DER','-in','/tmp/c.der','-noout','-subject'],
                capture_output=True, text=True).stdout.strip()
            certs.append(subj)
    else:                                                        # EFI_CERT_SHA256_GUID
        for i in range(0, len(body), 16+ssz):
            hashes.append(body[i+16:i+16+ssz].hex())
    off += lsz

print(f"{len(certs)} cert(s), {len(hashes)} hash(es)")
for c in certs:
    print(f"  {c}")
```

### Confirm PCR7 authority events

```sh
sudo tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements > tpm-eventlog-sb-on.txt
grep -c 'EV_EFI_VARIABLE_AUTHORITY' tpm-eventlog-sb-on.txt
```

The count should equal: `(number of distinct PCI option ROM hashes) + 1` (for the bootloader cert). Every `EV_EFI_VARIABLE_AUTHORITY` event maps to a specific db entry that was matched; any enrolled entry that never appears here is unnecessary.

---

## Resetting the db (starting over)

If the db needs to be rebuilt from scratch — e.g. to remove previously enrolled entries — use the `DeleteAllKeys` reset. This wipes **only db**, leaving PK, KEK, and dbx intact.

```sh
curl -sk -u "$BMC_USER:$BMC_PASS" -X POST \
  -H "Content-Type: application/json" \
  -d '{"ResetKeysType": "DeleteAllKeys"}' \
  "$SB/SecureBootDatabases/db/Actions/SecureBootDatabase.ResetKeys"
```

Then re-enroll from Step 3.

---

## Known iDRAC Redfish quirks

| Issue | Detail |
|---|---|
| `db/Certificates` returns `count: 0` | After a reboot the iDRAC Certificates endpoint doesn't surface NVRAM-resident certs enrolled in prior sessions. The certs are present and active; the endpoint is buggy. Verify via OS efivar instead. |
| `db/Signatures` also returns `count: 0` | Same bug. |
| Slot IDs change after reboot | `CustSecbootpolicy.N` slot numbers are reassigned. Don't rely on slot IDs for targeted deletion; use `DeleteAllKeys` and re-enroll instead. |
| `SignatureData` vs `SignatureString` | Posting hashes to `db/Signatures` requires `SignatureString` (not `SignatureData`) when `SignatureTypeRegistry: UEFI` is set. Without `SignatureTypeRegistry` the call returns HTTP 400. |
| Pending job conflict | If a BIOS settings job is already queued, a second PATCH returns an error. Clear the pending job via the iDRAC Jobs endpoint before retrying. |
| SB blocks OS efivar writes | With SB enforcement active, direct writes to `/sys/firmware/efi/efivars/db-*` are rejected by the kernel. All db changes must go through Redfish or a signed `.auth` file. |

---

## EFI_SIGNATURE_LIST format reference

The db efivar on disk is 4 bytes of EFI variable attributes followed by one or more `EFI_SIGNATURE_LIST` structures:

```
[4 bytes]  EFI variable attributes  (e.g. 0x27 = NV+BS+RT+AT)
[repeated] EFI_SIGNATURE_LIST:
  SignatureType    GUID  16 bytes
  SignatureListSize     uint32   (total size of this list including header)
  SignatureHeaderSize  uint32   (usually 0)
  SignatureSize        uint32   (size of each entry: 16-byte owner GUID + payload)
  [repeated] EFI_SIGNATURE_DATA:
    SignatureOwner  GUID  16 bytes
    SignatureData         SignatureSize-16 bytes  (DER cert or SHA-256 hash)
```

Relevant GUIDs (bytes in little-endian order as they appear on disk):

| Type | GUID bytes (hex) |
|---|---|
| `EFI_CERT_X509_GUID` | `a1 59 c0 a5 e4 94 a7 4a 87 b5 ab 15 5c 2b f0 72` |
| `EFI_CERT_SHA256_GUID` | `26 16 c4 c1 4c 50 92 40 ac a9 41 f9 36 93 43 28` |
| db efivar GUID | `cb b2 19 d7 3a 3d 96 45 a3 bc da d0 0e 67 65 6f` |

---

## PCR7 authority event computation

When the firmware authorises a binary via db, it extends PCR7 with the SHA-256 of the following structure (`EFI_VARIABLE_DATA`):

```
VariableGuid        16 bytes  (db efivar GUID, little-endian)
UnicodeNameLength    8 bytes  uint64  (number of UTF-16 chars, e.g. 2 for "db")
VariableDataLength   8 bytes  uint64  (length of the matched EFI_SIGNATURE_DATA)
UnicodeName          N*2 bytes  ("db" = 64 00 62 00)
VariableData         M bytes   (EFI_SIGNATURE_DATA: owner GUID + cert or hash)
```

To verify that a specific db entry was used during boot, compute:

```python
import hashlib, struct

DB_VAR_GUID = bytes.fromhex('cbb219d73a3d9645a3bcdad00e67656f')

def pcr7_auth_digest(sig_data: bytes) -> str:
    name = b'd\x00b\x00'
    event_data = (DB_VAR_GUID
                  + struct.pack('<Q', 2)               # len("db") in chars
                  + struct.pack('<Q', len(sig_data))
                  + name
                  + sig_data)
    return hashlib.sha256(event_data).hexdigest()

# For a hash entry (owner = zero GUID):
h = bytes.fromhex("b1ee3fa0e98fadd50e6457ef739f018580ab6e9ed9afa161ed0ff8222ae7c287")
sig_data = b'\x00' * 16 + h
print(pcr7_auth_digest(sig_data))
```

---

## HPE (iLO)

Tested on: **HPE ProLiant DL380 Gen11**, BIOS U54 v2.84, iLO 6.

### Key differences from Dell

| | Dell iDRAC | HPE iLO |
|---|---|---|
| System path | `/redfish/v1/Systems/System.Embedded.1` | `/redfish/v1/Systems/1` |
| All SB changes | Immediate or next-job | **Always deferred** — applied on next reboot |
| PK enrollment auth | Basic auth sufficient | **Session token required** — Basic auth returns 401 |
| Factory cert store | No separate default store | Read-only `dbDefault` (10 certs) exists but is NOT restored by the top-level `DeleteAllKeys` |
| Correct wipe action | `db/Actions/SecureBootDatabase.ResetKeys` | **Top-level** `SecureBoot/Actions/SecureBoot.ResetKeys` with `DeleteAllKeys` |
| Hash enrollment fields | `SignatureTypeRegistry`, `SignatureType`, `SignatureOwner`, `SignatureString` | `SignatureType`, `SignatureString` only |
| SB enable PATCH | `Bios/Settings` → `{"Attributes": {"SecureBoot": "Enabled"}}` | `SecureBoot` resource → `{"SecureBootEnable": true}` |
| PCR7 event type | `0xe0000003` (`EV_EFI_VARIABLE_AUTHORITY`) | `0x800000e0` (HPE variant, same semantics) |
| Custom SB policy | BIOS attribute `SecureBootPolicy: Custom` removes factory db | No equivalent attribute — use top-level `DeleteAllKeys` instead |
| Addon EFIs (systemd-boot) | N/A | Must be signed; unsigned addons silently skipped when SB on |

### The `dbDefault` store

HPE iLO exposes a read-only `dbDefault` endpoint that holds 10 factory certs (MS, HPE, VMware). After `ResetAllKeysToDefault` these are copied into the active `db`.

`dbDefault` is **not** restored by `DeleteAllKeys` — that action genuinely empties the stores. The catch is _which_ `DeleteAllKeys` you call:

- `POST .../SecureBootDatabases/db/Actions/SecureBootDatabase.ResetKeys {"ResetKeysType": "DeleteAllKeys"}` — wipes only db, but iLO **repopulates it from `dbDefault` on the next reboot**.
- `POST .../SecureBoot/Actions/SecureBoot.ResetKeys {"ResetKeysType": "DeleteAllKeys"}` — wipes PK + KEK + db + dbx. After rebooting, **all four stores are truly empty**. Use this one.

### HPE SB setup environment

```sh
export N9_BMC_USER="$(kubectl get bmcsecret <node> -o jsonpath='{.data.username}' | base64 -d)"
export N9_BMC_PASS="$(kubectl get bmcsecret <node> -o jsonpath='{.data.password}' | base64 -d)"
export N9_IDRAC="https://<ilo-ip>"
export N9_SYS="$N9_IDRAC/redfish/v1/Systems/1"
```

### HPE Step 1 — Wipe all SB stores

Resets the server to UEFI Setup Mode (no PK → no SB enforcement).

```sh
# Wipe PK + KEK + db + dbx
curl -sk -u "$N9_BMC_USER:$N9_BMC_PASS" -X POST \
  -H "Content-Type: application/json" \
  -d '{"ResetKeysType": "DeleteAllKeys"}' \
  "$N9_SYS/SecureBoot/Actions/SecureBoot.ResetKeys"

# Reboot to apply — all HPE SB changes are deferred
curl -sk -u "$N9_BMC_USER:$N9_BMC_PASS" -X POST \
  -H "Content-Type: application/json" \
  -d '{"ResetType": "GracefulRestart"}' \
  "$N9_SYS/Actions/ComputerSystem.Reset"
```

After the reboot, verify all stores are empty:

```sh
for store in PK KEK db; do
  curl -sk -u "$N9_BMC_USER:$N9_BMC_PASS" \
    "$N9_SYS/SecureBoot/SecureBootDatabases/$store/Certificates" | \
    python3 -c "import sys,json; d=json.load(sys.stdin); print('$store certs:', d.get('Members@odata.count',0))"
done
# Expected: PK certs: 0 / KEK certs: 0 / db certs: 0
```

### HPE Step 2 — Determine option ROM hashes

Same as the Dell procedure (Step 2 above). Boot with SB disabled, capture the TPM event log, extract hashes of PCI device-path option ROMs.

On HPE, reading the TPM event log requires root:

```sh
sudo cat /sys/kernel/security/tpm0/binary_bios_measurements > tpm-eventlog-sb-off.bin
```

### HPE Step 3 — Sign all EFI binaries

HPE systemd-boot reads addon EFIs from `/efi/loader/addons/`. With SB on, **unsigned addons are silently skipped** — no OS-visible error, but any kernel parameters they carry are not applied. Sign them alongside the main bootloader and UKI:

```sh
for efi in BOOTX64.EFI uki.efi addons/*.addon.efi; do
  sbsign --key db-gl.key --cert db-gl.crt --output "signed/$efi" "$efi"
done
```

### HPE Step 4 — Enroll PK + KEK + db cert + oprom hashes

With PK=0 (Setup Mode) all stores are writable. The script below handles the iLO session-token requirement:

```python
#!/usr/bin/env python3
"""
Enroll db-gl cert into PK, KEK, and db, plus N oprom hashes into db.
Run after top-level DeleteAllKeys + reboot (Setup Mode: PK=0, KEK=0, db=0).
"""
import json, os, urllib.request, urllib.error, ssl

BMC_USER = os.environ["N9_BMC_USER"]
BMC_PASS = os.environ["N9_BMC_PASS"]
BMC_URL  = os.environ.get("N9_IDRAC", "https://<ilo-ip>")
SB_BASE  = f"{BMC_URL}/redfish/v1/Systems/1/SecureBoot/SecureBootDatabases"

CERT_FILE   = "db-gl.crt"
HASHES_FILE = "oprom-hashes.json"  # [{"sha256": "<64 hex chars>"}, ...]

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# Session token — Basic auth is rejected (401) for PK writes on HPE iLO
_r = urllib.request.Request(
    f"{BMC_URL}/redfish/v1/SessionService/Sessions",
    data=json.dumps({"UserName": BMC_USER, "Password": BMC_PASS}).encode(),
    method="POST",
    headers={"Content-Type": "application/json"},
)
with urllib.request.urlopen(_r, context=ctx) as _resp:
    TOKEN = _resp.headers.get("X-Auth-Token")

def req(method, url, body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method, headers={
        "X-Auth-Token": TOKEN,
        "Content-Type": "application/json",
    })
    try:
        with urllib.request.urlopen(r, context=ctx) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b'{}')

with open(CERT_FILE) as f:
    cert_pem = f.read()

for store in ("PK", "KEK", "db"):
    status, body = req("POST", f"{SB_BASE}/{store}/Certificates", {
        "CertificateString": cert_pem,
        "CertificateType": "PEM",
    })
    msg = body.get("error", {}).get("@Message.ExtendedInfo", [{}])[0].get("MessageId", "")
    print(f"{store}: status={status} {msg}")

for entry in json.load(open(HASHES_FILE)):
    h = entry["sha256"]
    status, body = req("POST", f"{SB_BASE}/db/Signatures", {
        "SignatureType": "EFI_CERT_SHA256_GUID",
        "SignatureString": h,
    })
    msg = body.get("error", {}).get("@Message.ExtendedInfo", [{}])[0].get("MessageId", "")
    print(f"hash {h[:16]}...: status={status} {msg}")

print("Done. Enable SB and reboot.")
```

Expected: each store returns `status=202` with a task ID.

### HPE Step 5 — Enable Secure Boot and reboot

```sh
# Stage SB enable
curl -sk -u "$N9_BMC_USER:$N9_BMC_PASS" -X PATCH \
  -H "Content-Type: application/json" \
  -d '{"SecureBootEnable": true}' \
  "$N9_SYS/SecureBoot"

# Single reboot applies all staged tasks in order
curl -sk -u "$N9_BMC_USER:$N9_BMC_PASS" -X POST \
  -H "Content-Type: application/json" \
  -d '{"ResetType": "GracefulRestart"}' \
  "$N9_SYS/Actions/ComputerSystem.Reset"
```

> **Task ordering**: all HPE SB operations are deferred to the next reboot. Do not reboot between the enrollment calls and the SB enable PATCH — they must all queue before the single reboot that applies them.

### HPE Step 6 — Verify

**Check SB state via Redfish:**

```sh
curl -sk -u "$N9_BMC_USER:$N9_BMC_PASS" "$N9_SYS/SecureBoot" | \
  python3 -c "import sys,json; d=json.load(sys.stdin);
    print('Mode:', d['SecureBootMode'],
          'Enable:', d['SecureBootEnable'],
          'CurrentBoot:', d['SecureBootCurrentBoot'])"
# Expected: Mode: UserMode  Enable: True  CurrentBoot: Enabled

for store in PK KEK db; do
  curl -sk -u "$N9_BMC_USER:$N9_BMC_PASS" \
    "$N9_SYS/SecureBoot/SecureBootDatabases/$store/Certificates" | \
    python3 -c "import sys,json; d=json.load(sys.stdin); print('$store certs:', d.get('Members@odata.count',0))"
done
curl -sk -u "$N9_BMC_USER:$N9_BMC_PASS" \
  "$N9_SYS/SecureBoot/SecureBootDatabases/db/Signatures" | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print('db sigs:', d.get('Members@odata.count',0))"
# Expected: PK certs: 1 / KEK certs: 1 / db certs: 1 / db sigs: N
```

**Check SB active in OS:**

```sh
od -An -tx1 /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c
# Expected: 06 00 00 00 01
```

**Check PCR7 authority events:**

HPE uses event type `0x800000e0` for `EV_EFI_VARIABLE_AUTHORITY` (Dell uses `0xe0000003`). The TCG2 log on HPE Gen11 uses SHA256 + SHA384. Parse with:

```python
import struct, hashlib, json

data = open("tpm-eventlog-sb-on.bin", "rb").read()

# First event: TCG1-format spec ID — skip it
first_evt_end = 32 + struct.unpack_from("<I", data, 28)[0]

# HPE ProLiant Gen11: SHA256(alg=0x0b, size=32) + SHA384(alg=0x0c, size=48)
alg_sizes = {0x0b: 32, 0x0c: 48}

KNOWN_CERTS = {
    "<sha256-of-your-cert-DER>": "your-cert-name",
}
known_hashes = {h["sha256"]: f"oprom-{i+1}"
                for i, h in enumerate(json.load(open("oprom-hashes.json")))}

EV_EFI_VAR_AUTH = {0xe0000003, 0x800000e0}

pos = first_evt_end
while pos + 16 < len(data):
    pcr, etype = struct.unpack_from("<II", data, pos); pos += 8
    dc = struct.unpack_from("<I", data, pos)[0]; pos += 4
    for _ in range(dc):
        alg = struct.unpack_from("<H", data, pos)[0]; pos += 2
        pos += alg_sizes.get(alg, 32)
    esz = struct.unpack_from("<I", data, pos)[0]; pos += 4
    evt = data[pos:pos+esz]; pos += esz

    if pcr != 7 or etype not in EV_EFI_VAR_AUTH or len(evt) < 32:
        continue
    name_len, data_len = struct.unpack_from("<QQ", evt, 16)
    name = evt[32:32 + name_len*2].decode("utf-16-le", errors="replace")
    sig = evt[32 + name_len*2:32 + name_len*2 + data_len]
    payload = sig[16:]
    sha = hashlib.sha256(payload).hexdigest()
    label = (KNOWN_CERTS.get(sha)
             or known_hashes.get(payload.hex())
             or ("SHA256 hash: " + payload.hex() if len(payload) == 32
                 else f"cert sha256={sha}"))
    print(f"PCR7 AUTH  var={name}  → {label}")
```

Expected output — all entries are your own, no MS or HPE certs:

```
PCR7 AUTH  var=db  → oprom-1
PCR7 AUTH  var=db  → oprom-2
PCR7 AUTH  var=db  → oprom-3
PCR7 AUTH  var=db  → oprom-4
PCR7 AUTH  var=db  → your-cert-name
```

### Known HPE iLO Redfish quirks

| Issue | Detail |
|---|---|
| All SB changes are deferred | Every cert enroll, hash enroll, and SB enable PATCH returns `iLO.2.37.SystemResetRequired` and only takes effect on reboot. Never reboot mid-sequence. |
| PK enrollment requires session token | `POST .../PK/Certificates` returns `401 NoValidSession` with Basic auth. Obtain an `X-Auth-Token` first via `POST /redfish/v1/SessionService/Sessions`. |
| `db`-level `DeleteAllKeys` is overridden | `POST .../db/Actions/SecureBootDatabase.ResetKeys {"ResetKeysType": "DeleteAllKeys"}` empties db but iLO repopulates it from `dbDefault` on reboot. Use the top-level `POST .../SecureBoot/Actions/SecureBoot.ResetKeys {"ResetKeysType": "DeleteAllKeys"}` instead. |
| `dbDefault` always present | HPE ships 10 factory certs in a read-only `dbDefault` endpoint (MS, HPE, VMware). They are not used once you enroll your own keys via top-level `DeleteAllKeys` + re-enroll. They only become active if you call `ResetAllKeysToDefault`. |
| Mode shows `None` after full wipe | With PK=0 (Setup Mode), `SecureBootMode` is reported as `null` by iLO. This is normal. |
| `SecureBootEnable` staging consumed on first reboot | If you stage `SecureBootEnable: true` before PK is enrolled, the flag is consumed but SB cannot activate (no PK). Re-stage it after PK enrollment. |
| Addon EFIs silently skipped when unsigned | systemd-boot reads `/efi/loader/addons/*.addon.efi`. With SB on, unsigned addons log `Access denied` on the iLO console but boot continues — the kernel parameters they carry are **silently dropped**. Sign all addon EFIs with the same db cert. |
