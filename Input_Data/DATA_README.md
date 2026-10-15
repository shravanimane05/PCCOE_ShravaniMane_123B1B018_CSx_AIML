# AutoTARA AI — Dataset Documentation & Synthetic Origin Statement

## 1. Synthetic Data Statement
All data files in this directory are **100% synthetically generated** for educational and research evaluation purposes within the AutoTARA AI project.
- **No proprietary OEM, Tier-1 supplier, or real-world vehicle telematics data** is included or referenced.
- Standards such as ISO/SAE 21434 and UNECE R155 are referenced solely by name as inspiration for methodology and structure; no copyrighted standard text has been reproduced.
- Threat patterns represent generic security design patterns derived from public cybersecurity literature and automotive security research concepts.

---

## 2. Directory Structure

```
Input_Data/
├── architecture/
│   ├── baseline_v1.json                     # Baseline fictional connected-vehicle architecture (v1.0)
│   └── baseline_v2_bluetooth_adapter.json   # Extended architecture with aftermarket BT adapter (v2.0: COMP-10, IF-11, TB-05)
└── knowledge_base/
    ├── threat_patterns.json                 # 30 synthetic threat patterns with stable IDs (TP-001..TP-030)
    ├── controls.json                        # 32 security controls (CTRL-001..CTRL-032)
    ├── requirements.json                    # 31 cybersecurity requirement templates (REQ-001..REQ-031)
    ├── verification_tests.json              # 32 verification test cases (TEST-001..TEST-032)
    └── prototype_rubric.json                # Impact (1-5), Feasibility (1-5), and 4 risk bands
```

---

## 3. Field-Level Schema Tables

### 3.1 `threat_patterns.json` (Array of Threat Pattern Objects)

| Field | Type | Required | Description | Example |
|---|---|---|---|---|
| `id` | string | Yes | Unique stable threat pattern ID (`TP-001` .. `TP-030`) | `"TP-001"` |
| `title` | string | Yes | Short descriptive title of the threat | `"Token and API Authorization Bypass"` |
| `description` | string | Yes | Detailed narrative of the threat mechanism | `"An attacker obtains or forges a mobile-app access token..."` |
| `applicable_asset_types` | string[] | Yes | Target asset type tags matching architecture asset types | `["mobile_app", "cloud_api"]` |
| `interface_types` | string[] | Yes | Protocols and communication media involved | `["http_rest", "tls"]` |
| `trust_boundary` | string | Yes | Trust boundary crossed (`TB-01` .. `TB-05`) | `"TB-01"` |
| `attack_surface` | string | Yes | Specific exposed surface where attack initiates | `"Cloud API endpoint exposed to mobile clients"` |
| `threat_scenario` | string | Yes | Step-by-step narrative of the attack execution | `"1. Intercept token. 2. Replay against API..."` |
| `damage_scenario` | string | Yes | Consequence narrative detailing vehicle/user harm | `"Unauthorized vehicle control, privacy violation..."` |
| `stride_category` | string | Yes | STRIDE classification (`Spoofing`, `Tampering`, etc.) | `"Spoofing"` |
| `suggested_control_ids` | string[] | Yes | References to mitigations in `controls.json` | `["CTRL-002", "CTRL-015", "CTRL-016"]` |
| `owner` | string | Yes | Engineering or security team responsible | `"Cloud Security Team"` |
| `version` | string | Yes | Threat pattern specification version | `"1.0"` |
| `last_review_date` | string (ISO) | Yes | Date pattern was last reviewed (`YYYY-MM-DD`) | `"2026-09-15"` |
| `next_review_date` | string (ISO) | Yes | Date pattern review is due (`YYYY-MM-DD`) | `"2026-12-15"` |
| `source_note` | string | Yes | Origin note and deliberate hard negative documentation | `"Authored synthetic pattern. DELIBERATE HARD NEGATIVE..."` |
| `keywords` | string[] | Yes | Indexing keywords for lexical retrieval | `["token", "oauth", "authorization", "session"]` |

### 3.2 `controls.json` (Array of Security Control Objects)

| Field | Type | Required | Description | Example |
|---|---|---|---|---|
| `id` | string | Yes | Unique stable control ID (`CTRL-001` .. `CTRL-032`) | `"CTRL-001"` |
| `name` | string | Yes | Name of the security control | `"Mutual TLS Authentication"` |
| `description` | string | Yes | Technical specification of the control | `"Enforce mutual TLS (mTLS) with client certificates..."` |
| `type` | string | Yes | Control classification (`preventive`, `detective`, `corrective`) | `"preventive"` |
| `applicable_asset_types` | string[] | Yes | Asset types where this control applies | `["cloud_api", "tcu"]` |

*Note: In accordance with single-source-of-truth linking, reverse links to requirements are derived in code from `requirements.json`.*

### 3.3 `requirements.json` (Array of Requirement Template Objects)

| Field | Type | Required | Description | Example |
|---|---|---|---|---|
| `id` | string | Yes | Unique requirement ID (`REQ-001` .. `REQ-031`) | `"REQ-001"` |
| `title` | string | Yes | Short requirement title | `"API Mutual and Token-Based Authentication"` |
| `text_template` | string | Yes | Formal requirement string with `{asset}` placeholder | `"The {asset} shall enforce mutual TLS..."` |
| `linked_control_ids` | string[] | Yes | Forward links to `controls.json` satisfying this requirement | `["CTRL-001", "CTRL-002"]` |
| `category` | string | Yes | Security objective category | `"Authentication"` |

### 3.4 `verification_tests.json` (Array of Test Case Objects)

| Field | Type | Required | Description | Example |
|---|---|---|---|---|
| `id` | string | Yes | Unique test case ID (`TEST-001` .. `TEST-032`) | `"TEST-001"` |
| `title` | string | Yes | Test case title | `"Verify Mutual TLS Handshake Enforcement"` |
| `objective` | string | Yes | Verification objective statement | `"Confirm that the cloud API rejects connections without..."` |
| `steps` | string[] | Yes | Ordered procedural test execution steps | `["1. Attempt connection without cert...", "2. ..."]` |
| `expected_result` | string | Yes | Pass criteria and observable outcome | `"Steps 1 and 2 are rejected with TLS handshake failure..."` |
| `linked_requirement_ids` | string[] | Yes | Forward links to `requirements.json` verified by this test | `["REQ-001"]` |

### 3.5 `prototype_rubric.json` (Scoring and Rubric Definition)

| Field | Type | Description |
|---|---|---|
| `impact_scale` | object[] | 5 levels (`level`: 1..5, `label`: Negligible..Critical, `description`) |
| `attack_feasibility_scale` | object[] | 5 levels (`level`: 1..5, `label`: Very Low..Very High, `description`) |
| `risk_bands` | object[] | 4 bands: Low (1-5), Medium (6-12), High (13-19), Critical (20-25) |
| `disclaimer` | string | Explicit notice of educational/prototype model origin |

### 3.6 Architecture Baseline Schemas (`baseline_v1.json` & `baseline_v2_bluetooth_adapter.json`)

| Section | Elements | Key Fields per Element |
|---|---|---|
| `components` | 9 (v1) / 10 (v2) | `id` (`COMP-01`..), `name`, `type`, `trust_zone_id`, `description` |
| `interfaces` | 10 (v1) / 11 (v2) | `id` (`IF-01`..), `name`, `source_component_id`, `target_component_id`, `protocol`, `trust_boundary_id`, `description` |
| `data_flows` | 10 (v1 & v2) | `id` (`DF-01`..), `name`, `interface_id`, `data_type`, `direction`, `description` |
| `trust_zones` | 5 (v1 & v2) | `id` (`TZ-01`..`TZ-05`), `name`, `trust_level` (`untrusted`, `semi-trusted`, `trusted`, `highly-trusted`) |
| `trust_boundaries`| 4 (v1) / 5 (v2) | `id` (`TB-01`..`TB-05`), `name`, `from_zone_id`, `to_zone_id` |
| `assets` | 10 (v1 & v2) | `id` (`A-01`..`A-10`), `name`, `category` (`data` or `component`), `type`, `hosted_on`, `description` |

---

## 4. Single Source of Truth & Traceability Linking Contract

Forward relationships are declared explicitly in one direction:
1. **Threat Pattern → Controls**: `threat_patterns.json` defines `suggested_control_ids`.
2. **Requirement → Controls**: `requirements.json` defines `linked_control_ids`.
3. **Verification Test → Requirements**: `verification_tests.json` defines `linked_requirement_ids`.

Reverse relationships are strictly computed in code by `DataLoader.build_derived_traceability()`:
- `control_to_requirements`: `{CTRL-xxx: [REQ-yyy, ...]}`
- `requirement_to_tests`: `{REQ-yyy: [TEST-zzz, ...]}`
- `control_to_threats`: `{CTRL-xxx: [TP-aaa, ...]}`

---

## 5. Freshness Determination Rule & Exact 180-Day Overdue Boundary

Freshness status is computed deterministically from `next_review_date` relative to the anchor `reference_date` (`2026-10-13`):
Let `days_ahead = (next_review_date - reference_date).days`.

- **Current** (`days_ahead > 30`): Next review is strictly more than 30 days in the future. (**15 patterns**)
- **Review Due** (`-180 <= days_ahead <= 30`): Next review is due within 30 days ahead, or is overdue by up to and including **exactly 180 days**. (**10 patterns**)
- **Outdated** (`days_ahead < -180`): Next review is overdue by strictly more than 180 days (181+ days overdue). (**5 patterns**)

### Exact Boundary Behavior:
| Condition | `days_ahead` | Computed Status | Note |
|---|---|---|---|
| Review due 31 days ahead | `+31` | **Current** | Above 30-day ahead threshold |
| Review due 30 days ahead | `+30` | **Review Due** | Upper inclusive boundary for Review Due |
| Review due today | `0` | **Review Due** | Due now |
| Overdue by exactly 180 days | `-180` | **Review Due** | **Exact boundary condition**: Still Review Due |
| Overdue by 181 days | `-181` | **Outdated** | Strictly overdue >180 days transitions to Outdated |

---

## 6. Real Near-Duplicate Pairs & Hard Negatives

The knowledge base contains deliberate near-duplicate pairs (hard negatives) designed to test whether the retrieval engine can distinguish closely related threat concepts rather than matching solely on broad lexical keywords:

| Pattern A | Pattern B | Shared Context / Domain | What Separates Them (Distinguishing Factor) |
|---|---|---|---|
| **TP-024**<br>Insecure OTA Update Metadata Spoofing | **TP-002**<br>Malicious OTA Firmware Injection | OTA update channel (`TB-02`, `ota_firmware`) | **Payload vs Manifest:** `TP-002` injects modified or tampered binary firmware payloads. `TP-024` tampers only with manifest metadata (version numbers, target ECU IDs, routing flags) without modifying binary payloads. |
| **TP-024**<br>Insecure OTA Update Metadata Spoofing | **TP-009**<br>OTA Firmware Rollback Attack | OTA version manipulation (`TB-02`, `ota_firmware`) | **Valid Old Image vs Manifest Corruption:** `TP-009` forces installation of an authentic, signed older firmware binary to re-introduce patched vulnerabilities (anti-rollback bypass). `TP-024` tampers with metadata to misroute updates to wrong ECUs or suppress critical patch installations. |
| **TP-024**<br>Insecure OTA Update Metadata Spoofing | **TP-020**<br>OTA Server Infrastructure Compromise | OTA distribution ecosystem (`TB-02`, `ota_firmware`) | **Infrastructure vs Delivery Manifest:** `TP-020` represents root compromise of the cloud OTA build/signing server infrastructure itself. `TP-024` attacks transit manifest handling and metadata parsing on the vehicle/delivery channel without requiring server compromise. |
| **TP-026**<br>Insecure Credential Storage on Mobile Device | **TP-018**<br>Mobile App Tampering and Repackaging | Mobile companion app (`TB-01`, `COMP-01`) | **At-Rest Storage vs Binary Tampering:** `TP-018` decompiles, modifies code, and repackages an unauthorized app binary. `TP-026` targets an unmodified app storing plaintext tokens/keys in insecure local storage (world-readable shared preferences, unencrypted keychain). |
| **TP-029**<br>Compromised Cloud Admin Credential Abuse | **TP-020**<br>OTA Server Infrastructure Compromise | Cloud backend services (`TB-01`/`TB-02`, `COMP-02`/`COMP-03`) | **Administrative Management Plane vs Update Pipeline:** `TP-029` involves administrative credentials abuse across multi-tenant user portals and fleet command APIs. `TP-020` is targeted penetration of the firmware distribution and cryptographic signing pipeline. |
| **TP-029**<br>Compromised Cloud Admin Credential Abuse | **TP-001**<br>Token and API Authorization Bypass | Cloud API authorization (`TB-01`, `cloud_api`) | **Privilege Scope:** `TP-001` targets individual end-user OAuth access tokens to control single vehicle accounts. `TP-029` targets cloud tenant administrator credentials providing fleet-wide access and audit log alteration. |
| **TP-023**<br>Man-in-the-Middle on Cloud-to-TCU Channel | **TP-003**<br>Spoofed or Replayed Cloud-to-TCU Commands | Cloud-to-TCU cellular link (`TB-02`, `tcu`) | **Active MITM vs Passive Replay:** `TP-003` captures and replays previously authorized command messages without breaking encryption. `TP-023` uses active cellular interception (rogue base station / IMSI catcher) to perform TLS downgrade and live in-flight payload modification. |
| **TP-013**<br>Bluetooth Diagnostic Adapter Exploitation | **TP-030**<br>Weak Bluetooth Pairing Exploitation | Aftermarket Bluetooth OBD adapter (`TB-05`, `COMP-10`) | **Post-Connect Exploit vs Pairing Bypass:** `TP-030` attacks the initial Bluetooth pairing layer (Just Works mode, short PIN brute-force). `TP-013` exploits adapter firmware bugs, buffer overflows, or command execution flaws once wireless communication is established. |

---

## 7. Trust Boundaries and Architecture Change Scope

### 7.1 Trust Boundary Assignment Summary
- `TB-01` (Mobile to Cloud): 6 patterns (`TP-001`, `TP-008`, `TP-018`, `TP-019`, `TP-026`, `TP-029`)
- `TB-02` (Cloud to Vehicle): 10 patterns (`TP-002`, `TP-003`, `TP-006`, `TP-007`, `TP-009`, `TP-010`, `TP-020`, `TP-021`, `TP-022`, `TP-023`, `TP-024`)
- `TB-03` (TCU to In-Vehicle): 8 patterns (`TP-004`, `TP-011`, `TP-012`, `TP-015`, `TP-016`, `TP-017`, `TP-025`, `TP-028`)
- `TB-04` (Diagnostic to Gateway): 4 patterns (`TP-005`, `TP-014`, `TP-027`)
- `TB-05` (Bluetooth Adapter to Gateway): 2 patterns (`TP-013`, `TP-030`)

### 7.2 Handling of `TB-05` and Baseline v2
- `TB-05` is introduced **exclusively in `baseline_v2_bluetooth_adapter.json`** representing the wireless-to-wired boundary between the aftermarket Bluetooth diagnostic dongle (`COMP-10`) and the central gateway ECU (`COMP-05`).
- In `baseline_v1.json`, only `TB-01` through `TB-04` exist.
- Threats `TP-013` and `TP-030` specifically target this aftermarket Bluetooth boundary (`TB-05`). In baseline v1, these threats are dormant / unmapped because `COMP-10` does not exist. In baseline v2, they are triggered by the architecture diff reassessment.

### 7.3 Handling of `TP-014` (Wi-Fi Diagnostic Interface Abuse)
- `TP-014` is assigned to `TB-04` (Diagnostic to Gateway).
- In the baseline architecture, service-bay diagnostic equipment connects to the gateway across `TB-04`. `TP-014` models a workshop tester or external diagnostic device that provides a wireless Wi-Fi link (e.g., DoIP / ISO 13400 workshop tool), bridging external diagnostic testers to the vehicle gateway. Because the baseline vehicle does not have an on-board Wi-Fi hot spot, `TP-014` applies at `TB-04` specifically to external diagnostic tool connections.
