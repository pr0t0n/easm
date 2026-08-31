---
skill_id: skill.bas.service_targeting
name: BAS Service Targeting
version: 1.0.0
category: bas
phase_ids:
- P02
status: approved
supported_target_types:
- ip_address
- cidr
risk_level: low
noise_level: low
requires_authorization: true
required_tools:
- nmap
evidence_required:
- port_scan_result
- service_capability_map
- skipped_target_reason
exit_criteria:
  minimum_tools_attempted: 1
  minimum_evidence_items: 1
  validator_required: true
allowed_execution_modes:
- safe_validation
- controlled_pentest
safety_rules:
  destructive_payloads_allowed: false
  scope_guard_required: true
source_report_ids: []
---

# Objective

Route BAS techniques only to hosts whose observed service fingerprint supports that technique.

# Mandatory Rule

Run `Port & Service Scanning` before any service-specific BAS technique. The scan result is the routing source of truth for that execution. A technique must not run against every active host only because the schedule target is a CIDR.

# Capability Matrix

| Capability | Required Observation | BAS Techniques |
|---|---|---|
| `web` | TCP 80, 443, 8000, 8001, 8008, 8080, 8081, 8443, 8888, 3000, 5000, 5601, 9000, or 9443 open | Web application scan, controlled exploit validation |
| `smb` | TCP 139 or 445 open | SMB enumeration, share discovery, safe credential checks, NTLM relay simulation |
| `dns` | TCP 53 open | DNS validation only |
| `kerberos` | TCP 88 or 464 open | Kerberoasting and Kerberos-specific identity validation |
| `ad_dc` | LDAP plus Kerberos observed, or Global Catalog TCP 3268/3269 observed | BloodHound collection, AD LDAP scouting, DC-specific validation |
| `vmware` | TCP 5480, 902, or 9443 open | vCenter/ESXi credential posture checks |

# Dispatch Contract

1. Expand CIDR targets into unit hosts for any technique with `required_ports` or `required_capabilities`.
2. Build host capabilities from the mandatory port scan result.
3. Dispatch only when the host satisfies every required capability and at least one required port.
4. Skip hosts with no completed fingerprint using `service_fingerprint_missing_per_port_scan`.
5. Skip hosts whose fingerprint lacks the capability using `capability_not_observed_per_port_scan`.
6. Preserve the skip reason in the BAS run output so the operator understands why a test did not execute.

# Examples

- BloodHound must run only on hosts classified as `ad_dc`, not on all active hosts.
- Web tests must run only on hosts with a web port.
- SMB tests must run only on hosts with SMB ports.
- DNS checks must run only on hosts where DNS was observed.
