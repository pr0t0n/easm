# Finding Adjudication and Revalidation Wires

Status: end-to-end implementation complete

## End-to-end closure

The executable return circuit is:

1. P21 persists the exact finding, endpoint, method, parameter, object fixtures and identity keys in a wire.
2. The work queue passes the complete wire contract to local or MCP executors.
3. Business-logic comparison resolves the named identities, replays the same observed object and makes no request when an exact prerequisite is absent.
4. The tool result becomes a finding-bound baseline/attempt evidence pair.
5. One shared terminal hook consumes local and asynchronously-polled results.
6. The deterministic gate re-adjudicates, projects the verdict to the finding/coverage, recalculates attack paths and records outcome learning.
7. P22 exposes an explicit answer contract for validity, false-positive cause, missing evidence, executed work, recommendation, PoC, exploit URLs, attack path, CVE and CVSS.

Positive cross-identity proof requires the bound owner/control request to
succeed and the bound secondary identity to obtain the same resource. Explicit
negative proof requires the owner/control request to succeed and the secondary
identity to be denied. Failure, timeout, missing identity or an ambiguous
response remains inconclusive.

## Invariants

- P20 correlates evidence into candidate/proven attack paths.
- P21 adjudicates findings and executes bounded revalidation wires.
- P22 reports persisted decisions; it never schedules offensive work.
- LLM output is advisory. Only the deterministic evidence gate may confirm or refute.
- Missing information, timeout and tool failure are inconclusive, never false-positive proof.
- Every re-test is bound to the originating finding, target, endpoint, parameter, identities and evidence.
- CVE/CVSS/EPSS/KEV/exploit facts are source-attributed; unavailable lookups remain `unknown`.

## Phase 1 — Foundation

Persist:

- `FindingAdjudication`: redacted dossier, LLM proposal, deterministic verdict, cause, confidence and provenance.
- `ValidationWire`: the return edge from evidence gap to exact P21 test and back.
- `FindingIntelligenceSnapshot`: source-attributed CVE applicability, CVSS, EPSS, KEV and exploit references.

The wire includes:

- finding/adjudication/parent wire/work item IDs;
- source artifact and discovered endpoint IDs;
- exact target and parameter refs;
- primary and secondary identity refs;
- closed `action_id`, tool/profile and expected positive/negative signals;
- input bindings, scope/policy decision, result summary, attempt budget and idempotency key.

## Phase 2 — Executable loop

1. Build a compact dossier from finding, experiment, proof pack, artifacts, contradictions, identities, intelligence and historical calibration.
2. Run deterministic promotion checks first.
3. If evidence remains ambiguous, ask the LLM for a strict JSON proposal.
4. Validate evidence IDs, exact target binding and closed action catalog.
5. Materialize an allowed action as a P21 `ScanWorkItem` carrying `validation_wire_id`.
6. On terminal work-item status, classify the real output, complete the wire and rebuild the dossier.
7. Re-adjudicate until terminal verdict, missing human input or budget exhaustion.
8. Recompute attack paths after every wire result.

Initial budgets are three adjudication cycles and three wires per finding. The existing executor retry budget remains independent.

Closed actions:

- collect full artifact;
- repeat same validator;
- collect baseline or negative control;
- run a family validator;
- compare two identities or two objects;
- verify product version/configuration/CVE applicability;
- refresh CVE or public exploit intelligence;
- rebuild attack path;
- request human input.

The LLM cannot author URLs, commands, payloads, credentials, CVEs, exploit references or final CVSS scores.

## Phase 3 — Closure

- NVD/CISA KEV, FIRST EPSS and ExploitDB results are persisted as snapshots.
- Public exploit availability changes risk priority, not CVSS.
- The report contract includes adjudication, missing evidence, contradictions, wires, results and intelligence.
- The HTML P22 report includes a P21 adjudication/wire section.
- APIs expose adjudication history and an audited manual re-adjudication trigger.
- Scan deletion removes wire/intelligence/adjudication children before their FK parents.

## Terminal semantics

- `confirmed`: positive, target-grounded, reproducible evidence satisfies the family contract.
- `refuted`: an explicit negative observation was produced by a functioning test with satisfied preconditions.
- `inconclusive`: evidence is absent, ambiguous, unstable or execution failed.
- `blocked`: scope, authorization, identity or another required input is missing.
- `not_applicable`: verified product/version/configuration is outside the affected condition.
- `invalid_evidence`: parser, truncation or target binding makes the evidence unusable.
- `needs_human_review`: the bounded autonomous loop cannot safely finish.

## Acceptance gates

- An LLM target different from the dossier is rejected.
- An LLM evidence ID absent from the dossier is rejected.
- A legacy P21 PoC is wrapped in an idempotent exact-target wire.
- Timeout/failure cannot refute.
- Missing information cannot set false positive.
- Out-of-scope targets cannot materialize wires.
- Attack paths are recomputed only from persisted evidence states.
- P22 only consumes persisted adjudication results.
