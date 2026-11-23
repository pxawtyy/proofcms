# Seven lab-confirmed defects — triage outcome (2026-11-22)

A defensive classification review covered the seven checks whose flaws were
confirmed in an isolated lab but whose shipped probes remain version/surface
only. The full case fact sheet and packet were kept on the Desktop; the
conclusion is recorded here so the set is not re-triaged from scratch.

## Conclusion

No new externally observable separator was identified for any of the seven.
Each stays at its current disposition; the review's `confirmed with control`
verdicts are **lab-level** severity classifications, not claims of remote
detectability. The lab-to-production gap is the common blocker.

| Case | Lab-level classification | External reachability | Why it stays passive |
|---|---|---|---|
| CVE-2011-3416 | Integrity / authentication-boundary bypass | login form + identity-reflecting page | needs accepted credentials and an application-specific protected URL |
| CVE-2025-53772 | Integrity / deserialization | exposed handler URL | needs valid domain credentials and host filesystem read-back |
| CVE-2026-123007 | Availability | HTTP/2 over TLS, large response | definitive signal is an instrumented-build log; uninstrumented behavior not demonstrated |
| CVE-2026-40372 | Integrity / cryptographic bypass | none | local .NET self-test, no network service |
| CVE-2023-3824 | Boundary / validation anomaly | none | needs an application that loads an untrusted archive and lists it |
| CVE-2024-8929 | Confidentiality / memory over-read | none | needs control of the database service and persistent worker buffers |
| CVE-2024-8932 | Availability | none | needs 32-bit PHP and an unbounded input path |

## Control expectations

Fixed builds fail closed: reject malformed input or crafted headers, enforce
flow-control bounds, reject all-zero HMACs, reject invalid archive entries and
database field packets, and raise explicit length errors. None of those
rejections is visible to an unauthenticated HTTP client without the private
preconditions above.

## Evidence thresholds

A higher severity verdict would need unauthenticated reachability (cases 1-2),
non-crash memory corruption or secret disclosure from production buffers
(cases 3, 5-7), or remote payload injection into a DataProtection consumer
(case 4). A lower verdict would need proof that the affected path is
unreachable in production (64-bit-only estates, trusted-only database/archive
boundaries, or non-reproducible behavior on uninstrumented builds).

## Related

CVE-2026-88092 was the one case in this category that did graduate: its oracle
(a counter incremented by a smuggled request) was readable over HTTP with
application-specific named paths, so it now ships as an aggressive probe.
