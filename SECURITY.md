# Security policy

## Supported version

Security fixes are applied to the latest `0.1.x` development line until a formal release policy is
published. Pin and scan the exact commit/image deployed; branches are not security attestations.

## Reporting a vulnerability

Do not open a public issue containing exploit details, credentials, tenant data or malicious files.
Use the repository host's private security-advisory channel or the deployment owner's documented
security contact. Include affected commit/version, impact, minimal reproduction, required privileges
and suggested remediation. Remove real secrets and personal data.

Do not test systems or data without explicit authorization. Avoid denial of service, persistence,
social engineering, data exfiltration and third-party provider abuse. The operator should acknowledge
a report within five business days, triage severity, coordinate a fix/embargo and credit the reporter
if requested.

## Deployment responsibility

The repository includes defense-in-depth defaults, not a production approval, penetration-test
certificate, or universal compliance certification. The reference production topology puts parsing
in a distinct no-general-egress service with no application data volume. The ingestion worker streams
one authenticated, size- and digest-bound input; the parser writes only to request-private temporary
storage and returns bounded encoded artifacts. Worker and parser do not share an exchange volume.

This separation reduces persistence and cross-job exposure but is not a hardware isolation boundary.
A compromised parser can still inspect its active request or craft hostile output. Keep independent
worker response validation, one-job parser capacity, resource limits, read-only roots, dropped
capabilities, enforced destination policy, private transport authentication/mTLS, current malware
scanning, and authorized malformed-media tests.

Before production, complete the environment-specific gates in
[the QA/VAPT report](docs/09-qa-vapt.md), including exact locks/digests, model/license review,
current malware scanning, parser sandbox and malformed-media validation, private authenticated
stores, TLS/egress controls, backups, DAST/load/adversarial tests, and an incident contact. Those
gates were not executed in the delivery workspace. Never send regulated or confidential content to
an unapproved model/search provider.

Local Windows OCR is an operating-system convenience, not a production OCR trust boundary. Enabling
an external router or vision model sends bounded questions/evidence and selected image bytes to the
configured provider; operators must approve that destination and its retention policy.
