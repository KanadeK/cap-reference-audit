# Changelog

## 0.1.1

- Require setuptools >=77.0.3, matching the SPDX license-expression metadata used by the project.
- Include this changelog in the source distribution. Runtime behavior is unchanged.

## 0.1.0

- Audit exact sender/identifier/sent references across local CAP 1.2 files.
- Distinguish absent messages from timestamp mismatches and conflicting identities.
- Detect chronology problems, self-reference and cycles without recursive traversal.
- Report duplicate copies, cross-status/sender references and unverified signatures.
- Provide deterministic JSON evidence, source hashes and configurable CI gates.

Validation: 40 automated tests on Windows/Python 3.13, including a 1,500-message
graph, invalid XML, DTD rejection and CLI integration. Ruff, wheel/sdist builds and
isolated wheel installation are part of release checks. GitHub CI runs Linux/Python
3.11 and 3.13 and Windows/Python 3.13.

Limitations: local UTF-8 CAP 1.2 envelopes only; no current-alert evaluation,
signature validation or full CAP/profile conformance checking. See README.
