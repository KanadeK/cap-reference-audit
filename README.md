# cap-reference-audit

Check whether CAP 1.2 messages in a local archive can actually resolve their
references. A document can be valid XML while its Update or Cancel points to a
missing message, a wrong timestamp or conflicting copies.

This small offline CLI builds a reference ledger across files. It is for archive QA
and ingestion testing. It is **not an alert receiver or a determination of currently
active warnings**. Python 3.11+, MIT, no runtime dependencies or network requests.

## Install and run

```sh
git clone https://github.com/KanadeK/cap-reference-audit.git
cd cap-reference-audit
python -m venv .venv
# POSIX: source .venv/bin/activate
# PowerShell: .venv\Scripts\Activate.ps1
python -m pip install .
cap-reference-audit examples/complete
cap-reference-audit examples/complete examples/missing --format json
```

The first command succeeds with two messages, one edge, no findings. The second
reports a `missing_reference` and exits **1**. Example data is synthetic with
`status=Test`, not operational warning data.

Supply explicit files or directories containing `.xml` files (nonrecursive):

```sh
python -m cap_reference_audit archive/ --format json --fail-on warning
cap-reference-audit archive/ --fail-on never
```

Uninstall with `python -m pip uninstall cap-reference-audit`. Remove the dedicated
virtual environment after deactivating it to clean up. The tool never modifies inputs.

## Findings and interpretation

Errors: missing reference, timestamp mismatch, conflicting bytes for one extended
identity, sender reusing an identifier with another timestamp, self-reference,
future reference and reference cycles.

Warnings: byte-identical duplicate copies, duplicate references, equal-second
timestamps, status mismatch, cross-sender Update/Cancel, missing references on a
control message, and unverified XML signatures.

`missing_control_reference` is an archive QA warning: base CAP makes `references`
optional, while some deployment profiles impose stronger requirements. Cross-sender
references are not automatically invalid; this tool cannot establish authority.
Equal timestamps cannot prove ordering within a second. A missing reference can mean
your local archive is intentionally incomplete, rather than a bad publisher.

Exit codes: **0** selected gate passed, **1** findings meet the gate, **2** malformed,
unsupported, unreadable or oversized input. Default gate is `error`; `warning` fails
on either severity; `never` still reports findings and still fails on input errors.

JSON schema version 1 includes source-file SHA-256 values, exact identity strings,
edges with resolution state, sorted findings and summary counts. Its
`not_referenced_by_local_control` list contains Alert/Update messages not referenced
by a locally resolved Update/Cancel edge. It is purely graph topology: entries can
be expired, invalid, unauthorized, or superseded outside the supplied archive.

## Identity and security boundaries

- Identity is the exact `sender,identifier,sent` tuple. Equivalent time instants
  written with different offsets are **not** silently merged. Chronology uses
  timezone-aware instants.
- Different file bytes with the same identity are conflicts, even if changes are
  just formatting/signature differences. Review them manually. Conflicting copies
  are excluded from resolved edges rather than arbitrarily choosing one.
- UTF-8 single CAP 1.2 `alert` roots only. Numeric timezone with seconds required;
  CAP specifies `-00:00` for UTC. This version rejects `Z`, `+00:00`, fractional
  seconds and 24:00. No Atom feeds, CAP 1.1, XML wrappers or remote URLs.
- 4 MiB per file, 64 MiB total, at most 2,000 unique paths. Processing is in memory.
  DTD/entity declarations are rejected; XInclude is not resolved. No resources,
  attachments or schemas are fetched. The parser reads only the fields used here.
- XML signatures are acknowledged but **not verified**. No authentication, expiry,
  geography, message content, full XML Schema validation, CAP-CP, IPAWS or Google
  profile certification. Validate against your profile separately.
- JSON reports include source paths and sender identifiers from your inputs. Review
  reports before publishing. No content is sent anywhere by this tool.

## Design and alternatives

[OASIS CAP 1.2](https://docs.oasis-open.org/emergency/cap/v1.2/CAP-v1.2-os.html)
defines extended references. [CAP-CP's discussion](https://www.securitepublique.gc.ca/cnt/rsrcs/pblctns/capcp-ntro-rl-st/index3-en.aspx?wbdisable=true)
explains why missed messages can break chains. Existing tools such as
[capvalidator](https://github.com/farrel/capvalidator) validate documents; this
project complements them with cross-file archive evidence.

```python
from cap_reference_audit.core import audit, load

report = audit(load(["archive/"]))
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for tests/build instructions. No third-party
code or actual emergency messages are bundled.

## 中文说明

离线审计 CAP 1.2 消息档案的引用关系，识别缺失前序消息、时间戳不匹配、身份
冲突、自引用、未来引用和引用环。提供 JSON 证据及 CI 退出码。仅检查本地输入
文件之间的关系，不接收或发布预警，不判断当前有效警报，也不验证签名和地区规范。
