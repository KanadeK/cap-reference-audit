"""Offline integrity checks for CAP archive references, not alert delivery."""

import hashlib
import re
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

NS = "{urn:oasis:names:tc:emergency:cap:1.2}"
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_FILES = 2000
DATE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}\Z", re.ASCII)
STATUSES = {"Actual", "Exercise", "System", "Test", "Draft"}
TYPES = {"Alert", "Update", "Cancel", "Ack", "Error"}


class InputError(ValueError):
    """Input is unsupported, malformed or exceeds an explicit bound."""


@dataclass(frozen=True, order=True)
class Identity:
    sender: str
    identifier: str
    sent: str

    def text(self):
        return f"{self.sender},{self.identifier},{self.sent}"


@dataclass(frozen=True)
class Message:
    identity: Identity
    time: datetime
    status: str
    kind: str
    scope: str
    references: tuple[Identity, ...]
    source: str
    digest: str
    signed: bool


def parse_time(value: str) -> datetime:
    if not DATE.fullmatch(value):
        raise InputError("CAP timestamp needs seconds and a numeric timezone, not Z/fractions")
    hours, minutes = int(value[-5:-3]), int(value[-2:])
    if hours > 14 or minutes > 59 or (hours == 14 and minutes):
        raise InputError("CAP timezone offset is outside the XML dateTime range")
    if value.endswith("+00:00"):
        raise InputError("CAP represents UTC as -00:00, not +00:00")
    try:
        return datetime.fromisoformat(value)
    except ValueError as exc:
        raise InputError(f"invalid CAP timestamp: {value!r}") from exc


def _identifier(value):
    if not value or re.search(r"[\s,<&]", value):
        raise InputError(
            "sender and identifier must be nonempty and contain no whitespace, comma, <, &"
        )
    return value


def parse(data: bytes, source="<memory>") -> Message:
    if len(data) > MAX_FILE_BYTES:
        raise InputError("CAP file exceeds 4 MiB")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeError as exc:
        raise InputError("CAP files must be UTF-8") from exc
    if "\x00" in text or re.search(r"<!\s*(DOCTYPE|ENTITY)\b", text, re.IGNORECASE):
        raise InputError("DTD, entity declarations and NUL are not supported")
    encoding = re.search(r"<\?xml\s[^?]*encoding\s*=\s*['\"]([^'\"]+)", text)
    if encoding and encoding[1].lower() not in {"utf-8", "utf8"}:
        raise InputError("XML encoding declaration must be UTF-8")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise InputError(f"invalid XML: {exc}") from exc
    if root.tag != NS + "alert":
        raise InputError("expected a single CAP 1.2 alert root, not a feed or wrapper")

    def field(name, required=True):
        elements = root.findall(NS + name)
        if not elements and not required:
            return ""
        if len(elements) != 1 or len(elements[0]):
            raise InputError(f"expected one plain-text {name} element")
        value = elements[0].text or ""
        if required and not value:
            raise InputError(f"empty {name}")
        return value

    identity = Identity(
        _identifier(field("sender")), _identifier(field("identifier")), field("sent")
    )
    instant = parse_time(identity.sent)
    kind, status, scope = field("msgType"), field("status"), field("scope")
    if (
        kind not in TYPES
        or status not in STATUSES
        or scope not in {"Public", "Restricted", "Private"}
    ):
        raise InputError("invalid CAP msgType, status or scope")
    references = []
    for token in field("references", False).split():
        parts = token.split(",")
        if len(parts) != 3:
            raise InputError("reference must contain exactly sender,identifier,sent")
        ref = Identity(_identifier(parts[0]), _identifier(parts[1]), parts[2])
        parse_time(ref.sent)
        references.append(ref)
    return Message(
        identity,
        instant,
        status,
        kind,
        scope,
        tuple(references),
        source,
        hashlib.sha256(data).hexdigest(),
        bool(root.findall("{http://www.w3.org/2000/09/xmldsig#}Signature")),
    )


def load(paths) -> list[Message]:
    """Expand explicit files and nonrecursive *.xml directories, never URLs."""
    files = set()
    try:
        for item in paths:
            path = Path(item)
            if path.is_dir():
                files.update(
                    p.resolve()
                    for p in path.iterdir()
                    if p.is_file() and p.suffix.lower() == ".xml"
                )
            else:
                files.add(path.resolve())
        if not files or len(files) > MAX_FILES:
            raise InputError("provide 1 to 2000 local CAP XML files")
        total = 0
        result = []
        for path in sorted(files):
            with path.open("rb") as stream:
                data = stream.read(MAX_FILE_BYTES + 1)
            total += len(data)
            if total > MAX_TOTAL_BYTES:
                raise InputError("CAP input exceeds the 64 MiB total limit")
            try:
                result.append(parse(data, str(path)))
            except InputError as exc:
                raise InputError(f"{path.name}: {exc}") from exc
        return result
    except OSError as exc:
        raise InputError(f"cannot read CAP input: {exc}") from exc


def audit(messages: list[Message]) -> dict:
    """Build exact reference edges and explain unresolved/unsafe relationships."""
    if not messages:
        raise InputError("no messages")
    groups = defaultdict(list)
    by_pair = defaultdict(set)
    for message in messages:
        groups[message.identity].append(message)
        by_pair[(message.identity.sender, message.identity.identifier)].add(message.identity)
    findings = []

    def finding(code, severity, key, detail, reference=None):
        findings.append(
            {
                "code": code,
                "severity": severity,
                "message": key.text(),
                "reference": reference.text() if reference else None,
                "detail": detail,
            }
        )

    usable = {}
    for key, group in sorted(groups.items()):
        if len({m.digest for m in group}) > 1:
            finding(
                "conflicting_identity",
                "error",
                key,
                "Different file bytes claim the same extended identity; review all copies.",
            )
            continue
        usable[key] = group[0]
        if len(group) > 1:
            finding(
                "duplicate_copy", "warning", key, f"{len(group)} byte-identical copies supplied."
            )
        if group[0].signed:
            finding(
                "signature_unverified", "warning", key, "XML signature present but not verified."
            )
    for identities in by_pair.values():
        if len(identities) > 1:
            for key in sorted(identities):
                finding(
                    "identifier_reused",
                    "error",
                    key,
                    "Sender reused an identifier with different sent timestamps.",
                )

    edges = []
    graph = {key: [] for key in usable}
    superseded = set()
    for key, message in sorted(usable.items()):
        if message.kind in {"Update", "Cancel"} and not message.references:
            finding(
                "missing_control_reference",
                "warning",
                key,
                "Update/Cancel has no reference; archive QA warning, not base-schema failure.",
            )
        for ref, count in sorted(Counter(message.references).items()):
            if count > 1:
                finding(
                    "duplicate_reference", "warning", key, f"Reference repeated {count} times.", ref
                )
            target = usable.get(ref)
            if ref in groups and target is None:
                status = "conflicting_identity"
            elif target is None:
                status = (
                    "timestamp_mismatch"
                    if (ref.sender, ref.identifier) in by_pair
                    else "missing_reference"
                )
            else:
                status = "resolved"
            edge = {"from": key.text(), "to": ref.text(), "resolution": status}
            edges.append(edge)
            if status != "resolved":
                finding(
                    status,
                    "error",
                    key,
                    "Reference does not resolve uniquely to exact local sender,identifier,sent.",
                    ref,
                )
                continue
            graph[key].append(ref)
            if ref == key:
                finding("self_reference", "error", key, "Message references itself.", ref)
            elif target.time > message.time:
                finding(
                    "future_reference", "error", key, "Reference is sent after this message.", ref
                )
            elif target.time == message.time:
                finding(
                    "equal_time_reference",
                    "warning",
                    key,
                    "Equal second-resolution timestamps cannot establish earlier ordering.",
                    ref,
                )
            if message.status != target.status:
                finding(
                    "status_mismatch",
                    "warning",
                    key,
                    "Message and target have different status.",
                    ref,
                )
            if key.sender != ref.sender and message.kind in {"Update", "Cancel"}:
                finding(
                    "cross_sender_control",
                    "warning",
                    key,
                    "Cross-sender Update/Cancel requires authority review; none is inferred.",
                    ref,
                )
            if message.kind in {"Update", "Cancel"}:
                superseded.add(ref)

    # Iterative depth-first traversal avoids recursion limits on long archives.
    colors = {}
    for start in sorted(graph):
        if start in colors:
            continue
        colors[start] = 1
        stack = [(start, iter(graph[start]))]
        while stack:
            current, iterator = stack[-1]
            nxt = next(iterator, None)
            if nxt is None:
                colors[current] = 2
                stack.pop()
            elif colors.get(nxt) == 1:
                finding(
                    "reference_cycle", "error", current, "Back edge creates a reference cycle.", nxt
                )
            elif nxt not in colors:
                colors[nxt] = 1
                stack.append((nxt, iter(graph[nxt])))

    return {
        "schema_version": 1,
        "summary": {
            "files": len(messages),
            "identities": len(groups),
            "edges": len(edges),
            "errors": sum(f["severity"] == "error" for f in findings),
            "warnings": sum(f["severity"] == "warning" for f in findings),
        },
        "messages": [
            {
                "identity": key.text(),
                "files": sorted(m.source for m in group),
                "sha256": sorted({m.digest for m in group}),
            }
            for key, group in sorted(groups.items())
        ],
        "edges": edges,
        "findings": sorted(findings, key=lambda f: (f["message"], f["code"], f["reference"] or "")),
        "not_referenced_by_local_control": [
            key.text()
            for key, m in sorted(usable.items())
            if m.kind in {"Alert", "Update"} and key not in superseded
        ],
        "notice": (
            "Local reference topology only. No current-alert, expiry or authenticity conclusion."
        ),
    }
