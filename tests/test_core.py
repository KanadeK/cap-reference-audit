import json
import os
import subprocess
import sys
from pathlib import Path
from xml.sax.saxutils import escape

import pytest

from cap_reference_audit import core
from cap_reference_audit.core import InputError, audit, load, parse, parse_time


def message(
    identifier="A",
    sent="2026-01-01T00:00:00-00:00",
    kind="Alert",
    refs="",
    sender="archive.example",
    status="Test",
    extra="",
):
    text = f"""<alert xmlns="urn:oasis:names:tc:emergency:cap:1.2">
    <identifier>{escape(identifier)}</identifier><sender>{escape(sender)}</sender>
    <sent>{sent}</sent><status>{status}</status><msgType>{kind}</msgType><scope>Public</scope>
    <references>{escape(refs)}</references>{extra}</alert>"""
    return text.encode()


def ref(identifier="A", sent="2026-01-01T00:00:00-00:00", sender="archive.example"):
    return f"{sender},{identifier},{sent}"


def codes(report):
    return {f["code"] for f in report["findings"]}


def test_complete_alert_update_cancel_chain():
    a = parse(message())
    b = parse(message("B", "2026-01-01T01:00:00-00:00", "Update", ref()))
    c = parse(
        message("C", "2026-01-01T02:00:00-00:00", "Cancel", ref() + " " + ref("B", b.identity.sent))
    )
    report = audit([c, b, a])
    assert report["summary"] == {
        "files": 3,
        "identities": 3,
        "edges": 3,
        "errors": 0,
        "warnings": 0,
    }
    assert not report["not_referenced_by_local_control"]
    assert report == audit([a, b, c])


def test_missing_and_wrong_timestamp_are_distinct():
    a = parse(message())
    b = parse(
        message(
            "B",
            "2026-01-01T02:00:00-00:00",
            "Update",
            ref("MISSING") + " " + ref("A", "2026-01-01T01:00:00+01:00"),
        )
    )
    report = audit([a, b])
    assert codes(report) == {"missing_reference", "timestamp_mismatch"}
    assert report["summary"]["errors"] == 2


def test_self_future_cycle_and_equal_time():
    a = parse(message("A", refs=ref("B", "2026-01-01T01:00:00-00:00")))
    b = parse(message("B", "2026-01-01T01:00:00-00:00", refs=ref()))
    assert {"future_reference", "reference_cycle"} <= codes(audit([a, b]))
    assert {"self_reference", "reference_cycle"} <= codes(audit([parse(message(refs=ref()))]))
    assert "equal_time_reference" in codes(
        audit([parse(message()), parse(message("B", refs=ref()))])
    )


def test_duplicates_and_conflicts():
    raw = message()
    assert codes(audit([parse(raw, "one"), parse(raw, "two")])) == {"duplicate_copy"}
    conflicting = parse(message(extra="<note>Changed bytes</note>"))
    control = parse(message("B", "2026-01-01T01:00:00-00:00", "Update", ref()))
    report = audit([parse(raw), conflicting, control])
    assert "conflicting_identity" in codes(report)
    assert report["edges"][0]["resolution"] == "conflicting_identity"


def test_identifier_reuse_and_repeated_reference():
    a = parse(message())
    changed = parse(message("A", "2026-01-01T01:00:00-00:00"))
    assert "identifier_reused" in codes(audit([a, changed]))
    b = parse(message("B", "2026-01-01T02:00:00-00:00", refs=ref() + " " + ref()))
    report = audit([a, b])
    assert codes(report) == {"duplicate_reference"}
    assert len(report["edges"]) == 1


def test_warnings_do_not_claim_schema_or_authority_failure():
    a = parse(message())
    b = parse(
        message(
            "B",
            "2026-01-01T02:00:00-00:00",
            "Cancel",
            ref(),
            sender="other.example",
            status="Actual",
        )
    )
    assert codes(audit([a, b])) == {"cross_sender_control", "status_mismatch"}
    assert codes(audit([parse(message(kind="Update"))])) == {"missing_control_reference"}


def test_ack_does_not_supersede_and_signature_not_trusted():
    a = parse(message(extra='<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"/>'))
    b = parse(message("B", "2026-01-01T01:00:00-00:00", "Ack", ref()))
    report = audit([a, b])
    assert report["not_referenced_by_local_control"] == [ref()]
    assert codes(report) == {"signature_unverified"}


@pytest.mark.parametrize(
    "value",
    [
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:00",
        "2026-01-01T00:00:00+00:00",
        "2026-01-01T00:00:00.5-00:00",
        "2026-01-01T00:00:00+15:00",
        "2026-01-01T00:00:00+14:01",
        "2026-01-01T00:00:00+01:60",
        "2026-02-30T00:00:00-00:00",
        "2026-01-01T24:00:00-00:00",
        "bad",
    ],
)
def test_invalid_times(value):
    with pytest.raises(InputError):
        parse_time(value)


def test_numeric_offset_chronology():
    a = parse(message(sent="2026-01-01T02:00:00+02:00"))
    b = parse(message("B", "2026-01-01T01:00:00-00:00", "Update", ref(sent=a.identity.sent)))
    assert not audit([a, b])["findings"]


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"\xff",
        b"<alert/>",
        b"<alert>",
        b"\x00",
        b"<!DOCTYPE x><x/>",
        b'<!DOCTYPE x [<!ENTITY a "test">]><x>&a;</x>',
        b'<?xml version="1.0" encoding="ISO-8859-1"?><x/>',
        message(identifier="has space"),
        message(identifier="a,b"),
        message(sender="a&b"),
        message(status="Bogus"),
        message(kind="Bogus"),
        message(refs="only,two"),
        message(extra="<identifier>Duplicate</identifier>"),
        message().replace(b"<identifier>A</identifier>", b"<identifier><b>A</b></identifier>"),
        message().replace(b"<sender>archive.example</sender>", b""),
        message(identifier=""),
    ],
)
def test_invalid_xml_or_envelope(data):
    with pytest.raises(InputError):
        parse(data)


def test_file_loading_bounds_and_no_network(tmp_path, monkeypatch):
    (tmp_path / "a.xml").write_bytes(message())
    (tmp_path / "ignored.json").write_bytes(b"bad")
    assert len(load([tmp_path, tmp_path / "a.xml"])) == 1
    with pytest.raises(InputError):
        load([tmp_path / "missing.xml"])
    monkeypatch.setattr(core, "MAX_TOTAL_BYTES", 5)
    with pytest.raises(InputError, match="total limit"):
        load([tmp_path])
    monkeypatch.setattr(core, "MAX_FILE_BYTES", 5)
    with pytest.raises(InputError, match="4 MiB"):
        parse(message())


def test_empty_input(tmp_path):
    with pytest.raises(InputError):
        load([tmp_path])
    with pytest.raises(InputError):
        audit([])


def test_cli_workflow(tmp_path):
    (tmp_path / "a.xml").write_bytes(message())
    b = tmp_path / "b.xml"
    b.write_bytes(message("B", "2026-01-01T01:00:00-00:00", "Update", ref("MISSING")))
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).parents[1] / "src"))

    def run(*args):
        return subprocess.run(
            [sys.executable, "-m", "cap_reference_audit", str(tmp_path), *args],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    result = run("--format", "json")
    assert result.returncode == 1
    assert json.loads(result.stdout)["findings"][0]["code"] == "missing_reference"
    assert run("--fail-on", "never").returncode == 0
    b.write_bytes(message("B", kind="Update"))
    assert run().returncode == 0 and run("--fail-on", "warning").returncode == 1
    b.write_bytes(b"not XML")
    result = run()
    assert result.returncode == 2 and not result.stdout


def test_long_graph_does_not_recurse():
    messages = []
    for i in range(1500):
        # Equal times deliberately produce warnings; this test exercises graph depth.
        messages.append(parse(message(str(i), refs=ref(str(i + 1)) if i < 1499 else "")))
    assert audit(messages)["summary"]["edges"] == 1499
