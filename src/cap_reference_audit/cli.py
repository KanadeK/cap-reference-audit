import argparse
import json
import sys

from . import __version__
from .core import InputError, audit, load


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Audit exact references across local CAP 1.2 messages."
    )
    parser.add_argument("inputs", nargs="+", help="XML files or directories (nonrecursive)")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--fail-on", choices=["error", "warning", "never"], default="error")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)
    try:
        report = audit(load(args.inputs))
    except InputError as exc:
        print(f"Input error: {ascii(str(exc))}", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps(report, ensure_ascii=True, indent=2))
    else:
        print(json.dumps(report["summary"], sort_keys=True))
        for item in report["findings"]:
            print(
                f"{item['severity']}: {item['code']} {ascii(item['message'])} "
                f"reference={ascii(item['reference'])}: {item['detail']}"
            )
        print(report["notice"])
    summary = report["summary"]
    failed = summary["errors"] or (args.fail_on == "warning" and summary["warnings"])
    return int(args.fail_on != "never" and bool(failed))
