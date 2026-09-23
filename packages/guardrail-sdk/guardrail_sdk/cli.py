"""`guardrail` command line: conformance checks for plugin authors."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys

import httpx

from .conformance import load_samples, run_conformance
from .guardrail import PluginContext
from .loader import resolve_class
from .manifest import Manifest
from .remote import EnvSecretReader

_VAR_RE = re.compile(r"\$\{([A-Z0-9_]+)(?::-([^}]*))?\}")


def _load_config(path: str | None) -> dict:
    """Read a JSON config, expanding ${VAR} / ${VAR:-default} from the environment."""
    if not path:
        return {}
    text = open(path, encoding="utf-8").read()

    def repl(m: re.Match[str]) -> str:
        if m.group(1) in os.environ:
            return os.environ[m.group(1)]
        if m.group(2) is not None:
            return m.group(2)
        raise SystemExit(f"config {path} needs environment variable {m.group(1)}")

    return json.loads(_VAR_RE.sub(repl, text))


async def _conformance(args: argparse.Namespace) -> int:
    manifest = Manifest.from_yaml(args.manifest)
    config = _load_config(args.config)
    samples = load_samples(args.samples) if args.samples else None
    async with httpx.AsyncClient() as http:
        cls = resolve_class(manifest)
        guardrail = cls(manifest, PluginContext(http=http, secrets=EnvSecretReader()))
        try:
            report = await run_conformance(guardrail, config, samples)
        finally:
            await guardrail.close()
    print(json.dumps(report.to_dict(), indent=2))
    return 0 if report.passed else 1


async def _evaluate(args: argparse.Namespace) -> int:
    from .evaluation import evaluate, load_dataset, meets, report

    manifest = Manifest.from_yaml(args.manifest)
    config = _load_config(args.config)
    cases = load_dataset(args.dataset)
    async with httpx.AsyncClient() as http:
        guardrail = resolve_class(manifest)(manifest, PluginContext(http=http, secrets=EnvSecretReader()))
        await guardrail.setup(config)
        try:
            per_stage = await evaluate(guardrail, cases)
        finally:
            await guardrail.close()
    out = report(per_stage, manifest.key)
    problems = meets(per_stage, args.min_precision, args.min_recall, args.min_cases)
    out["thresholds"] = {
        "min_precision": args.min_precision,
        "min_recall": args.min_recall,
        "min_cases": args.min_cases,
        "passed": not problems,
        "problems": problems,
    }
    text = json.dumps(out, indent=2)
    if args.report:
        with open(args.report, "w", encoding="utf-8") as fh:
            fh.write(text)
    print(text)
    return 0 if not problems else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="guardrail")
    sub = parser.add_subparsers(dest="command", required=True)
    c = sub.add_parser("conformance", help="run the conformance suite against a guardrail")
    c.add_argument("--manifest", required=True, help="path to guardrail.yaml")
    c.add_argument("--config", help="JSON file with the guardrail config")
    c.add_argument("--samples", help="JSON file with extra labelled samples")
    e = sub.add_parser("evaluate", help="precision/recall against a labelled JSONL dataset")
    e.add_argument("--manifest", required=True)
    e.add_argument("--config", help="JSON file with the guardrail config")
    e.add_argument("--dataset", required=True, help="JSONL: {id, stage, label: pii|clean, payload}")
    e.add_argument("--min-precision", type=float, default=0.0)
    e.add_argument("--min-recall", type=float, default=0.0)
    e.add_argument("--min-cases", type=int, default=200, help="required cases per stage (requirement D)")
    e.add_argument("--report", help="also write the JSON report here")
    args = parser.parse_args(argv)
    if args.command == "conformance":
        return asyncio.run(_conformance(args))
    if args.command == "evaluate":
        return asyncio.run(_evaluate(args))
    return 2


if __name__ == "__main__":
    sys.exit(main())
