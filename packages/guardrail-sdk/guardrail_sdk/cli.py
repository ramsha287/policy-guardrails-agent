"""`guardrail` command line: conformance checks for plugin authors."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

import httpx

from .conformance import load_samples, run_conformance
from .guardrail import PluginContext
from .loader import resolve_class
from .manifest import Manifest
from .remote import EnvSecretReader


async def _conformance(args: argparse.Namespace) -> int:
    manifest = Manifest.from_yaml(args.manifest)
    config = json.loads(open(args.config, encoding="utf-8").read()) if args.config else {}
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="guardrail")
    sub = parser.add_subparsers(dest="command", required=True)
    c = sub.add_parser("conformance", help="run the conformance suite against a guardrail")
    c.add_argument("--manifest", required=True, help="path to guardrail.yaml")
    c.add_argument("--config", help="JSON file with the guardrail config")
    c.add_argument("--samples", help="JSON file with extra labelled samples")
    args = parser.parse_args(argv)
    if args.command == "conformance":
        return asyncio.run(_conformance(args))
    return 2


if __name__ == "__main__":
    sys.exit(main())
