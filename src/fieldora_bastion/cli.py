"""FieldoraBastion command line interface."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from fieldora_bastion.map_bundle import build_map_bundle
from fieldora_bastion.model_bundle import BundleBuildError, build_model_bundle
from fieldora_bastion.scanner import ScanError, scan_with_clamav


def _add_scan_parser(sub: argparse._SubParsersAction, name: str) -> None:
    scan = sub.add_parser(name)
    scan.add_argument("source", type=Path)
    scan.add_argument("report", type=Path)
    scan.add_argument("--database", type=Path, required=True)
    scan.add_argument("--max-bytes", type=int, default=64 * 1024 * 1024 * 1024)


def _add_trust_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--source-id", default="fieldora-bastion")
    parser.add_argument("--license-id", default="unspecified")
    parser.add_argument(
        "--signing-key",
        type=Path,
        help="Ed25519 private key PEM used to emit manifest.sig; key material is never copied.",
    )
    parser.add_argument(
        "--scan-report",
        type=Path,
        help=(
            "JSON clean-scan attestation produced by an approved malware scanner; "
            "requires --signing-key so the attestation is bound to manifest.sig."
        ),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fieldora-bastion")
    sub = parser.add_subparsers(dest="command", required=True)

    _add_scan_parser(sub, "scan-model-source")
    _add_scan_parser(sub, "scan-map-source")

    build = sub.add_parser("build-model-bundle")
    build.add_argument("source", type=Path)
    build.add_argument("output", type=Path)
    build.add_argument("--model-id", required=True)
    build.add_argument("--version", required=True)
    build.add_argument("--max-bytes", type=int, default=64 * 1024 * 1024 * 1024)
    _add_trust_args(build)

    maps = sub.add_parser("build-map-bundle")
    maps.add_argument("source", type=Path)
    maps.add_argument("output", type=Path)
    maps.add_argument("--map-id", required=True)
    maps.add_argument("--version", required=True)
    maps.add_argument("--max-bytes", type=int, default=256 * 1024 * 1024 * 1024)
    _add_trust_args(maps)
    return parser


def _scan(args: argparse.Namespace) -> int:
    try:
        report = scan_with_clamav(
            args.source,
            args.report,
            database_dir=args.database,
            max_total_bytes=args.max_bytes,
        )
    except ScanError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, separators=(",", ":")))
        return 2
    print(json.dumps({"ok": True, **report}, separators=(",", ":")))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command in {"scan-model-source", "scan-map-source"}:
        return _scan(args)

    try:
        if args.command == "build-model-bundle":
            built = build_model_bundle(
                args.source,
                args.output,
                model_id=args.model_id,
                version=args.version,
                source=args.source_id,
                license_id=args.license_id,
                max_total_bytes=args.max_bytes,
                signing_key=args.signing_key,
                scan_report=args.scan_report,
            )
            identity = {"model_id": built.model_id}
        else:
            built = build_map_bundle(
                args.source,
                args.output,
                map_id=args.map_id,
                version=args.version,
                source=args.source_id,
                license_id=args.license_id,
                max_total_bytes=args.max_bytes,
                signing_key=args.signing_key,
                scan_report=args.scan_report,
            )
            identity = {"map_id": built.map_id}
    except BundleBuildError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, separators=(",", ":")))
        return 2
    print(
        json.dumps(
            {
                "ok": True,
                **identity,
                "version": built.version,
                "file_count": built.file_count,
                "total_bytes": built.total_bytes,
                "bundle": str(built.root),
                "manifest_signature": "ed25519" if built.signing_key_id else "unsigned",
                "signing_key_id": built.signing_key_id,
            },
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
