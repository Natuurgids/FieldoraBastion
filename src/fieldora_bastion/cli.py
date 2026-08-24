"""FieldoraBastion command line interface."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from fieldora_bastion.model_bundle import BundleBuildError, build_model_bundle


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fieldora-bastion")
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build-model-bundle")
    build.add_argument("source", type=Path)
    build.add_argument("output", type=Path)
    build.add_argument("--model-id", required=True)
    build.add_argument("--version", required=True)
    build.add_argument("--source-id", default="fieldora-bastion")
    build.add_argument("--license-id", default="unspecified")
    build.add_argument("--max-bytes", type=int, default=64 * 1024 * 1024 * 1024)
    build.add_argument(
        "--signing-key",
        type=Path,
        help="Ed25519 private key PEM used to emit manifest.sig; key material is never copied.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        built = build_model_bundle(
            args.source,
            args.output,
            model_id=args.model_id,
            version=args.version,
            source=args.source_id,
            license_id=args.license_id,
            max_total_bytes=args.max_bytes,
            signing_key=args.signing_key,
        )
    except BundleBuildError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, separators=(",", ":")))
        return 2
    print(
        json.dumps(
            {
                "ok": True,
                "model_id": built.model_id,
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
