"""FieldoraBastion command line interface."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from fieldora_bastion.dataset_certification import (
    DatasetCertificationError,
    certify_gbif_dataset,
    certify_map_dataset,
)
from fieldora_bastion.gbif_acquisition import GbifAcquisitionError, acquire_gbif_archive
from fieldora_bastion.model_bundle import BundleBuildError, build_model_bundle
from fieldora_bastion.scanner import ScanError, scan_with_clamav
from fieldora_bastion.secret_handler import UnixSocketSigner
from fieldora_bastion.security_install_transfer import (
    TransferBuildError,
    build_security_install_transfer,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fieldora-bastion")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan-model-source")
    scan.add_argument("source", type=Path)
    scan.add_argument("report", type=Path)
    scan.add_argument("--database", type=Path, required=True)
    scan.add_argument("--max-bytes", type=int, default=64 * 1024 * 1024 * 1024)

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
    build.add_argument(
        "--scan-report",
        type=Path,
        help=(
            "JSON clean-scan attestation produced by an approved malware scanner; "
            "requires --signing-key so the attestation is bound to manifest.sig."
        ),
    )
    maps = sub.add_parser("certify-map-dataset")
    maps.add_argument("source", type=Path)
    maps.add_argument("output", type=Path)
    maps.add_argument("--dataset-id", required=True)
    maps.add_argument("--version", required=True)
    maps.add_argument("--signer-key-id", required=True)
    maps.add_argument("--signing-key", type=Path, required=True)
    maps.add_argument("--source-id", required=True)
    maps.add_argument("--license-id", required=True)
    maps.add_argument("--scan-report", type=Path, required=True)

    acquire = sub.add_parser("acquire-gbif-archive")
    acquire.add_argument("source_url")
    acquire.add_argument("quarantine", type=Path)
    acquire.add_argument("--download-key", required=True)
    acquire.add_argument("--doi", required=True)
    acquire.add_argument("--license-id", required=True)
    acquire.add_argument("--query-json", required=True)
    acquire.add_argument("--record-count", type=int, required=True)
    acquire.add_argument("--max-bytes", type=int, default=64 * 1024 * 1024 * 1024)
    acquire.add_argument("--signing-key", type=Path)
    acquire.add_argument("--signer-socket", type=Path)
    acquire.add_argument("--signer-key-id")

    gbif = sub.add_parser("certify-gbif-dataset")
    gbif.add_argument("source", type=Path)
    gbif.add_argument("output", type=Path)
    gbif.add_argument("--dataset-id", required=True)
    gbif.add_argument("--version", required=True)
    gbif.add_argument("--signer-key-id", required=True)
    gbif.add_argument("--signing-key", type=Path, required=True)
    gbif.add_argument("--acquisition-record", type=Path, required=True)
    gbif.add_argument("--scan-report", type=Path, required=True)
    gbif.add_argument("--acquisition-public-key", type=Path, required=True)

    transfer = sub.add_parser("export-security-install")
    transfer.add_argument("bundle", type=Path)
    transfer.add_argument("output", type=Path)
    transfer.add_argument("--collector-id", default="offline-transfer")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "scan-model-source":
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

    if args.command == "acquire-gbif-archive":
        try:
            query = json.loads(args.query_json)
            if not isinstance(query, dict):
                raise ValueError("GBIF query JSON must be an object")
            archive, provenance = acquire_gbif_archive(
                args.source_url, args.quarantine, download_key=args.download_key,
                doi=args.doi, license_id=args.license_id, query=query,
                record_count=args.record_count, max_bytes=args.max_bytes,
                signing_key=args.signing_key,
                signer=(
                    UnixSocketSigner(args.signer_socket, args.signer_key_id)
                    if args.signer_socket and args.signer_key_id
                    else None
                ),
            )
        except (GbifAcquisitionError, OSError, json.JSONDecodeError, ValueError) as exc:
            print(json.dumps({"ok": False, "error": str(exc)}, separators=(",", ":")))
            return 2
        print(json.dumps(
            {"ok": True, "archive": str(archive), "acquisition_record": str(provenance)},
            separators=(",", ":"),
        ))
        return 0

    if args.command in {"certify-map-dataset", "certify-gbif-dataset"}:
        try:
            if args.command == "certify-map-dataset":
                artifact, evidence = certify_map_dataset(
                    args.source, args.output, dataset_id=args.dataset_id,
                    version=args.version, signer_key_id=args.signer_key_id,
                    signing_key=args.signing_key,
                    source_id=args.source_id,
                    license_id=args.license_id,
                    scan_report=args.scan_report,
                )
            else:
                acquisition = json.loads(args.acquisition_record.read_text(encoding="utf-8"))
                artifact, evidence = certify_gbif_dataset(
                    args.source, args.output, dataset_id=args.dataset_id,
                    version=args.version, signer_key_id=args.signer_key_id,
                    signing_key=args.signing_key,
                    acquisition_record=acquisition,
                    scan_report=args.scan_report,
                    acquisition_public_key=args.acquisition_public_key,
                )
        except (
            DatasetCertificationError,
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValueError,
        ) as exc:
            print(json.dumps({"ok": False, "error": str(exc)}, separators=(",", ":")))
            return 2
        print(json.dumps(
            {"ok": True, "artifact": str(artifact), "evidence": str(evidence)},
            separators=(",", ":"),
        ))
        return 0

    if args.command == "export-security-install":
        try:
            artifact, evidence = build_security_install_transfer(
                args.bundle, args.output, collector_id=args.collector_id
            )
        except TransferBuildError as exc:
            print(json.dumps({"ok": False, "error": str(exc)}, separators=(",", ":")))
            return 2
        print(json.dumps({"ok": True, "artifact": str(artifact), "evidence": str(evidence)}, separators=(",", ":")))
        return 0

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
            scan_report=args.scan_report,
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
