"""Type-specific validation for map and biodiversity artifacts.

These validators intentionally operate on quarantined local files. Network
acquisition is a separate Bastion concern and Fieldora is never contacted.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from zipfile import BadZipFile, ZipFile

_MAP_EXTENSIONS = {".gpkg", ".geojson", ".json", ".tif", ".tiff", ".mbtiles", ".pmtiles"}
_BIODIVERSITY_EXTENSIONS = {".csv", ".tsv", ".txt", ".json", ".zip"}
_DWC_TERMS = {"scientificName", "taxonKey", "occurrenceID", "eventDate"}


class DatasetValidationError(ValueError):
    """Raised when quarantined external data fails its Bastion policy."""


def _regular_files(root: Path) -> list[Path]:
    root = root.resolve()
    files = sorted(path for path in root.rglob("*") if path.is_file())
    if not files:
        raise DatasetValidationError("dataset is empty")
    for path in files:
        if path.is_symlink():
            raise DatasetValidationError("dataset must not contain symlinks")
    return files


def validate_map_dataset(root: Path, *, source_id: str, license_id: str) -> dict:
    """Validate a quarantined map package before it can be certified."""
    if not source_id.strip() or not license_id.strip():
        raise DatasetValidationError("map source and license are required")
    files = _regular_files(root)
    unsupported = [p.name for p in files if p.suffix.lower() not in _MAP_EXTENSIONS]
    if unsupported:
        raise DatasetValidationError(f"unsupported map file type: {unsupported[0]}")
    # GeoJSON can be structurally checked without adding native GDAL dependencies.
    geojson_count = 0
    for path in files:
        if path.suffix.lower() in {".geojson", ".json"}:
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise DatasetValidationError(f"invalid GeoJSON/JSON: {path.name}") from exc
            if not isinstance(payload, dict) or payload.get("type") not in {
                "FeatureCollection", "Feature", "GeometryCollection",
                "Point", "MultiPoint", "LineString", "MultiLineString",
                "Polygon", "MultiPolygon",
            }:
                raise DatasetValidationError(f"unrecognized GeoJSON structure: {path.name}")
            geojson_count += 1
    return {
        "approved": True,
        "validator": "fieldora-bastion-map-v1",
        "source_id": source_id,
        "license_id": license_id,
        "file_count": len(files),
        "geojson_structures_checked": geojson_count,
        "native_geospatial_validation_required_on_bastion": any(
            p.suffix.lower() in {".gpkg", ".tif", ".tiff", ".mbtiles", ".pmtiles"} for p in files
        ),
    }


def validate_biodiversity_dataset(
    root: Path,
    *,
    source_id: str,
    license_id: str,
    dataset_key: str = "",
    doi: str = "",
) -> dict:
    """Validate GBIF/Darwin-Core-like material and preserve source identifiers."""
    if not source_id.strip() or not license_id.strip():
        raise DatasetValidationError("biodiversity source and license are required")
    files = _regular_files(root)
    unsupported = [p.name for p in files if p.suffix.lower() not in _BIODIVERSITY_EXTENSIONS]
    if unsupported:
        raise DatasetValidationError(f"unsupported biodiversity file type: {unsupported[0]}")

    tabular_checked = 0
    darwin_core_terms: set[str] = set()
    for path in files:
        suffix = path.suffix.lower()
        if suffix in {".csv", ".tsv", ".txt"}:
            delimiter = "\t" if suffix in {".tsv", ".txt"} else ","
            try:
                with path.open("r", encoding="utf-8-sig", newline="") as stream:
                    reader = csv.reader(stream, delimiter=delimiter)
                    header = next(reader, [])
            except (OSError, UnicodeDecodeError, csv.Error) as exc:
                raise DatasetValidationError(f"unreadable tabular dataset: {path.name}") from exc
            if not header:
                raise DatasetValidationError(f"tabular dataset has no header: {path.name}")
            darwin_core_terms.update(_DWC_TERMS.intersection(header))
            tabular_checked += 1
        elif suffix == ".zip":
            try:
                with ZipFile(path) as archive:
                    for member in archive.infolist():
                        name = Path(member.filename)
                        if name.is_absolute() or ".." in name.parts:
                            raise DatasetValidationError("biodiversity archive contains unsafe path")
            except BadZipFile as exc:
                raise DatasetValidationError(f"invalid biodiversity ZIP: {path.name}") from exc

    return {
        "approved": True,
        "validator": "fieldora-bastion-biodiversity-v1",
        "source_id": source_id,
        "license_id": license_id,
        "dataset_key": dataset_key,
        "doi": doi,
        "file_count": len(files),
        "tabular_files_checked": tabular_checked,
        "darwin_core_terms_observed": sorted(darwin_core_terms),
    }
