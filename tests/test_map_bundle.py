from __future__ import annotations

import json
from pathlib import Path

import pytest

from fieldora_bastion.map_bundle import build_map_bundle
from fieldora_bastion.model_bundle import BundleBuildError


def test_build_map_bundle_accepts_data_only_primary_map(tmp_path: Path) -> None:
    source = tmp_path / "source"
    output = tmp_path / "approved"
    source.mkdir()
    (source / "region.pmtiles").write_bytes(b"pmtiles-test")
    (source / "style.json").write_text('{"version":8}', encoding="utf-8")

    built = build_map_bundle(
        source,
        output,
        map_id="nl-basemap",
        version="2026.08",
        source="approved-map-source",
        license_id="ODbL-1.0",
    )

    manifest = json.loads((built.root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["package_class"] == "map"
    assert manifest["map_id"] == "nl-basemap"
    assert manifest["version"] == "2026.08"
    assert {item["path"] for item in manifest["files"]} == {
        "region.pmtiles",
        "style.json",
    }
    assert not (built.root / "manifest.sig").exists()


def test_map_bundle_rejects_executable_content(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "region.mbtiles").write_bytes(b"map")
    (source / "install.py").write_text("print('no')", encoding="utf-8")

    with pytest.raises(BundleBuildError, match="unsupported or executable map file"):
        build_map_bundle(source, tmp_path / "approved", map_id="map", version="1")


def test_map_bundle_requires_primary_map_artifact(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "style.json").write_text("{}", encoding="utf-8")

    with pytest.raises(BundleBuildError, match="no supported primary map artifact"):
        build_map_bundle(source, tmp_path / "approved", map_id="map", version="1")


def test_map_bundle_rejects_symlink(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    real = tmp_path / "outside.pmtiles"
    real.write_bytes(b"map")
    link = source / "region.pmtiles"
    try:
        link.symlink_to(real)
    except OSError:
        pytest.skip("symlinks unavailable")

    with pytest.raises(BundleBuildError, match="must not contain symlinks"):
        build_map_bundle(source, tmp_path / "approved", map_id="map", version="1")
