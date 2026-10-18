"""Security dependency updates must not change benchmark application behavior."""

import json
import tarfile
from pathlib import Path

import pytest

from scripts.build_release_snapshots import build, derive, digest

ROOT = Path(__file__).parents[2]


def contents(path: Path) -> dict[str, bytes]:
    with tarfile.open(path) as archive:
        result = {}
        for member in archive.getmembers():
            if member.isfile():
                stream = archive.extractfile(member)
                assert stream is not None
                result["/".join(Path(member.name).parts[1:])] = stream.read()
        return result


@pytest.mark.parametrize("case", ["ah54", "ah56"])
def test_release_fixture_preserves_application_and_provenance(case: str, tmp_path: Path) -> None:
    import shutil

    original = ROOT / "config/evaluation/snapshots"
    released = ROOT / "config/evaluation/release-snapshots"
    before = contents(original / (case + ".tar.gz"))
    after = contents(released / (case + ".tar.gz"))
    assert before.keys() == after.keys()
    assert {name for name in before if before[name] != after[name]} == {"package.json", "package-lock.json"}
    assert (released / (case + ".diff")).read_bytes() == (original / (case + ".diff")).read_bytes()
    for name in ("package.json", "package-lock.json"):
        assert after[name] == (ROOT / "validation/ecommerce" / name).read_bytes()
    assert json.loads(before["package.json"])["dependencies"] == json.loads(after["package.json"])["dependencies"]
    provenance = json.loads((released / "dependency-provenance.json").read_text())[case]
    assert provenance["original_archive_digest"] == digest((original / (case + ".tar.gz")).read_bytes())
    assert provenance["release_archive_digest"] == digest((released / (case + ".tar.gz")).read_bytes())
    shutil.copytree(original, tmp_path / "config/evaluation/snapshots")
    shutil.copytree(ROOT / "validation/ecommerce", tmp_path / "validation/ecommerce")
    build(tmp_path)
    assert (tmp_path / "config/evaluation/release-snapshots" / (case + ".tar.gz")).read_bytes() == (
        released / (case + ".tar.gz")
    ).read_bytes()


def test_release_derivation_rejects_missing_dependency_contract() -> None:
    archive = (ROOT / "config/evaluation/snapshots/ah54.tar.gz").read_bytes()
    with pytest.raises(ValueError, match="MISSING_RELEASE_DEPENDENCY_FILES"):
        derive(archive, {"missing.json": b"{}"})
