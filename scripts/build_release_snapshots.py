"""Derive release fixtures with reviewed dependency locks; preserve historical archives."""

from __future__ import annotations

import gzip
import hashlib
import json
import tarfile
from io import BytesIO
from pathlib import Path, PurePosixPath

from pydantic import TypeAdapter

from remediation_agent.adapters.runtime_qualification import Fixture

ROOT = Path(__file__).resolve().parents[1]


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def derive(archive: bytes, replacements: dict[str, bytes]) -> bytes:
    """Replace only the two root dependency files in a verified operator fixture."""
    output = BytesIO()
    replaced: set[str] = set()
    with tarfile.open(fileobj=BytesIO(archive)) as source, tarfile.open(fileobj=output, mode="w") as target:
        for member in source.getmembers():
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or not (member.isfile() or member.isdir()):
                raise ValueError("UNSAFE_RELEASE_FIXTURE")
            # Canonicalize archive metadata before re-emitting it. No extraction occurs.
            member = member.replace(name=path.as_posix())
            member.pax_headers = {}
            relative = PurePosixPath(*path.parts[1:]).as_posix()
            if member.isdir():
                target.addfile(member)
                continue
            stream = source.extractfile(member)
            if stream is None:
                raise ValueError("MISSING_RELEASE_FIXTURE_FILE")
            payload = stream.read()
            if relative in replacements:
                payload = replacements[relative]
                replaced.add(relative)
            member.size = len(payload)
            target.addfile(member, BytesIO(payload))
    if replaced != set(replacements):
        raise ValueError("MISSING_RELEASE_DEPENDENCY_FILES")
    compressed = BytesIO()
    # GzipFile uses the portable unknown-OS header on Python 3.12, unlike compress.
    with gzip.GzipFile(fileobj=compressed, mode="wb", filename="", mtime=0) as stream_out:
        stream_out.write(output.getvalue())
    return compressed.getvalue()


def build(root: Path = ROOT) -> None:
    originals = root / "config/evaluation/snapshots"
    destination = root / "config/evaluation/release-snapshots"
    fixtures = TypeAdapter(dict[str, Fixture]).validate_json((originals / "manifest.json").read_text())
    replacements = {
        name: (root / "validation/ecommerce" / name).read_bytes() for name in ("package.json", "package-lock.json")
    }
    destination.mkdir(exist_ok=True)
    generated: dict[str, Fixture] = {}
    provenance: dict[str, dict[str, str]] = {}
    for name, fixture in fixtures.items():
        original = (originals / fixture.archive).read_bytes()
        patch = (originals / (name + ".diff")).read_bytes()
        if digest(original) != fixture.archive_digest or digest(patch) != fixture.patch_digest:
            raise ValueError("QUALIFICATION_FIXTURE_DIGEST_MISMATCH")
        derived = derive(original, replacements)
        (destination / fixture.archive).write_bytes(derived)
        (destination / (name + ".diff")).write_bytes(patch)
        generated[name] = fixture.model_copy(update={"archive_digest": digest(derived)})
        provenance[name] = {
            "source_commit": fixture.source_commit,
            "original_archive_digest": fixture.archive_digest,
            "release_archive_digest": digest(derived),
            **{key + "_digest": digest(value) for key, value in replacements.items()},
        }
    (destination / "manifest.json").write_text(
        json.dumps({key: value.model_dump() for key, value in generated.items()}, indent=2) + "\n"
    )
    (destination / "dependency-provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")


if __name__ == "__main__":
    build()
