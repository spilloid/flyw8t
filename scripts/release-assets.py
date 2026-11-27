"""Write or verify the checksum manifest for the exact Flyw8t release assets."""

import argparse
import hashlib
import re
from pathlib import Path


COMPONENTS = ("agent", "mcp", "server", "sign")
MANIFEST = "SHA256SUMS"


def expected_binaries(tag):
    if not re.fullmatch(r"v[0-9][0-9A-Za-z.+-]*", tag):
        raise ValueError("Expected a release tag beginning with v and a version number")
    return sorted(
        [f"flyw8t-{name}-{tag}-x86_64-pc-windows-msvc.exe" for name in (*COMPONENTS, "technician")]
        + [f"flyw8t-{name}-{tag}-x86_64-unknown-linux-gnu" for name in COMPONENTS]
    )


def checksum(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def check_release(tag, directory, write_checksums):
    names = expected_binaries(tag)
    expected = set(names if write_checksums else [*names, MANIFEST])
    entries = {entry.name: entry for entry in directory.iterdir()}
    if entries.keys() != expected:
        missing = ", ".join(sorted(expected - entries.keys())) or "none"
        extra = ", ".join(sorted(entries.keys() - expected)) or "none"
        raise ValueError(f"Release asset inventory differs. Missing {missing}. Unexpected {extra}.")
    for entry in entries.values():
        if entry.is_symlink() or not entry.is_file() or entry.stat().st_size == 0:
            raise ValueError(f"Release asset must be a nonempty regular file ({entry.name})")

    manifest = "".join(f"{checksum(entries[name])}  {name}\n" for name in names).encode("ascii")
    path = directory / MANIFEST
    if write_checksums:
        with path.open("xb") as target:
            target.write(manifest)
    elif path.read_bytes() != manifest:
        raise ValueError("SHA256SUMS does not match the release assets")
    print(f"{tag} · {len(names)} release binaries · {MANIFEST} {'written' if write_checksums else 'verified'}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tag")
    parser.add_argument("directory", type=Path)
    parser.add_argument(
        "--write-checksums", action="store_true", help="write SHA256SUMS for staged assets"
    )
    args = parser.parse_args()
    try:
        check_release(args.tag, args.directory, args.write_checksums)
    except (ValueError, OSError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
