"""Create the public Windows participant from a signed sender and two pinned upstream archives."""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import tempfile
import tomllib
import zipfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
MEDIA = ROOT / "scripts/windows-media-probe"
NODE_VERSION = "24.22.3"
# https://nodejs.org/download/release/v24.22.3/SHASUMS256.txt
NODE_ZIP_SHA = "e612af99f626ab415ea225af6bce5c971feb448cb5cae250bb1c3fa50c5f7d9f"
NODE_EXE_SHA = "86fc4785327db5f5c7558dc6156c543b433c313e813a222e088086222ab4afa6"
APP_FILES = ("public-participant.mjs", "native-participant.mjs", "companion.mjs",
             "participant-transport.mjs", "public-connection.mjs", "participant.html", "participant-ui.js", "participant-ui.css")
CRATE_NOTICE = re.compile(r"^(?:licen[sc]e|copying|copyright|notice|authors)(?:$|[-_.])", re.I)
EXTRA = {"asn1-rs-impl-LICENSE-APACHE": "a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2",
         "asn1-rs-impl-LICENSE-MIT": "a5c61b93b6ee1d104af9920cf020ff3c7efe818e31fe562c72261847a728f513"}


def output(args, cwd=None):
    return subprocess.check_output(args, cwd=cwd, stdin=subprocess.DEVNULL)


def checked(path, digest):
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest.lower():
        raise ValueError(f"Content digest differs for {path.name}")
    return data


def rust_notices(source):
    media = source / "scripts/windows-media-probe"
    graph = json.loads(output(["cargo", "metadata", "--format-version", "1", "--locked", "--offline",
                               "--features", "attended-picker", "--filter-platform", "x86_64-pc-windows-msvc"], media))
    packages = sorted((p for p in graph["packages"] if p["source"]), key=lambda p: (p["name"], p["version"]))
    rust_docs = Path(output(["rustc", "--print", "sysroot"], media).decode().strip()) / "share/doc/rust"
    vcs = {}
    for p in packages:
        d = Path(p["manifest_path"]).parent
        info = d / ".cargo_vcs_info.json"
        if info.is_file():
            vcs[p["id"]] = json.loads(info.read_bytes())["git"]["sha1"]
    sections = []
    for p in packages:
        d = Path(p["manifest_path"]).parent
        docs = []
        for base, _, names in os.walk(d):
            relative = Path(base).relative_to(d)
            license_directory = any(n.lower() in {"license", "licenses", "licences"} for n in relative.parts)
            for name in sorted(names):
                if CRATE_NOTICE.match(name) or license_directory:
                    file = Path(base) / name
                    docs.append((file.relative_to(d).as_posix(), file.read_bytes()))
        declared = p.get("license_file")
        if declared:
            file = (d / declared).resolve()
            if not file.is_relative_to(d.resolve()):
                raise ValueError("Unexpected license file location")
            docs.append((file.name, file.read_bytes()))
        if not docs:
            if p["repository"] == "https://github.com/webrtc-rs/rtc":
                sibling = next(q for q in packages if q["name"] == "rtc" and q["repository"] == p["repository"]
                               and vcs[q["id"]] == vcs[p["id"]])
                for name in ("LICENSE-APACHE", "LICENSE-MIT"):
                    docs.append((name, (Path(sibling["manifest_path"]).parent / name).read_bytes()))
            elif p["name"] == "asn1-rs-impl" and vcs[p["id"]] == "a20e5f7319c896737ad0f2557037817b91ad854f":
                docs.extend((name, checked(HERE / "notices" / name, sha)) for name, sha in EXTRA.items())
            elif p["name"] == "crc32c" and vcs[p["id"]] == "254a861f7cc71bfe455e86f0e1d86e3c83c33390":
                # The crate's upstream README offers Apache-2.0. Include its original wording and full license.
                docs.extend([("README.md", (d / "README.md").read_bytes()),
                             ("Apache-2.0.txt", (rust_docs / "licenses/Apache-2.0.txt").read_bytes())])
            else:
                raise ValueError(f"Inspect missing upstream license for {p['name']} {p['version']}")
        sections.append(f"\n{p['name']} {p['version']} · {p['license']}\n{p['repository'] or ''}\n".encode())
        for label, data in sorted(docs):
            sections.extend((f"\n{label}\n".encode(), data, b"\n"))
    results = {"licenses/rust/Dependencies.txt": b"".join(sections),
               "licenses/rust/COPYRIGHT-library.html": (rust_docs / "COPYRIGHT-library.html").read_bytes()}
    # Ship the links/references accompanying rustc's standard library attribution.
    for file in sorted((rust_docs / "licenses").glob("*.txt")):
        results["licenses/rust/licenses/" + file.name] = file.read_bytes()
    return results, len(packages)


def runtime_files(node_zip, npm_tarball):
    archive = checked(node_zip, NODE_ZIP_SHA)
    base = f"node-v{NODE_VERSION}-win-x64/"
    with zipfile.ZipFile(io.BytesIO(archive)) as node:
        binary = node.read(base + "node.exe")
        if hashlib.sha256(binary).hexdigest() != NODE_EXE_SHA:
            raise ValueError("Node executable differs from the pinned upstream checksum.")
        files = {"runtime/node.exe": binary, f"licenses/Node-{NODE_VERSION}.txt": node.read(base + "LICENSE")}

    lock = json.loads((MEDIA / "package-lock.json").read_bytes())
    dependency = lock["packages"]["node_modules/undici"]
    if dependency["version"] != "8.12.3" or dependency.get("dependencies") or dependency.get("optionalDependencies"):
        raise ValueError("Review the locked runtime dependencies before rebuilding this package.")
    package = npm_tarball.read_bytes()
    if "sha512-" + base64.b64encode(hashlib.sha512(package).digest()).decode() != dependency["integrity"]:
        raise ValueError("Undici archive differs from the npm lock.")
    with tarfile.open(fileobj=io.BytesIO(package), mode="r:gz") as tgz:
        for member in tgz:
            path = PurePosixPath(member.name)
            if not member.isfile() or not path.parts or path.parts[0] != "package" or ".." in path.parts:
                continue
            relative = PurePosixPath(*path.parts[1:]).as_posix()
            if relative in {"index.js", "index-fetch.js", "package.json", "LICENSE"} or relative.startswith("lib/") or CRATE_NOTICE.match(path.name):
                files["app/node_modules/undici/" + relative] = tgz.extractfile(member).read()
    for name in ("index.js", "index-fetch.js", "package.json", "LICENSE"):
        if "app/node_modules/undici/" + name not in files:
            raise ValueError("Incomplete undici distribution.")
    return files


def verify_node(path):
    script = (
        "$s=Get-AuthenticodeSignature -LiteralPath $env:FLYW8T_PACKAGED_NODE; "
        "if($s.Status -ne 'Valid' -or !$s.TimeStamperCertificate -or "
        "$s.SignerCertificate.GetNameInfo('SimpleName',$false) -cne 'OpenJS Foundation'){exit 1}"
    )
    subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                   check=True, env={**os.environ, "FLYW8T_PACKAGED_NODE": str(path)})
    if output([str(path), "--version"]).strip() != f"v{NODE_VERSION}".encode():
        raise ValueError("Unexpected Node version.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sender", type=Path, required=True, help="Authenticode-signed picker-enabled Windows build")
    parser.add_argument("--node-zip", type=Path, required=True)
    parser.add_argument("--undici-tarball", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    version = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))["workspace"]["package"]["version"]
    source_files = ["LICENSE", "Cargo.toml", "scripts/participant-release/Start Flyw8t Participant.cmd",
                    *["scripts/windows-media-probe/" + name for name in APP_FILES]]
    output(["git", "ls-files", "--error-unmatch", "--", *source_files], ROOT)
    subprocess.run(["git", "diff", "--quiet", "HEAD", "--", "scripts/participant-release",
                    "scripts/windows-media-probe", "scripts/windows-capture-probe", "LICENSE", "Cargo.toml"],
                   check=True, cwd=ROOT)
    files = runtime_files(args.node_zip, args.undici_tarball)
    # Verify precisely the bytes to be archived, independently of the input path.
    files["native/flyw8t-participant.exe"] = args.sender.read_bytes()
    with tempfile.TemporaryDirectory() as temporary:
        folder = Path(temporary)
        sender = folder / "flyw8t-participant.exe"
        sender.write_bytes(files["native/flyw8t-participant.exe"])
        subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                        "-File", str(ROOT / "scripts/verify-signature.ps1"), "-Files", str(sender)], check=True)
        # A different signed Flyw8t binary or a sender built without the picker
        # must not pass. EOF refuses the session before any capture can start.
        probe = subprocess.run([str(sender), "--selected-window-console-relay"], input=b"",
                               capture_output=True, timeout=30, cwd=folder)
        if probe.returncode == 0 or b"invalid fixture identity message" not in probe.stderr:
            raise ValueError("Signed binary did not handle the picker-enabled sender protocol.")
        node = folder / "node.exe"
        node.write_bytes(files["runtime/node.exe"])
        verify_node(node)
    for name in APP_FILES:
        files["app/" + name] = (MEDIA / name).read_bytes()
    files["licenses/Flyw8t.txt"] = (ROOT / "LICENSE").read_bytes()
    files["Start Flyw8t Participant.cmd"] = (HERE / "Start Flyw8t Participant.cmd").read_bytes()
    notices, count = rust_notices(ROOT)
    files.update(notices)
    metadata = {"version": version, "revision": output(["git", "rev-parse", "HEAD"], ROOT).decode().strip(),
                "node": NODE_VERSION, "rustDependencyNotices": count}
    files["build.json"] = (json.dumps(metadata, indent=2) + "\n").encode()
    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    destination = output_dir / f"flyw8t-participant-v{version}-x86_64-pc-windows-msvc.zip"
    with zipfile.ZipFile(destination, "x") as archive:
        for name, data in sorted(files.items()):
            entry = zipfile.ZipInfo(name)
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = 0o644 << 16
            archive.writestr(entry, data)
    print(f"{destination.name} ({len(files)} files, {count} Rust dependency notices)")


if __name__ == "__main__":
    main()
