#!/usr/bin/env python3
"""
CryptoChessAssetManager.py
PQC-C10E-R2C Emergency Dispatcher + Direct Launcher

PIAL-T-L:
  PQC Integrated Asset Loader-Tester-Launcher Suite

C10E-R2A adds:
  - Never delegates to old unsafe C9 manager.
  - Bare run opens safe GUI/status only.
  - Supports old cryptochess.sh positional commands directly:
      status
      verify-pqcassets
      verify-assets
      restore-runtime
      restore-runtime-only
  - No hidden return/repack.
  - No hidden launch.
  - Device paths stay private; reports use local/internal names only.\n  - Restores legacy C8/C9 path maps that omit explicit type=file.\n  - Lists virtual internal container contents without exposing device paths.\n  - Adds read-only preview for selected internal text/JSON/MD files.\n  - Adds searchable GUI internal container browser window.\n  - Adds --find filter for CLI container listings.\n  - Adds read-only privacy audit for public-release blockers.\n  - Adds optional explicit export/C10_PRIVACY_AUDIT_REPORT.json writing.\n  - Adds read-only public cleanup plan.\n  - Adds optional explicit export/C10_PUBLIC_CLEANUP_PLAN.json writing.\n  - Adds explicit public assets candidate builder under export/C10_public_candidates/.\n  - Does not replace the active root assets container.\n  - Detects/removes state backups, anchors, chess.crypto backups, and migrated state-container folders.\n  - Adds explicit guarded promotion of a verified public assets candidate.\n  - Adds a public data/README_PUBLIC_STATE.md placeholder so local state can be generated at runtime.\n  - Adds nested PQCZIP audit to detect stale embedded assets/manager files.\n  - Adds fresh C10 public PQCZIP builder under export/C10_public_release/.\n  - Adds direct audit for one PQCZIP candidate.\n  - Adds explicit guarded promotion of fresh public PQCZIP.\n  - Quarantines stale C9 PQCZIP, C9 metadata, and unwrap helper.\n  - Adds final public release doctor and final release report.\n  - Builds final C10E-R1 PQCZIP artifacts.\n  - Adds positional run/launch/launch-game compatibility aliases for wrapper smoke tests.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import struct
import subprocess
import tempfile
import sys
from dataclasses import dataclass, asdict
from typing import Any

MAGIC_PAH1 = b"PAH1"
C10_STAGE = "PQC-C10E-R2C"
APP_NAME = "PIAL-T-L"
APP_TITLE = "CryptoChess PIAL-T-L Asset Manager"

PRIVATE_EXTS = {".key", ".kchain", ".kbch", ".pah2"}
SAFE_PUBLIC_EXTS = {".pqcasset", ".json", ".txt", ".md", ".py", ".sh", ".anchor", ".bchkproof", ".sig", ".pub"}
SUSPICIOUS_NAMES = {"install.key", "cryptochess_hnr_install.key", "state.pah2", "chess.crypto"}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def validate_internal_path(value: str) -> tuple[bool, str]:
    if not isinstance(value, str) or not value.strip():
        return False, "empty path"
    if "\x00" in value:
        return False, "NUL byte in path"
    if value.startswith(("/", "~")):
        return False, "absolute/home path"
    if "\\" in value:
        return False, "backslash/device-style path"
    if len(value) >= 3 and value[1] == ":" and value[2] in ("/", "\\"):
        return False, "drive-letter path"

    p = PurePosixPath(value)
    if p.is_absolute():
        return False, "absolute path"
    if any(part in {"", ".", ".."} for part in p.parts):
        return False, "dot/traversal path"
    if any(part.startswith("~") for part in p.parts):
        return False, "home-like path part"
    return True, "ok"


def safe_rel_to_path(rel: str) -> Path:
    ok, why = validate_internal_path(rel)
    if not ok:
        raise ValueError(f"unsafe internal path {rel!r}: {why}")
    return Path(*PurePosixPath(rel).parts)


def looks_private_name(name: str) -> bool:
    lower = name.lower()
    if lower in SUSPICIOUS_NAMES:
        return True
    if Path(lower).suffix in PRIVATE_EXTS:
        return True
    if "install.key" in lower:
        return True
    if "keychain" in lower:
        return True
    return False


@dataclass
class Pah1EntryInfo:
    name: str
    auth_len: int
    data_len: int
    name_len: int
    sha256: str
    auth_matches_sha256: bool


@dataclass
class Pah1Report:
    file_name: str
    size_bytes: int
    sha256: str
    is_pah1: bool
    version: int | None
    entry_count_declared: int
    valid_entries: int
    invalid_entries: int
    trailing_bytes: int
    container_kind: str
    empty: bool
    path_map_found: bool
    path_map_entries: int
    invalid_internal_paths: int
    private_name_warnings: int
    passed: bool
    warnings: list[str]
    errors: list[str]


class Pah1Container:
    def __init__(self, path: Path):
        self.path = path
        self.raw = path.read_bytes()
        self.entries: dict[str, bytes] = {}
        self.entry_infos: list[Pah1EntryInfo] = []
        self.version: int | None = None
        self.entry_count_declared = 0
        self.trailing_bytes = 0
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def parse(self) -> None:
        raw = self.raw

        if len(raw) < 12 or raw[:4] != MAGIC_PAH1:
            self.errors.append("not PAH1")
            return

        self.version, self.entry_count_declared = struct.unpack_from("<II", raw, 4)

        if self.version != 1:
            self.errors.append(f"unsupported PAH1 version: {self.version}")
            return
        if self.entry_count_declared < 0 or self.entry_count_declared > 100000:
            self.errors.append(f"unsafe entry count: {self.entry_count_declared}")
            return

        pos = 12

        for index in range(self.entry_count_declared):
            if pos + 12 > len(raw):
                self.errors.append(f"truncated entry header at index {index}")
                return

            auth_len, data_len, name_len = struct.unpack_from("<III", raw, pos)
            pos += 12

            if name_len <= 0 or name_len > 65536:
                self.errors.append(f"invalid name length at entry {index}")
                return
            if auth_len <= 0 or auth_len > 65536:
                self.errors.append(f"invalid auth length at entry {index}")
                return

            end = pos + name_len + auth_len + data_len
            if end > len(raw):
                self.errors.append(f"truncated entry payload at index {index}")
                return

            name_b = raw[pos:pos + name_len]
            pos += name_len

            if b"\x00" in name_b:
                self.errors.append(f"NUL filename at entry {index}")
                return

            try:
                name = name_b.decode("utf-8")
            except UnicodeDecodeError:
                self.errors.append(f"non-UTF8 filename at entry {index}")
                return

            auth = raw[pos:pos + auth_len]
            pos += auth_len

            data = raw[pos:pos + data_len]
            pos += data_len

            if name in self.entries:
                self.errors.append(f"duplicate entry name: {name}")
                return

            data_sha = sha256_bytes(data)
            auth_matches = auth == data_sha.encode("ascii")

            # C8/C9 readme legacy containers used the auth field differently.
            # In C10A this is a warning only. C10B/C10C add real signed manifests.
            if not auth_matches:
                self.warnings.append(f"legacy auth/hash mismatch: {name}")

            ok_path, why = validate_internal_path(name)
            if not ok_path:
                self.warnings.append(f"entry name path warning: {name!r}: {why}")

            if looks_private_name(name):
                self.warnings.append(f"private-looking entry name: {name}")

            self.entries[name] = data
            self.entry_infos.append(Pah1EntryInfo(
                name=name,
                auth_len=auth_len,
                data_len=data_len,
                name_len=name_len,
                sha256=data_sha,
                auth_matches_sha256=auth_matches,
            ))

        self.trailing_bytes = len(raw) - pos
        if self.trailing_bytes != 0:
            self.errors.append(f"trailing bytes: {self.trailing_bytes}")

    def ensure_parsed(self) -> None:
        if not self.entries and not self.errors and self.entry_count_declared == 0:
            self.parse()

    def detect_kind(self) -> str:
        lower = self.path.name.lower()
        if self.raw[:4] != MAGIC_PAH1:
            return "not-pqcasset"
        if self.entry_count_declared == 0:
            return "empty-pqcasset"
        if lower.startswith("pqczip_"):
            return "vanity-pqczip" if "vanity" in lower else "pqczip"
        if any(name.lower() == "c9_package_path_map.json" for name in self.entries):
            return "vanity-pqczip" if "vanity" in lower else "pqczip"
        if "vanity" in lower:
            return "vanity-pqcasset"
        return "pqcasset"

    def path_map_names(self) -> list[str]:
        self.ensure_parsed()
        return [n for n in self.entries if "path_map" in n.lower() and n.lower().endswith(".json")]

    def load_path_map(self) -> tuple[str, dict[str, Any]]:
        self.ensure_parsed()
        candidates = self.path_map_names()
        if not candidates:
            raise ValueError("path map not found")

        last_error = None
        for name in candidates:
            try:
                payload = json.loads(self.entries[name].decode("utf-8"))
                if isinstance(payload, dict) and isinstance(payload.get("entries"), list):
                    return name, payload
            except Exception as exc:
                last_error = exc

        raise ValueError(f"path map unreadable: {last_error}")

    def inspect_path_maps(self) -> tuple[int, int, int]:
        path_map_entries = 0
        invalid_internal_paths = 0
        private_warnings = 0

        for name in self.path_map_names():
            try:
                payload = json.loads(self.entries[name].decode("utf-8"))
            except Exception:
                self.warnings.append(f"path map unreadable: {name}")
                continue

            entries = payload.get("entries")
            if not isinstance(entries, list):
                continue

            for item in entries:
                if not isinstance(item, dict):
                    continue

                rel = item.get("relative_path")
                encoded = item.get("encoded_name")

                if isinstance(rel, str):
                    path_map_entries += 1
                    ok, why = validate_internal_path(rel)
                    if not ok:
                        invalid_internal_paths += 1
                        self.errors.append(f"invalid path-map path: {rel!r}: {why}")
                    if looks_private_name(rel):
                        private_warnings += 1
                        self.warnings.append(f"private-looking path-map path: {rel}")

                if isinstance(encoded, str) and encoded not in self.entries:
                    self.errors.append(f"path map references missing encoded entry: {encoded}")

        return path_map_entries, invalid_internal_paths, private_warnings

    def report(self) -> Pah1Report:
        self.parse()
        is_pah1 = len(self.raw) >= 4 and self.raw[:4] == MAGIC_PAH1
        kind = self.detect_kind() if is_pah1 else "not-pqcasset"
        path_map_found = bool(self.path_map_names()) if is_pah1 else False
        pm_entries, invalid_paths, private_warnings = self.inspect_path_maps() if is_pah1 else (0, 0, 0)

        valid_entries = sum(1 for e in self.entry_infos if e.auth_matches_sha256)
        invalid_entries = len(self.entry_infos) - valid_entries

        passed = is_pah1 and not self.errors and self.trailing_bytes == 0

        return Pah1Report(
            file_name=self.path.name,
            size_bytes=self.path.stat().st_size,
            sha256=sha256_file(self.path),
            is_pah1=is_pah1,
            version=self.version,
            entry_count_declared=self.entry_count_declared,
            valid_entries=valid_entries,
            invalid_entries=invalid_entries,
            trailing_bytes=self.trailing_bytes,
            container_kind=kind,
            empty=(self.entry_count_declared == 0),
            path_map_found=path_map_found,
            path_map_entries=pm_entries,
            invalid_internal_paths=invalid_paths,
            private_name_warnings=private_warnings,
            passed=passed,
            warnings=self.warnings,
            errors=self.errors,
        )


def extract_container(container_path: Path, output_dir: Path, clean: bool = True) -> dict[str, Any]:
    pc = Pah1Container(container_path)
    pc.parse()

    if pc.errors:
        return {
            "container": container_path.name,
            "output_dir": output_dir.as_posix(),
            "passed": False,
            "extract_passed": False,
            "errors": pc.errors,
        }

    try:
        _pm_name, path_map = pc.load_path_map()
    except Exception as exc:
        return {
            "container": container_path.name,
            "output_dir": output_dir.as_posix(),
            "passed": False,
            "extract_passed": False,
            "errors": [str(exc)],
        }

    if clean and output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    restored = 0
    invalid_paths = 0
    missing_encoded = 0
    hash_mismatch = 0

    for item in path_map.get("entries", []):
        if not isinstance(item, dict):
            continue

        typ = item.get("type")
        rel = item.get("relative_path")
        encoded = item.get("encoded_name")

        # C8/C9 inner path maps often omit "type".
        # If encoded_name exists, this is a file payload.
        # If encoded_name is absent, treat it as a directory entry.
        if typ is None:
            typ = "file" if isinstance(encoded, str) else "dir"

        if not isinstance(rel, str):
            invalid_paths += 1
            continue

        try:
            target_rel = safe_rel_to_path(rel)
        except Exception:
            invalid_paths += 1
            continue

        target = output_dir / target_rel

        if typ == "dir":
            target.mkdir(parents=True, exist_ok=True)
            continue

        if typ != "file":
            continue

        if not isinstance(encoded, str) or encoded not in pc.entries:
            missing_encoded += 1
            continue

        data = pc.entries[encoded]
        expected_sha = item.get("sha256")
        if isinstance(expected_sha, str) and expected_sha and sha256_bytes(data) != expected_sha:
            hash_mismatch += 1
            continue

        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

        mode = item.get("mode")
        if isinstance(mode, str) and mode:
            try:
                os.chmod(target, int(mode, 8))
            except Exception:
                pass

        restored += 1

    passed = invalid_paths == 0 and missing_encoded == 0 and hash_mismatch == 0 and restored > 0

    return {
        "role": infer_role(container_path.name),
        "container": container_path.name,
        "output_dir": output_dir.as_posix(),
        "native_loader": True,
        "passed": passed,
        "extract_passed": passed,
        "entry_count_declared": pc.entry_count_declared,
        "valid_entries": len(pc.entry_infos),
        "invalid_entries": 0,
        "skipped_encrypted": 0,
        "restored_flat_files": len(pc.entry_infos),
        "trailing_bytes": pc.trailing_bytes,
        "path_map_found": True,
        "entry_count": len(path_map.get("entries", [])),
        "restored": restored,
        "invalid_paths": invalid_paths,
        "missing_encoded": missing_encoded,
        "hash_mismatch": hash_mismatch,
    }


def infer_role(name: str) -> str:
    lower = name.lower()
    if "core" in lower:
        return "core"
    if "assets" in lower:
        return "assets"
    if "readme" in lower or "docs" in lower:
        return "readme"
    if "state" in lower:
        return "state"
    if "key" in lower or "kchain" in lower or lower.endswith(".kbch"):
        return "keychain"
    if "proof" in lower or lower.endswith(".bchkproof"):
        return "proof"
    if lower.startswith("pqczip_"):
        return "outer"
    if lower.endswith(".json") and "manifest" in lower:
        return "manifest"
    if lower.endswith(".json") and "seal" in lower:
        return "seal"
    if lower.endswith(".txt") and "sha256" in lower:
        return "sha256"
    if lower == "cryptochess.sh":
        return "launcher"
    if lower == "cryptochessassetmanager.py":
        return "manager"
    return "unknown"


def find_role_container(role: str) -> Path | None:
    matches = sorted(Path(".").glob(f"3Dx9_{role}_*.pqcasset"))
    return matches[0] if matches else None


def marker_for(kind: str, warning: str) -> str:
    if warning:
        return "red *"
    return {
        "pqcasset": "green !",
        "empty-pqcasset": "yellow !",
        "pqczip": "black !",
        "vanity-pqcasset": "blue !",
        "vanity-pqczip": "teal !",
        "release-file": "gray !",
        "script": "gray !",
        "manager": "purple !",
        "private": "orange *",
        "strange": "red *",
        "not-pqcasset": "red !",
    }.get(kind, "gray !")



@dataclass
class VirtualEntry:
    internal_path: str
    parent: str
    name: str
    type: str
    size_bytes: int
    sha256: str | None
    encoded_name: str | None
    role: str
    marker: str
    warning: str


TEXT_PREVIEW_EXTS = {".txt", ".md", ".json", ".py", ".sh", ".guide", ".help", ".tldr", ".list", ".lore", ".csv"}


def virtual_marker_for(entry_type: str, warning: str) -> str:
    if warning:
        return "red *"
    if entry_type == "dir":
        return "gray /"
    return "green file"


def virtual_entries_for_container(container_path: Path) -> tuple[list[VirtualEntry], list[str], list[str]]:
    """
    Return portable virtual contents of a PAH1/PQCAsset container.

    This function never returns device paths. It returns only internal paths.
    """
    pc = Pah1Container(container_path)
    pc.parse()

    if pc.errors:
        return [], pc.warnings, pc.errors

    role = infer_role(container_path.name)
    out: list[VirtualEntry] = []
    errors: list[str] = []
    warnings: list[str] = list(pc.warnings)

    # Preferred path-map mode.
    try:
        _pm_name, path_map = pc.load_path_map()
        entries = path_map.get("entries", [])

        for item in entries:
            if not isinstance(item, dict):
                continue

            rel = item.get("relative_path")
            encoded = item.get("encoded_name")
            typ = item.get("type")

            if typ is None:
                typ = "file" if isinstance(encoded, str) else "dir"

            if not isinstance(rel, str):
                warnings.append("path-map entry missing relative_path")
                continue

            ok, why = validate_internal_path(rel)
            warning = ""
            if not ok:
                warning = f"invalid internal path: {why}"
            elif looks_private_name(rel):
                warning = "private-looking internal name"

            rel_posix = PurePosixPath(rel)
            parent = rel_posix.parent.as_posix()
            if parent == ".":
                parent = ""

            data = b""
            sha = None
            size = 0

            if typ == "file":
                if not isinstance(encoded, str):
                    warning = warning or "file entry missing encoded_name"
                elif encoded not in pc.entries:
                    warning = warning or "encoded payload missing"
                else:
                    data = pc.entries[encoded]
                    size = len(data)
                    sha = sha256_bytes(data)

            out.append(VirtualEntry(
                internal_path=rel,
                parent=parent,
                name=rel_posix.name,
                type=str(typ),
                size_bytes=size,
                sha256=sha,
                encoded_name=encoded if isinstance(encoded, str) else None,
                role=role,
                marker=virtual_marker_for(str(typ), warning),
                warning=warning,
            ))

        return out, warnings, errors

    except Exception as exc:
        warnings.append(f"path-map listing fallback: {exc}")

    # Fallback for older or unusual containers.
    for name, data in sorted(pc.entries.items(), key=lambda kv: kv[0].lower()):
        ok, why = validate_internal_path(name)
        warning = ""
        if not ok:
            warning = f"encoded/raw entry name only: {why}"
        elif looks_private_name(name):
            warning = "private-looking internal name"

        rel_posix = PurePosixPath(name)
        parent = rel_posix.parent.as_posix()
        if parent == ".":
            parent = ""

        out.append(VirtualEntry(
            internal_path=name,
            parent=parent,
            name=rel_posix.name,
            type="raw-entry",
            size_bytes=len(data),
            sha256=sha256_bytes(data),
            encoded_name=name,
            role=role,
            marker=virtual_marker_for("file", warning),
            warning=warning,
        ))

    return out, warnings, errors


def print_container_listing(file_name: str, limit: int = 500, find: str = "") -> int:
    path = Path(file_name)
    if not path.exists():
        print(json.dumps({"passed": False, "error": "file not found", "file_name": path.name}, indent=2))
        return 2

    entries, warnings, errors = virtual_entries_for_container(path)
    original_count = len(entries)

    if find:
        q = find.lower().strip()
        entries = [
            e for e in entries
            if q in e.internal_path.lower()
            or q in e.name.lower()
            or q in e.parent.lower()
            or q in e.role.lower()
            or q in e.type.lower()
            or q in e.marker.lower()
            or q in e.warning.lower()
        ]

    passed = not errors

    print(json.dumps({
        "tool": APP_NAME,
        "stage": C10_STAGE,
        "container": path.name,
        "privacy": "device paths redacted; listing uses internal paths only",
        "entry_count": original_count,
        "matching_count": len(entries),
        "shown": min(len(entries), limit),
        "find": find,
        "passed": passed,
        "warnings": warnings[:20],
        "errors": errors,
        "entries": [asdict(e) for e in entries[:limit]],
    }, indent=2, sort_keys=True))

    return 0 if passed else 1



def read_internal_payload(container_path: Path, internal_path: str) -> tuple[bytes, str]:
    """
    Read one internal payload without extracting to disk.

    Returns:
      data, encoded_name

    Raises ValueError on unsafe path, missing payload, or parse failure.
    """
    ok, why = validate_internal_path(internal_path)
    if not ok:
        raise ValueError(f"unsafe internal path: {why}")

    pc = Pah1Container(container_path)
    pc.parse()

    if pc.errors:
        raise ValueError("; ".join(pc.errors))

    try:
        _pm_name, path_map = pc.load_path_map()
        for item in path_map.get("entries", []):
            if not isinstance(item, dict):
                continue
            if item.get("relative_path") == internal_path:
                enc = item.get("encoded_name")
                if isinstance(enc, str) and enc in pc.entries:
                    return pc.entries[enc], enc
                raise ValueError("internal path exists but encoded payload is missing")
    except Exception:
        if internal_path in pc.entries:
            return pc.entries[internal_path], internal_path

    raise ValueError("internal path not found")

def preview_internal_file(file_name: str, internal_path: str, max_bytes: int = 12000) -> int:
    """
    Read-only preview for one internal text-like file.

    Does not extract to disk. Does not reveal device paths.
    """
    container = Path(file_name)
    if not container.exists():
        print(json.dumps({"passed": False, "error": "container not found", "container": container.name}, indent=2))
        return 2

    ok, why = validate_internal_path(internal_path)
    if not ok:
        print(json.dumps({
            "passed": False,
            "error": "unsafe internal path",
            "internal_path": internal_path,
            "reason": why,
        }, indent=2))
        return 2

    pc = Pah1Container(container)
    pc.parse()

    if pc.errors:
        print(json.dumps({"passed": False, "errors": pc.errors, "container": container.name}, indent=2))
        return 1

    target_data = None
    encoded_name = None

    try:
        _pm_name, path_map = pc.load_path_map()
        for item in path_map.get("entries", []):
            if not isinstance(item, dict):
                continue
            if item.get("relative_path") == internal_path:
                enc = item.get("encoded_name")
                if isinstance(enc, str) and enc in pc.entries:
                    target_data = pc.entries[enc]
                    encoded_name = enc
                break
    except Exception:
        # Fallback: direct raw entry name.
        if internal_path in pc.entries:
            target_data = pc.entries[internal_path]
            encoded_name = internal_path

    if target_data is None:
        print(json.dumps({
            "passed": False,
            "error": "internal path not found or not previewable",
            "container": container.name,
            "internal_path": internal_path,
        }, indent=2))
        return 1

    suffix = PurePosixPath(internal_path).suffix.lower()
    preview_allowed = suffix in TEXT_PREVIEW_EXTS

    if not preview_allowed:
        print(json.dumps({
            "passed": False,
            "error": "binary or unsupported preview type",
            "container": container.name,
            "internal_path": internal_path,
            "size_bytes": len(target_data),
            "sha256": sha256_bytes(target_data),
            "hint": "Use listing/hash for binary files. Extraction workflow comes in a later C10 stage.",
        }, indent=2))
        return 1

    sample = target_data[:max_bytes]
    try:
        text = sample.decode("utf-8", errors="replace")
    except Exception:
        text = repr(sample)

    print(json.dumps({
        "tool": APP_NAME,
        "stage": C10_STAGE,
        "container": container.name,
        "internal_path": internal_path,
        "encoded_name": encoded_name,
        "size_bytes": len(target_data),
        "sha256": sha256_bytes(target_data),
        "truncated": len(target_data) > max_bytes,
        "privacy": "device path redacted; internal path only",
        "preview": text,
        "passed": True,
    }, indent=2, sort_keys=True))

    return 0



@dataclass
class PrivacyFinding:
    severity: str
    category: str
    file_name: str | None
    container: str | None
    internal_path: str | None
    reason: str
    public_release_blocker: bool


def classify_privacy_name(name: str, *, internal: bool) -> tuple[str | None, str, bool]:
    """
    Classify privacy risk from a portable name/internal path only.

    Returns:
      severity, reason, public_release_blocker

    severity:
      None | info | warning | blocker
    """
    lower = name.lower()
    suffix = PurePosixPath(lower).suffix if internal else Path(lower).suffix

    if internal:
        ok, why = validate_internal_path(name)
        if not ok:
            return "blocker", f"invalid internal path: {why}", True

    # Strong local-state / secret detection.
    normalized = lower.rstrip("/")
    posix_parts = set(PurePosixPath(normalized).parts)

    if "chess.crypto" in normalized:
        return "blocker", "persistent chess.crypto history/state file or backup", True

    if ".cryptochess_state_workspace" in posix_parts:
        return "blocker", "local state workspace must not be included in public release assets", True

    if "cryptochess.state.pqcasset" in posix_parts:
        return "blocker", "migrated local state container folder must not be included in public release assets", True

    if normalized.endswith(".bak"):
        base = normalized
        while base.endswith(".bak"):
            base = base[:-4]
        if "chess.crypto" in base:
            return "blocker", "persistent chess.crypto backup", True
        if base.endswith(".pah2") and ("state" in base or "identity" in base or "install" in base):
            return "blocker", "private/local PAH2 state backup", True
        if base.endswith(".key") or "install.key" in base:
            return "blocker", "private key/install-key backup", True
        if base.endswith(".anchor") and ("state" in base or "upgrade" in base or "install" in base):
            return "blocker", "local state/upgrade anchor backup", True

    if normalized.endswith(".anchor") and ("state" in normalized or "upgrade" in normalized or "install" in normalized):
        return "blocker", "local state/upgrade/install anchor must be generated locally", True

    if normalized in {"chess.crypto", "state.pah2", "install.key", "cryptochess_hnr_install.key"}:
        return "blocker", "private/local runtime identity or state filename", True

    if "install.key" in normalized:
        return "blocker", "install key must not be included in public release assets", True

    if suffix in {".key", ".kchain", ".kbch"}:
        return "blocker", "private key/keychain-style file", True

    if suffix == ".pah2":
        if "state" in normalized or "identity" in normalized or "user" in normalized or "install" in normalized:
            return "blocker", "private/local PAH2 state or identity-like file", True
        return "warning", "PAH2 file requires review before public release", False

    sensitive_terms = [
        "username",
        "user_name",
        "login_name",
        "hostname",
        "device_path",
        "local_path",
        "home_path",
        "private_key",
        "secret",
    ]

    for term in sensitive_terms:
        if term in lower:
            return "warning", f"sensitive term in name: {term}", False

    return None, "", False


def make_privacy_finding(
    *,
    severity: str,
    category: str,
    reason: str,
    file_name: str | None = None,
    container: str | None = None,
    internal_path: str | None = None,
    public_release_blocker: bool = False,
) -> PrivacyFinding:
    return PrivacyFinding(
        severity=severity,
        category=category,
        file_name=file_name,
        container=container,
        internal_path=internal_path,
        reason=reason,
        public_release_blocker=public_release_blocker,
    )


def audit_container_privacy(container_name: str) -> tuple[list[PrivacyFinding], dict[str, Any]]:
    path = Path(container_name)
    findings: list[PrivacyFinding] = []

    if not path.exists():
        findings.append(make_privacy_finding(
            severity="blocker",
            category="missing-container",
            file_name=path.name,
            reason="container file not found",
            public_release_blocker=True,
        ))
        return findings, {"container": path.name, "passed": False, "error": "missing container"}

    if path.suffix.lower() != ".pqcasset":
        findings.append(make_privacy_finding(
            severity="blocker",
            category="wrong-file-type",
            file_name=path.name,
            reason="audit-container expects a .pqcasset file",
            public_release_blocker=True,
        ))
        return findings, {"container": path.name, "passed": False, "error": "not pqcasset"}

    entries, warnings, errors = virtual_entries_for_container(path)

    for warning in warnings:
        if "private-looking" in warning.lower():
            findings.append(make_privacy_finding(
                severity="warning",
                category="container-warning",
                container=path.name,
                reason=warning,
                public_release_blocker=False,
            ))

    for error in errors:
        findings.append(make_privacy_finding(
            severity="blocker",
            category="container-error",
            container=path.name,
            reason=error,
            public_release_blocker=True,
        ))

    for e in entries:
        severity, reason, blocker = classify_privacy_name(e.internal_path, internal=True)
        if severity:
            findings.append(make_privacy_finding(
                severity=severity,
                category="internal-path",
                container=path.name,
                internal_path=e.internal_path,
                reason=reason,
                public_release_blocker=blocker,
            ))

        # The encoded name is not a user path, but it can still expose private type names.
        if e.encoded_name:
            enc_severity, enc_reason, enc_blocker = classify_privacy_name(e.encoded_name, internal=False)
            if enc_severity in {"blocker", "warning"}:
                findings.append(make_privacy_finding(
                    severity=enc_severity,
                    category="encoded-entry-name",
                    container=path.name,
                    internal_path=e.internal_path,
                    reason=f"{enc_reason}; encoded payload name contains sensitive type marker",
                    public_release_blocker=enc_blocker,
                ))

    blocker_count = sum(1 for f in findings if f.public_release_blocker)
    warning_count = sum(1 for f in findings if f.severity == "warning")

    summary = {
        "container": path.name,
        "entry_count": len(entries),
        "finding_count": len(findings),
        "blocker_count": blocker_count,
        "warning_count": warning_count,
        "public_release_ready": blocker_count == 0,
        "passed": not errors,
        "privacy": "device paths redacted; internal paths only",
    }

    return findings, summary


def audit_root_privacy() -> dict[str, Any]:
    findings: list[PrivacyFinding] = []
    container_summaries: list[dict[str, Any]] = []

    items = scan_directory(Path.cwd())

    for item in items:
        severity, reason, blocker = classify_privacy_name(item.name, internal=False)
        if severity:
            findings.append(make_privacy_finding(
                severity=severity,
                category="root-file-name",
                file_name=item.name,
                reason=reason,
                public_release_blocker=blocker,
            ))

        if item.kind == "private":
            findings.append(make_privacy_finding(
                severity="blocker",
                category="root-private-file",
                file_name=item.name,
                reason="private file type found in public root",
                public_release_blocker=True,
            ))

        if item.name.lower().endswith(".pqcasset"):
            c_findings, c_summary = audit_container_privacy(item.name)
            findings.extend(c_findings)
            container_summaries.append(c_summary)

    blocker_count = sum(1 for f in findings if f.public_release_blocker)
    warning_count = sum(1 for f in findings if f.severity == "warning")
    info_count = sum(1 for f in findings if f.severity == "info")

    report = {
        "tool": APP_NAME,
        "stage": C10_STAGE,
        "created_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "audit": "privacy",
        "privacy_policy": {
            "device_paths_exported": False,
            "public_report_paths": "file names and portable internal container paths only",
            "absolute_paths_allowed": False,
            "home_paths_allowed": False,
            "path_traversal_allowed": False,
            "private_keys_allowed_in_public_release": False,
            "install_keys_allowed_in_public_release": False,
            "local_state_allowed_in_public_release": False,
        },
        "summary": {
            "finding_count": len(findings),
            "blocker_count": blocker_count,
            "warning_count": warning_count,
            "info_count": info_count,
            "container_count": len(container_summaries),
            "public_release_ready": blocker_count == 0,
        },
        "container_summaries": container_summaries,
        "findings": [asdict(f) for f in findings],
    }

    return report


def write_privacy_report(report: dict[str, Any]) -> str:
    export_dir = Path("export")
    export_dir.mkdir(exist_ok=True)
    out = export_dir / "C10_PRIVACY_AUDIT_REPORT.json"
    out.write_text(json.dumps(report, indent=2, sort_keys=True))
    return out.as_posix()


def print_audit_privacy(*, write_report: bool = False, strict_public: bool = False) -> int:
    report = audit_root_privacy()

    if write_report:
        report["written_report"] = write_privacy_report(report)

    print(json.dumps(report, indent=2, sort_keys=True))

    ready = bool(report.get("summary", {}).get("public_release_ready"))
    if strict_public and not ready:
        return 1
    return 0


def print_audit_container(file_name: str, *, write_report: bool = False, strict_public: bool = False) -> int:
    findings, summary = audit_container_privacy(file_name)
    report = {
        "tool": APP_NAME,
        "stage": C10_STAGE,
        "created_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "audit": "container-privacy",
        "summary": summary,
        "findings": [asdict(f) for f in findings],
        "privacy": "device paths redacted; internal paths only",
    }

    if write_report:
        export_dir = Path("export")
        export_dir.mkdir(exist_ok=True)
        safe_stem = Path(file_name).name.replace("/", "_").replace("\\", "_")
        out = export_dir / f"C10_PRIVACY_AUDIT_{safe_stem}.json"
        out.write_text(json.dumps(report, indent=2, sort_keys=True))
        report["written_report"] = out.as_posix()

    print(json.dumps(report, indent=2, sort_keys=True))

    ready = bool(summary.get("public_release_ready"))
    if strict_public and not ready:
        return 1
    return 0



@dataclass
class CleanupAction:
    action: str
    target_type: str
    file_name: str | None
    container: str | None
    internal_path: str | None
    reason: str
    risk: str
    mutates: bool
    later_stage: str


def is_public_root_ignored_dir(name: str) -> tuple[bool, str]:
    lower = name.lower()

    ignored = {
        ".cryptochess_runtime": "runtime checkout/cache; must not be included in public release",
        "c9_build": "development/build folder; must not be included in public release",
        "c10_safety_backups": "local safety backups; must not be included in public release",
        "__pycache__": "python cache folder",
        ".pytest_cache": "test cache folder",
        ".git": "git metadata; release package should not embed repository internals",
    }

    if lower in ignored:
        return True, ignored[lower]

    if lower.startswith("c9_build"):
        return True, "development/build folder; must not be included in public release"

    if lower.startswith("c10_") and "backup" in lower:
        return True, "local C10 backup folder; must not be included in public release"

    return False, ""


def plan_public_cleanup() -> dict[str, Any]:
    """
    Read-only public release cleanup planner.

    This function does not mutate anything. It reports:
      - root files/dirs that must be excluded
      - internal container files that should be removed/replaced later
      - recommended later action stages
    """
    actions: list[CleanupAction] = []
    audit = audit_root_privacy()

    # Root directory/file review.
    for child in sorted(Path.cwd().iterdir(), key=lambda x: x.name.lower()):
        name = child.name

        # Device paths are not recorded. Only local file/folder names are used.
        if child.is_dir():
            ignored, reason = is_public_root_ignored_dir(name)
            if ignored:
                actions.append(CleanupAction(
                    action="exclude-from-public-release",
                    target_type="root-directory",
                    file_name=name,
                    container=None,
                    internal_path=None,
                    reason=reason,
                    risk="public-release-leak/noise",
                    mutates=False,
                    later_stage="C10C-apply-cleanup",
                ))
            continue

        severity, reason, blocker = classify_privacy_name(name, internal=False)
        if blocker:
            actions.append(CleanupAction(
                action="remove-or-exclude-root-file",
                target_type="root-file",
                file_name=name,
                container=None,
                internal_path=None,
                reason=reason,
                risk="private-local-secret-or-state",
                mutates=False,
                later_stage="C10C-apply-cleanup",
            ))

        if name in {"unwrap_pqczip_outer.py"}:
            actions.append(CleanupAction(
                action="exclude-from-final-public-surface",
                target_type="root-file",
                file_name=name,
                container=None,
                internal_path=None,
                reason="developer/bootstrap helper; final public surface should rely on PIAL-T-L manager",
                risk="release-surface-noise",
                mutates=False,
                later_stage="C10C-apply-cleanup",
            ))

        if name.startswith("CryptoChess_2.0.0-rc1_C9I_R2_FINAL_STANDALONE_"):
            actions.append(CleanupAction(
                action="move-to-release-metadata-or-replace",
                target_type="root-file",
                file_name=name,
                container=None,
                internal_path=None,
                reason="C9I-R2 metadata should be superseded by C10 signed release metadata",
                risk="outdated-release-metadata",
                mutates=False,
                later_stage="C10D-signed-manifest",
            ))

    # Container internal cleanup recommendations.
    for summary in audit.get("container_summaries", []):
        container = summary.get("container")
        if not isinstance(container, str):
            continue

        if not container.endswith(".pqcasset"):
            continue

        findings = [
            f for f in audit.get("findings", [])
            if f.get("container") == container
            and f.get("internal_path")
            and f.get("public_release_blocker")
        ]

        # De-duplicate internal blocker paths.
        blocker_paths = sorted({str(f["internal_path"]) for f in findings})

        for internal_path in blocker_paths:
            lower = internal_path.lower()

            if lower.endswith("cryptochess_hnr_install.key") or "install.key" in lower:
                action = "remove-internal-file-and-repack-container"
                reason = "install key is local/private and must be generated on user device after launch/diagnostics"
                risk = "private-install-key-leak"
            elif "chess.crypto" in lower:
                action = "remove-internal-file-and-repack-container"
                reason = "chess.crypto history/state backup is local runtime data and must not ship publicly"
                risk = "private-state-leak"
            elif "cryptochess.state.pqcasset" in lower:
                action = "remove-migrated-state-container-entry"
                reason = "migrated local state-container folder must not ship in public assets"
                risk = "private-state-leak"
            elif lower.endswith(".anchor") or ".anchor.bak" in lower:
                action = "remove-internal-file-and-repack-container"
                reason = "state/upgrade anchor is local runtime binding data and must be regenerated locally"
                risk = "private-state-leak"
            elif (lower.endswith(".pah2") or ".pah2.bak" in lower) and ("state" in lower or "identity" in lower):
                action = "remove-or-replace-with-local-template"
                reason = "state/identity PAH2 is local runtime data and must not be shipped as public user state"
                risk = "private-state-leak"
            else:
                action = "review-and-remove-internal-file"
                reason = "privacy audit marked this internal path as public-release blocker"
                risk = "privacy-blocker"

            actions.append(CleanupAction(
                action=action,
                target_type="container-internal-file",
                file_name=None,
                container=container,
                internal_path=internal_path,
                reason=reason,
                risk=risk,
                mutates=False,
                later_stage="C10C-apply-cleanup",
            ))

    # Non-blocking review recommendations for PAH2 assets.
    for item in scan_directory(Path.cwd()):
        if not item.name.endswith(".pqcasset"):
            continue

        try:
            entries, _warnings, _errors = virtual_entries_for_container(Path(item.name))
        except Exception:
            continue

        for e in entries:
            lower = e.internal_path.lower()
            if lower.endswith(".pah2") and not ("state" in lower or "identity" in lower):
                actions.append(CleanupAction(
                    action="review-pah2-before-public-release",
                    target_type="container-internal-file",
                    file_name=None,
                    container=item.name,
                    internal_path=e.internal_path,
                    reason="PAH2 asset may be valid, but should be reviewed/classified before C10 public release",
                    risk="format-review",
                    mutates=False,
                    later_stage="C10C-review",
                ))

    blocker_actions = [
        a for a in actions
        if a.risk in {
            "private-install-key-leak",
            "private-state-leak",
            "private-local-secret-or-state",
            "privacy-blocker",
        }
    ]

    report = {
        "tool": APP_NAME,
        "stage": C10_STAGE,
        "created_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "plan": "public-release-cleanup",
        "dry_run": True,
        "mutates": False,
        "privacy": "device paths redacted; only root names and internal container paths are shown",
        "summary": {
            "action_count": len(actions),
            "blocker_action_count": len(blocker_actions),
            "public_release_ready_now": audit.get("summary", {}).get("public_release_ready", False),
            "requires_later_apply_stage": len(blocker_actions) > 0,
        },
        "recommended_order": [
            "Review this dry-run plan.",
            "Remove/replace internal private state and install-key entries from assets container in a later explicit apply stage.",
            "Repack assets container only after review.",
            "Re-run privacy audit.",
            "Create C10 signed release manifest.",
            "Only then build final public PQCZIP.",
        ],
        "actions": [asdict(a) for a in actions],
        "source_audit_summary": audit.get("summary", {}),
    }

    return report


def write_cleanup_plan(report: dict[str, Any]) -> str:
    export_dir = Path("export")
    export_dir.mkdir(exist_ok=True)
    out = export_dir / "C10_PUBLIC_CLEANUP_PLAN.json"
    out.write_text(json.dumps(report, indent=2, sort_keys=True))
    return out.as_posix()


def print_cleanup_plan(*, write_report: bool = False, strict_public: bool = False) -> int:
    report = plan_public_cleanup()

    if write_report:
        report["written_report"] = write_cleanup_plan(report)

    print(json.dumps(report, indent=2, sort_keys=True))

    ready = bool(report.get("summary", {}).get("public_release_ready_now"))
    if strict_public and not ready:
        return 1
    return 0



def write_pah1_bytes(entries: list[tuple[str, bytes]]) -> bytes:
    """
    Build PAH1 bytes using C9/C10 structural auth placeholder:
      auth field = ASCII SHA256(data)

    Real signed manifest verification comes later in C10D.
    """
    out = bytearray()
    out.extend(MAGIC_PAH1)
    out.extend((1).to_bytes(4, "little"))
    out.extend(len(entries).to_bytes(4, "little"))

    seen: set[str] = set()

    for name, data in entries:
        if name in seen:
            raise ValueError(f"duplicate entry: {name}")
        seen.add(name)

        ok, why = validate_internal_path(name)
        if not ok:
            raise ValueError(f"unsafe PAH1 entry name {name!r}: {why}")

        name_b = name.encode("utf-8")
        auth_b = sha256_bytes(data).encode("ascii")

        out.extend(len(auth_b).to_bytes(4, "little"))
        out.extend(len(data).to_bytes(4, "little"))
        out.extend(len(name_b).to_bytes(4, "little"))
        out.extend(name_b)
        out.extend(auth_b)
        out.extend(data)

    return bytes(out)


def object_contains_any_string(obj: Any, needles: set[str]) -> bool:
    if isinstance(obj, str):
        return any(n in obj for n in needles)
    if isinstance(obj, list):
        return any(object_contains_any_string(x, needles) for x in obj)
    if isinstance(obj, dict):
        return any(
            object_contains_any_string(k, needles) or object_contains_any_string(v, needles)
            for k, v in obj.items()
        )
    return False


def prune_json_references(obj: Any, needles: set[str]) -> tuple[Any, int]:
    """
    Conservative manifest scrubber.

    Removes list items or dict children that reference removed internal paths
    or removed encoded names. This is used only for generated public candidate
    metadata, not for active runtime files.
    """
    removed = 0

    if isinstance(obj, list):
        new_list = []
        for item in obj:
            if object_contains_any_string(item, needles):
                removed += 1
                continue
            cleaned, sub_removed = prune_json_references(item, needles)
            removed += sub_removed
            new_list.append(cleaned)
        return new_list, removed

    if isinstance(obj, dict):
        new_dict = {}
        for k, v in obj.items():
            if object_contains_any_string(k, needles):
                removed += 1
                continue
            if object_contains_any_string(v, needles) and isinstance(v, (dict, list)):
                cleaned, sub_removed = prune_json_references(v, needles)
                removed += sub_removed
                new_dict[k] = cleaned
                continue
            if isinstance(v, str) and any(n in v for n in needles):
                removed += 1
                continue
            cleaned, sub_removed = prune_json_references(v, needles)
            removed += sub_removed
            new_dict[k] = cleaned
        return new_dict, removed

    return obj, removed


def build_public_assets_candidate(*, write_candidate: bool = False) -> dict[str, Any]:
    """
    Build a cleaned public assets candidate.

    Explicit behavior:
      - No root container replacement.
      - No return/repack of active assets.
      - Writes only under export/C10_public_candidates when write_candidate=True.
      - Removes public-release blockers:
          data/CryptoChess.state.pah2
          data/cryptochess_hnr_install.key
      - Keeps review-only PAH2 asset payload:
          _legacy_convert_from_pah2/CryptoChess.assets.pah2
    """
    assets = find_role_container("assets")
    if not assets:
        return {
            "tool": APP_NAME,
            "stage": C10_STAGE,
            "passed": False,
            "error": "assets container missing",
            "mutates_root": False,
        }

    pc = Pah1Container(assets)
    pc.parse()

    if pc.errors:
        return {
            "tool": APP_NAME,
            "stage": C10_STAGE,
            "passed": False,
            "container": assets.name,
            "errors": pc.errors,
            "mutates_root": False,
        }

    try:
        path_map_name, path_map = pc.load_path_map()
    except Exception as exc:
        return {
            "tool": APP_NAME,
            "stage": C10_STAGE,
            "passed": False,
            "container": assets.name,
            "error": f"path map unavailable: {exc}",
            "mutates_root": False,
        }

    original_entries = list(path_map.get("entries", []))

    # Dynamically remove every internal path now classified as a public-release blocker.
    # This covers:
    #   data/CryptoChess.state.pah2
    #   data/CryptoChess.state.pah2.bak
    #   data/CryptoChess.state.anchor
    #   data/.cryptochess_state_workspace/chess.crypto.bak
    #   _migrated_old_pqcasset_folders/CryptoChess.state.pqcasset/*
    #   data/cryptochess_hnr_install.key
    cleanup_targets: dict[str, str] = {}

    for item in original_entries:
        if not isinstance(item, dict):
            continue
        rel0 = item.get("relative_path")
        if not isinstance(rel0, str):
            continue
        severity, reason, blocker = classify_privacy_name(rel0, internal=True)
        if blocker:
            cleanup_targets[rel0] = reason

    kept_path_items: list[dict[str, Any]] = []
    removed_items: list[dict[str, Any]] = []
    remove_encoded: set[str] = set()

    for item in original_entries:
        if not isinstance(item, dict):
            continue

        rel = item.get("relative_path")
        enc = item.get("encoded_name")

        if isinstance(rel, str) and rel in cleanup_targets:
            removed_items.append({
                "internal_path": rel,
                "encoded_name": enc if isinstance(enc, str) else None,
                "reason": cleanup_targets[rel],
            })
            if isinstance(enc, str):
                remove_encoded.add(enc)
            continue

        kept_path_items.append(dict(item))

    # Metadata scrub needles include both internal paths and encoded payload names.
    scrub_needles = set(cleanup_targets.keys()) | remove_encoded

    # Optional override data for kept encoded payload entries, such as C8_PAYLOAD_MANIFEST.json.
    data_overrides: dict[str, bytes] = {}
    manifest_scrub_reports: list[dict[str, Any]] = []

    for item in kept_path_items:
        rel = item.get("relative_path")
        enc = item.get("encoded_name")

        if not isinstance(rel, str) or not isinstance(enc, str) or enc not in pc.entries:
            continue

        lower_rel = rel.lower()
        if "payload_manifest" not in lower_rel and "manifest" not in lower_rel:
            continue

        original_data = pc.entries[enc]

        try:
            obj = json.loads(original_data.decode("utf-8"))
        except Exception:
            continue

        cleaned_obj, removed_refs = prune_json_references(obj, scrub_needles)

        if removed_refs > 0:
            new_data = (json.dumps(cleaned_obj, indent=2, sort_keys=True) + "\n").encode("utf-8")
            data_overrides[enc] = new_data

            item["sha256"] = sha256_bytes(new_data)
            item["size_bytes"] = len(new_data)

            manifest_scrub_reports.append({
                "internal_path": rel,
                "encoded_name": enc,
                "removed_reference_count": removed_refs,
                "new_sha256": item["sha256"],
                "new_size_bytes": len(new_data),
            })

    # Ensure the public assets container still restores a data/ directory.
    # Private runtime state was removed, but the application needs data/ to exist
    # so it can generate chess.crypto, state.pah2, install.key, and anchors locally.
    added_public_placeholders: list[dict[str, Any]] = []
    extra_entries: list[tuple[str, bytes]] = []

    safe_data_entry_exists = False
    for item in kept_path_items:
        if not isinstance(item, dict):
            continue
        rel_check = item.get("relative_path")
        if isinstance(rel_check, str) and (rel_check == "data" or rel_check.startswith("data/")):
            safe_data_entry_exists = True
            break

    if not safe_data_entry_exists:
        placeholder_rel = "data/README_PUBLIC_STATE.md"
        placeholder_payload = (
            "# CryptoChess local state directory\n\n"
            "This public placeholder keeps the portable data/ directory present.\n\n"
            "Runtime-private files such as chess.crypto, CryptoChess.state.pah2,\n"
            "install keys, anchors, and backups are intentionally not shipped in\n"
            "the public assets container. They must be generated locally on the\n"
            "user device at launch or during diagnostics.\n"
        ).encode("utf-8")

        placeholder_sha = sha256_bytes(placeholder_payload)
        placeholder_encoded = f"C10_PUBLIC_000000_{placeholder_sha[:16]}_README_PUBLIC_STATE.md"

        counter = 0
        while placeholder_encoded in pc.entries or any(n == placeholder_encoded for n, _d in extra_entries):
            counter += 1
            placeholder_encoded = f"C10_PUBLIC_{counter:06d}_{placeholder_sha[:16]}_README_PUBLIC_STATE.md"

        kept_path_items.append({
            "type": "file",
            "relative_path": placeholder_rel,
            "encoded_name": placeholder_encoded,
            "sha256": placeholder_sha,
            "size_bytes": len(placeholder_payload),
            "mode": "0644",
            "c10_public_placeholder": True,
        })

        extra_entries.append((placeholder_encoded, placeholder_payload))

        added_public_placeholders.append({
            "internal_path": placeholder_rel,
            "encoded_name": placeholder_encoded,
            "sha256": placeholder_sha,
            "size_bytes": len(placeholder_payload),
            "reason": "preserve public data/ directory without shipping private state",
        })

    # Update path map entries and common count fields.
    updated_path_map = dict(path_map)
    updated_path_map["entries"] = kept_path_items
    updated_path_map["c10_public_cleanup"] = {
        "stage": C10_STAGE,
        "removed_internal_paths": sorted(cleanup_targets.keys()),
        "device_paths_exported": False,
        "note": "Generated candidate only; active root container not replaced.",
    }

    for key in ["entry_count", "file_count", "payload_count"]:
        if isinstance(updated_path_map.get(key), int):
            updated_path_map[key] = len(kept_path_items)

    path_map_data = (json.dumps(updated_path_map, indent=2, sort_keys=True) + "\n").encode("utf-8")

    # Preserve original container order, skipping removed payload entries and replacing path map/manifest data.
    rebuilt_entries: list[tuple[str, bytes]] = []

    for name in pc.entries.keys():
        if name in remove_encoded:
            continue

        if name == path_map_name:
            data = path_map_data
        elif name in data_overrides:
            data = data_overrides[name]
        else:
            data = pc.entries[name]

        rebuilt_entries.append((name, data))

    for extra_name, extra_data in extra_entries:
        rebuilt_entries.append((extra_name, extra_data))

    candidate_bytes = write_pah1_bytes(rebuilt_entries)
    candidate_sha = sha256_bytes(candidate_bytes)
    candidate_name = f"3Dx9_assets_{candidate_sha[:12]}.pqcasset"
    candidate_rel = f"export/C10_public_candidates/{candidate_name}"

    write_info: dict[str, Any] = {
        "written": False,
        "candidate_path": candidate_rel,
    }

    if write_candidate:
        out_dir = Path("export/C10_public_candidates")
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / candidate_name
        out_path.write_bytes(candidate_bytes)
        write_info.update({
            "written": True,
            "candidate_path": out_path.as_posix(),
            "size_bytes": out_path.stat().st_size,
        })

    report = {
        "tool": APP_NAME,
        "stage": C10_STAGE,
        "action": "build-public-assets-candidate",
        "dry_run": not write_candidate,
        "mutates_root": False,
        "writes_export_only": bool(write_candidate),
        "source_container": assets.name,
        "source_sha256": sha256_file(assets),
        "candidate_name": candidate_name,
        "candidate_sha256": candidate_sha,
        "candidate_size_bytes": len(candidate_bytes),
        "source_entry_count": len(pc.entries),
        "candidate_entry_count": len(rebuilt_entries),
        "source_path_map_entry_count": len(original_entries),
        "candidate_path_map_entry_count": len(kept_path_items),
        "removed_items": removed_items,
        "manifest_scrubs": manifest_scrub_reports,
        "added_public_placeholders": added_public_placeholders,
        "kept_review_items": [
            "_legacy_convert_from_pah2/CryptoChess.assets.pah2"
        ],
        "privacy": "device paths redacted; only internal paths shown",
        "write": write_info,
        "next": [
            "Verify candidate with --verify \"$CAND\".",
            "Audit candidate with --audit-container \"$CAND\".",
            "Search candidate for state/install.key before promotion.",
            "Promote only in a later explicit C10C stage.",
        ],
        "passed": True,
    }

    return report


def print_public_assets_candidate(*, write_candidate: bool = False, strict_public: bool = False) -> int:
    report = build_public_assets_candidate(write_candidate=write_candidate)
    print(json.dumps(report, indent=2, sort_keys=True))

    if not report.get("passed"):
        return 1

    if strict_public:
        # Candidate build itself is not enough; the caller should audit the candidate path.
        return 0

    return 0



def promote_public_assets_candidate(candidate_file: str, *, apply_promote: bool = False, yes: bool = False) -> dict[str, Any]:
    """
    Promote a cleaned public assets candidate to the active root assets slot.

    Safety:
      - Dry-run by default.
      - Requires --apply-promote and --yes to mutate root.
      - Candidate must verify structurally.
      - Candidate privacy audit must have blocker_count == 0.
      - Old root assets container is moved into c10_safety_backups.
    """
    candidate = Path(candidate_file)

    report: dict[str, Any] = {
        "tool": APP_NAME,
        "stage": C10_STAGE,
        "action": "promote-public-assets-candidate",
        "candidate": candidate.as_posix(),
        "dry_run": not (apply_promote and yes),
        "requested_apply": bool(apply_promote),
        "confirmed_yes": bool(yes),
        "mutates_root": bool(apply_promote and yes),
        "passed": False,
        "checks": {},
        "steps": [],
        "privacy": "device paths redacted where exported; root file names and candidate relative path only",
    }

    if not candidate.exists():
        report["error"] = "candidate file not found"
        return report

    if candidate.suffix.lower() != ".pqcasset":
        report["error"] = "candidate is not a .pqcasset"
        return report

    if not candidate.name.startswith("3Dx9_assets_"):
        report["error"] = "candidate name does not look like an assets container"
        return report

    cand_verify = Pah1Container(candidate).report()
    report["checks"]["candidate_verify"] = asdict(cand_verify)

    if not cand_verify.passed:
        report["error"] = "candidate structural verification failed"
        return report

    findings, audit_summary = audit_container_privacy(candidate.as_posix())
    report["checks"]["candidate_privacy_audit"] = {
        "summary": audit_summary,
        "findings": [asdict(f) for f in findings],
    }

    if audit_summary.get("blocker_count", 999) != 0:
        report["error"] = "candidate privacy audit has public-release blockers"
        return report

    active = find_role_container("assets")
    if not active:
        report["error"] = "active root assets container not found"
        return report

    active_sha = sha256_file(active)
    candidate_sha = sha256_file(candidate)

    report["active_before"] = {
        "container": active.name,
        "sha256": active_sha,
        "size_bytes": active.stat().st_size,
    }

    report["candidate_info"] = {
        "container": candidate.name,
        "sha256": candidate_sha,
        "size_bytes": candidate.stat().st_size,
    }

    if active.name == candidate.name and active.resolve() == candidate.resolve():
        report["error"] = "candidate is already the active root assets file"
        return report

    backup_dir = Path("c10_safety_backups") / "C10C_R3_promoted_assets_backup"
    backup_old = backup_dir / active.name
    destination = Path(candidate.name)

    report["planned_changes"] = [
        {
            "step": "backup-active-assets",
            "from": active.name,
            "to": backup_old.as_posix(),
        },
        {
            "step": "copy-candidate-to-root",
            "from": candidate.as_posix(),
            "to": destination.name,
        },
    ]

    if not apply_promote or not yes:
        report["passed"] = True
        report["note"] = "dry-run only; rerun with --apply-promote --yes to mutate root"
        return report

    backup_dir.mkdir(parents=True, exist_ok=True)

    if backup_old.exists():
        backup_old = backup_dir / f"{active.stem}_{active_sha[:12]}{active.suffix}"

    shutil.move(active.as_posix(), backup_old.as_posix())
    shutil.copy2(candidate.as_posix(), destination.as_posix())

    promoted_verify = Pah1Container(destination).report()
    promoted_findings, promoted_audit = audit_container_privacy(destination.as_posix())

    report["steps"].append({
        "step": "backup-active-assets",
        "from": active.name,
        "to": backup_old.as_posix(),
        "passed": backup_old.exists(),
    })
    report["steps"].append({
        "step": "copy-candidate-to-root",
        "from": candidate.as_posix(),
        "to": destination.name,
        "passed": destination.exists(),
    })

    report["active_after"] = {
        "container": destination.name,
        "sha256": sha256_file(destination),
        "size_bytes": destination.stat().st_size,
    }

    report["checks"]["promoted_verify"] = asdict(promoted_verify)
    report["checks"]["promoted_privacy_audit"] = {
        "summary": promoted_audit,
        "findings": [asdict(f) for f in promoted_findings],
    }

    passed = (
        destination.exists()
        and backup_old.exists()
        and promoted_verify.passed
        and promoted_audit.get("blocker_count") == 0
        and sha256_file(destination) == candidate_sha
    )

    report["passed"] = bool(passed)

    export_dir = Path("export")
    export_dir.mkdir(exist_ok=True)
    out = export_dir / "C10C_R3_PROMOTION_REPORT.json"
    out.write_text(json.dumps(report, indent=2, sort_keys=True))
    report["written_report"] = out.as_posix()

    return report


def print_promote_public_assets_candidate(candidate_file: str, *, apply_promote: bool = False, yes: bool = False) -> int:
    report = promote_public_assets_candidate(
        candidate_file,
        apply_promote=apply_promote,
        yes=yes,
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("passed") else 1



def make_release_surface_finding(
    *,
    severity: str,
    category: str,
    reason: str,
    file_name: str | None = None,
    container: str | None = None,
    internal_path: str | None = None,
    public_release_blocker: bool = False,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "severity": severity,
        "category": category,
        "file_name": file_name,
        "container": container,
        "internal_path": internal_path,
        "reason": reason,
        "public_release_blocker": public_release_blocker,
        "details": details or {},
    }


def active_public_surface_files() -> dict[str, dict[str, Any]]:
    """
    Files that should define the current public surface before final PQCZIP build.

    Does not include old C9 metadata or old outer PQCZIP. Those are reviewed
    separately as stale/rebuild-required items.
    """
    files: dict[str, dict[str, Any]] = {}

    for role in ["core", "readme", "assets"]:
        p = find_role_container(role)
        if p and p.exists():
            files[p.name] = {
                "role": role,
                "sha256": sha256_file(p),
                "size_bytes": p.stat().st_size,
            }

    for name, role in [
        ("CryptoChessAssetManager.py", "manager"),
        ("cryptochess.sh", "launcher"),
    ]:
        p = Path(name)
        if p.exists():
            files[p.name] = {
                "role": role,
                "sha256": sha256_file(p),
                "size_bytes": p.stat().st_size,
            }

    return files


def infer_embedded_surface_role(name: str) -> str:
    lower = name.lower()
    if lower.startswith("3dx9_assets_"):
        return "assets"
    if lower.startswith("3dx9_core_"):
        return "core"
    if lower.startswith("3dx9_readme_"):
        return "readme"
    if lower == "cryptochessassetmanager.py":
        return "manager"
    if lower == "cryptochess.sh":
        return "launcher"
    if lower.endswith(".json") and "manifest" in lower:
        return "manifest"
    if lower.endswith(".json") and "seal" in lower:
        return "seal"
    if lower.endswith(".txt") and "sha256" in lower:
        return "sha256"
    return "unknown"


def audit_nested_embedded_pqcasset(
    *,
    outer_container: Path,
    embedded_internal_path: str,
    embedded_name: str,
    embedded_data: bytes,
) -> list[dict[str, Any]]:
    """
    Audit an embedded .pqcasset payload without exporting device paths.

    Uses a temporary local file only for parsing. The report never includes
    that temporary path.
    """
    findings: list[dict[str, Any]] = []

    embedded_sha = sha256_bytes(embedded_data)
    role = infer_embedded_surface_role(embedded_name)

    active_files = active_public_surface_files()
    active_by_role: dict[str, dict[str, Any]] = {}
    for root_name, info in active_files.items():
        active_by_role[str(info.get("role"))] = {
            "name": root_name,
            **info,
        }

    # Stale embedded role/name checks.
    active = active_by_role.get(role)
    if active and active.get("sha256") != embedded_sha:
        findings.append(make_release_surface_finding(
            severity="blocker",
            category="stale-embedded-public-file",
            container=outer_container.name,
            internal_path=embedded_internal_path,
            reason=f"outer PQCZIP embeds stale {role} payload; rebuild final PQCZIP from current root files",
            public_release_blocker=True,
            details={
                "embedded_name": embedded_name,
                "embedded_sha256": embedded_sha,
                "active_root_name": active.get("name"),
                "active_root_sha256": active.get("sha256"),
                "role": role,
            },
        ))

    # Direct same-name mismatch check.
    same_name = active_files.get(embedded_name)
    if same_name and same_name.get("sha256") != embedded_sha:
        findings.append(make_release_surface_finding(
            severity="blocker",
            category="stale-embedded-same-name-file",
            container=outer_container.name,
            internal_path=embedded_internal_path,
            reason="outer PQCZIP embeds a file whose root version has changed",
            public_release_blocker=True,
            details={
                "embedded_name": embedded_name,
                "embedded_sha256": embedded_sha,
                "root_sha256": same_name.get("sha256"),
                "role": same_name.get("role"),
            },
        ))

    # Nested privacy audit for embedded .pqcasset payloads.
    if embedded_name.lower().endswith(".pqcasset"):
        with tempfile.TemporaryDirectory(prefix="cryptochess_nested_audit_") as td:
            safe_name = Path(embedded_name).name
            tmp = Path(td) / safe_name
            tmp.write_bytes(embedded_data)

            nested_findings, nested_summary = audit_container_privacy(tmp.as_posix())

            if nested_summary.get("blocker_count", 0) > 0:
                findings.append(make_release_surface_finding(
                    severity="blocker",
                    category="nested-container-privacy-blockers",
                    container=outer_container.name,
                    internal_path=embedded_internal_path,
                    reason="embedded PQCAsset contains privacy/public-release blockers",
                    public_release_blocker=True,
                    details={
                        "embedded_name": embedded_name,
                        "embedded_sha256": embedded_sha,
                        "nested_summary": nested_summary,
                        "nested_findings": [
                            {
                                "severity": f.severity,
                                "category": f.category,
                                "internal_path": f.internal_path,
                                "reason": f.reason,
                                "public_release_blocker": f.public_release_blocker,
                            }
                            for f in nested_findings
                            if f.public_release_blocker
                        ],
                    },
                ))

    return findings


def audit_release_surface() -> dict[str, Any]:
    """
    Read-only release surface audit.

    Detects:
      - missing active core/readme/assets/manager/wrapper
      - root private files
      - stale old PQCZIP outer containers
      - nested embedded PQCAssets with privacy blockers
      - old C9 metadata that should be superseded
    """
    findings: list[dict[str, Any]] = []
    active_files = active_public_surface_files()

    required_roles = {"core", "readme", "assets", "manager", "launcher"}
    active_roles = {str(v.get("role")) for v in active_files.values()}

    for role in sorted(required_roles - active_roles):
        findings.append(make_release_surface_finding(
            severity="blocker",
            category="missing-active-public-file",
            reason=f"required public surface role is missing: {role}",
            public_release_blocker=True,
            details={"role": role},
        ))

    # Root private/stale/noise checks.
    for item in scan_directory(Path.cwd()):
        severity, reason, blocker = classify_privacy_name(item.name, internal=False)
        if severity:
            findings.append(make_release_surface_finding(
                severity=severity,
                category="root-file-privacy",
                file_name=item.name,
                reason=reason,
                public_release_blocker=blocker,
            ))

        if item.name.startswith("CryptoChess_2.0.0-rc1_C9I_R2_FINAL_STANDALONE_"):
            findings.append(make_release_surface_finding(
                severity="warning",
                category="stale-c9-release-metadata",
                file_name=item.name,
                reason="C9I-R2 metadata should be superseded by C10 release metadata before final publication",
                public_release_blocker=False,
            ))

        if item.name == "unwrap_pqczip_outer.py":
            findings.append(make_release_surface_finding(
                severity="warning",
                category="developer-helper-on-public-surface",
                file_name=item.name,
                reason="developer bootstrap helper should be excluded from final public surface after C10 PQCZIP build",
                public_release_blocker=False,
            ))

    # Active root containers must audit clean.
    for root_name, info in active_files.items():
        if not root_name.endswith(".pqcasset"):
            continue
        c_findings, c_summary = audit_container_privacy(root_name)
        if c_summary.get("blocker_count", 0) > 0:
            findings.append(make_release_surface_finding(
                severity="blocker",
                category="active-root-container-privacy-blockers",
                file_name=root_name,
                reason="active root container has privacy blockers",
                public_release_blocker=True,
                details={
                    "summary": c_summary,
                    "findings": [asdict(f) for f in c_findings if f.public_release_blocker],
                },
            ))

    # Audit all root PQCZIP outer containers recursively one level.
    pqczip_summaries: list[dict[str, Any]] = []

    for item in scan_directory(Path.cwd()):
        if item.kind not in {"pqczip", "vanity-pqczip"}:
            continue

        outer = Path(item.name)
        entries, warnings, errors = virtual_entries_for_container(outer)
        embedded_summaries: list[dict[str, Any]] = []

        for e in entries:
            if not e.name.lower().endswith((".pqcasset", ".py", ".sh")):
                continue

            try:
                data, _encoded = read_internal_payload(outer, e.internal_path)
            except Exception as exc:
                findings.append(make_release_surface_finding(
                    severity="blocker",
                    category="outer-embedded-read-failed",
                    container=outer.name,
                    internal_path=e.internal_path,
                    reason=f"could not read embedded public payload: {exc}",
                    public_release_blocker=True,
                ))
                continue

            embedded_sha = sha256_bytes(data)
            embedded_role = infer_embedded_surface_role(e.name)

            embedded_summaries.append({
                "internal_path": e.internal_path,
                "name": e.name,
                "role": embedded_role,
                "sha256": embedded_sha,
                "size_bytes": len(data),
            })

            findings.extend(audit_nested_embedded_pqcasset(
                outer_container=outer,
                embedded_internal_path=e.internal_path,
                embedded_name=e.name,
                embedded_data=data,
            ))

        # Any old C9 outer PQCZIP must be rebuilt, even when nested audit is clean.
        if outer.name.startswith("PQCZIP_CryptoChess_2.0.0-rc1_C9I_R2_FINAL_STANDALONE_"):
            findings.append(make_release_surface_finding(
                severity="blocker",
                category="stale-outer-pqczip",
                file_name=outer.name,
                reason="old C9I-R2 outer PQCZIP must be rebuilt after C10 cleanup/manager changes",
                public_release_blocker=True,
                details={
                    "embedded_count": len(embedded_summaries),
                    "embedded": embedded_summaries,
                },
            ))

        pqczip_summaries.append({
            "outer_container": outer.name,
            "kind": item.kind,
            "entry_count": len(entries),
            "embedded_public_payloads": embedded_summaries,
            "warnings": warnings[:12],
            "errors": errors[:12],
        })

    blocker_count = sum(1 for f in findings if f.get("public_release_blocker"))
    warning_count = sum(1 for f in findings if f.get("severity") == "warning")

    report = {
        "tool": APP_NAME,
        "stage": C10_STAGE,
        "created_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "audit": "release-surface",
        "privacy": "device paths redacted; only root names and portable internal paths are shown",
        "active_public_surface_files": active_files,
        "pqczip_summaries": pqczip_summaries,
        "summary": {
            "finding_count": len(findings),
            "blocker_count": blocker_count,
            "warning_count": warning_count,
            "public_release_ready": blocker_count == 0,
            "requires_new_pqczip_build": any(
                f.get("category") in {
                    "stale-outer-pqczip",
                    "stale-embedded-public-file",
                    "stale-embedded-same-name-file",
                    "nested-container-privacy-blockers",
                }
                for f in findings
            ),
        },
        "findings": findings,
        "next": [
            "Build a fresh C10 outer PQCZIP from current root files.",
            "Do not publish the old C9I-R2 outer PQCZIP.",
            "Re-run release-surface audit after the new PQCZIP is built.",
        ],
    }

    return report


def write_release_surface_audit(report: dict[str, Any]) -> str:
    export_dir = Path("export")
    export_dir.mkdir(exist_ok=True)
    out = export_dir / "C10_RELEASE_SURFACE_AUDIT.json"
    out.write_text(json.dumps(report, indent=2, sort_keys=True))
    return out.as_posix()


def print_release_surface_audit(*, write_report: bool = False, strict_public: bool = False) -> int:
    report = audit_release_surface()

    if write_report:
        report["written_report"] = write_release_surface_audit(report)

    print(json.dumps(report, indent=2, sort_keys=True))

    ready = bool(report.get("summary", {}).get("public_release_ready"))
    if strict_public and not ready:
        return 1
    return 0



def ordered_public_surface_payloads() -> list[dict[str, Any]]:
    active = active_public_surface_files()

    by_role: dict[str, tuple[str, dict[str, Any]]] = {}
    for name, info in active.items():
        by_role[str(info.get("role"))] = (name, info)

    order = ["assets", "core", "readme", "manager", "launcher"]
    payloads: list[dict[str, Any]] = []

    for role in order:
        if role not in by_role:
            continue
        name, info = by_role[role]
        path = Path(name)
        if not path.exists():
            continue
        data = path.read_bytes()
        sha = sha256_bytes(data)
        payloads.append({
            "role": role,
            "name": name,
            "size_bytes": len(data),
            "sha256": sha,
            "data": data,
        })

    return payloads


def build_c10_public_pqczip(*, write_pqczip: bool = False) -> dict[str, Any]:
    """
    Build a fresh C10 public outer PQCZIP candidate.

    Safety:
      - No root mutation.
      - Writes only under export/C10_public_release when --write-pqczip is used.
      - Includes only current root public surface files:
          assets, core, readme, CryptoChessAssetManager.py, cryptochess.sh
      - Excludes old C9 metadata, old outer PQCZIP, unwrap helper, runtime cache, backups.
    """
    payloads = ordered_public_surface_payloads()

    required_roles = {"assets", "core", "readme", "manager", "launcher"}
    found_roles = {str(p.get("role")) for p in payloads}
    missing_roles = sorted(required_roles - found_roles)

    report: dict[str, Any] = {
        "tool": APP_NAME,
        "stage": C10_STAGE,
        "action": "build-c10-public-pqczip",
        "dry_run": not write_pqczip,
        "mutates_root": False,
        "writes_export_only": bool(write_pqczip),
        "required_roles": sorted(required_roles),
        "found_roles": sorted(found_roles),
        "missing_roles": missing_roles,
        "passed": False,
        "privacy": "device paths redacted; only root names and portable internal paths are shown",
    }

    if missing_roles:
        report["error"] = "missing required public surface roles"
        return report

    # Verify active assets container is public-release ready before embedding it.
    assets_payload = next((p0 for p0 in payloads if p0["role"] == "assets"), None)
    if not assets_payload:
        report["error"] = "assets payload missing"
        return report

    assets_findings, assets_summary = audit_container_privacy(str(assets_payload["name"]))
    report["active_assets_privacy_audit"] = {
        "summary": assets_summary,
        "findings": [asdict(f) for f in assets_findings],
    }

    if assets_summary.get("blocker_count", 999) != 0:
        report["error"] = "active assets container is not public-release ready"
        return report

    path_map_entries: list[dict[str, Any]] = []
    pah_entries: list[tuple[str, bytes]] = []

    for idx, payload in enumerate(payloads):
        name = str(payload["name"])
        sha = str(payload["sha256"])
        encoded_name = f"C10E_R2C_{idx:06d}_{sha[:16]}_{name}"

        path_map_entries.append({
            "type": "file",
            "relative_path": name,
            "encoded_name": encoded_name,
            "sha256": sha,
            "size_bytes": int(payload["size_bytes"]),
            "role": str(payload["role"]),
            "mode": "0755" if name.endswith(".sh") else "0644",
        })

        pah_entries.append((encoded_name, payload["data"]))

    manifest = {
        "profile": "CryptoChess-C10-Public-PQCZIP-Manifest-v1",
        "stage": C10_STAGE,
        "created_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "release": {
            "app": "CryptoChess",
            "version": "2.0.0-rc1",
            "label": "C10 public release candidate",
        },
        "privacy": {
            "device_paths_exported": False,
            "absolute_paths_in_manifest": False,
            "private_state_shipped": False,
            "install_key_shipped": False,
            "public_state_placeholder": "data/README_PUBLIC_STATE.md",
        },
        "payloads": [
            {
                "role": p0["role"],
                "name": p0["name"],
                "sha256": p0["sha256"],
                "size_bytes": p0["size_bytes"],
            }
            for p0 in payloads
        ],
        "excluded_from_public_pqczip": [
            "PQCZIP_CryptoChess_2.0.0-rc1_C9I_R2_FINAL_STANDALONE_975aba118b9c.pqcasset",
            "CryptoChess_2.0.0-rc1_C9I_R2_FINAL_STANDALONE_PQCZIP_MANIFEST.json",
            "CryptoChess_2.0.0-rc1_C9I_R2_FINAL_STANDALONE_PQCZIP_SEAL.json",
            "CryptoChess_2.0.0-rc1_C9I_R2_FINAL_STANDALONE_PQCZIP_SHA256.txt",
            "unwrap_pqczip_outer.py",
            ".cryptochess_runtime/",
            "c9_build/",
            "c10_safety_backups/",
        ],
    }

    path_map = {
        "profile": "CryptoChess-C10-Public-PQCZIP-PathMap-v1",
        "stage": C10_STAGE,
        "created_at_utc": manifest["created_at_utc"],
        "device_paths_exported": False,
        "entries": path_map_entries,
        "entry_count": len(path_map_entries),
    }

    manifest_data = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    path_map_data = (json.dumps(path_map, indent=2, sort_keys=True) + "\n").encode("utf-8")

    # Path map and manifest are metadata entries; they are not themselves listed
    # in the portable path map. This matches the C9 outer-container shape.
    outer_entries = [
        ("C10_PACKAGE_PATH_MAP.json", path_map_data),
        ("C10_PACKAGE_MANIFEST.json", manifest_data),
    ] + pah_entries

    outer_bytes = write_pah1_bytes(outer_entries)
    outer_sha = sha256_bytes(outer_bytes)
    outer_name = f"PQCZIP_CryptoChess_2.0.0-rc1_C10E_R2C_PUBLIC_{outer_sha[:12]}.pqcasset"
    outer_rel = f"export/C10_public_release/{outer_name}"

    report.update({
        "candidate_name": outer_name,
        "candidate_sha256": outer_sha,
        "candidate_size_bytes": len(outer_bytes),
        "payload_count": len(payloads),
        "payloads": [
            {
                "role": p0["role"],
                "name": p0["name"],
                "sha256": p0["sha256"],
                "size_bytes": p0["size_bytes"],
            }
            for p0 in payloads
        ],
        "path_map_entry_count": len(path_map_entries),
        "manifest_sha256": sha256_bytes(manifest_data),
        "path_map_sha256": sha256_bytes(path_map_data),
        "write": {
            "written": False,
            "candidate_path": outer_rel,
        },
        "next": [
            "Verify candidate with --verify \"$PQCZIP\".",
            "List candidate with --list-container \"$PQCZIP\".",
            "Audit candidate with --audit-pqczip \"$PQCZIP\".",
            "Promote only in a later explicit C10D stage.",
        ],
        "passed": True,
    })

    if write_pqczip:
        out_dir = Path("export/C10_public_release")
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / outer_name
        out_path.write_bytes(outer_bytes)
        report["write"] = {
            "written": True,
            "candidate_path": out_path.as_posix(),
            "size_bytes": out_path.stat().st_size,
        }

        manifest_out = out_dir / "C10_PACKAGE_MANIFEST.json"
        path_map_out = out_dir / "C10_PACKAGE_PATH_MAP.json"
        sha_out = out_dir / f"{outer_name}.sha256.txt"

        manifest_out.write_bytes(manifest_data)
        path_map_out.write_bytes(path_map_data)
        sha_out.write_text(f"{outer_sha}  {outer_name}\n")

        report["sidecar_reports"] = {
            "manifest": manifest_out.as_posix(),
            "path_map": path_map_out.as_posix(),
            "sha256": sha_out.as_posix(),
        }

    return report


def audit_one_pqczip_candidate(file_name: str) -> dict[str, Any]:
    outer = Path(file_name)
    findings: list[dict[str, Any]] = []

    report: dict[str, Any] = {
        "tool": APP_NAME,
        "stage": C10_STAGE,
        "audit": "pqczip-candidate",
        "container": outer.name,
        "privacy": "device paths redacted; only candidate name and portable internal paths are shown",
        "passed": False,
    }

    if not outer.exists():
        report["error"] = "PQCZIP candidate not found"
        return report

    pc_report = Pah1Container(outer).report()
    report["structure"] = asdict(pc_report)

    if not pc_report.passed:
        report["error"] = "PQCZIP structural verification failed"
        return report

    active_files = active_public_surface_files()
    active_by_role: dict[str, dict[str, Any]] = {}
    for root_name, info in active_files.items():
        active_by_role[str(info.get("role"))] = {
            "name": root_name,
            **info,
        }

    entries, warnings, errors = virtual_entries_for_container(outer)
    embedded_payloads: list[dict[str, Any]] = []

    for warning in warnings:
        findings.append(make_release_surface_finding(
            severity="warning",
            category="pqczip-warning",
            container=outer.name,
            reason=warning,
            public_release_blocker=False,
        ))

    for error in errors:
        findings.append(make_release_surface_finding(
            severity="blocker",
            category="pqczip-error",
            container=outer.name,
            reason=error,
            public_release_blocker=True,
        ))

    for e in entries:
        if not e.name.lower().endswith((".pqcasset", ".py", ".sh")):
            continue

        try:
            data, _encoded = read_internal_payload(outer, e.internal_path)
        except Exception as exc:
            findings.append(make_release_surface_finding(
                severity="blocker",
                category="embedded-read-failed",
                container=outer.name,
                internal_path=e.internal_path,
                reason=f"could not read embedded payload: {exc}",
                public_release_blocker=True,
            ))
            continue

        embedded_sha = sha256_bytes(data)
        embedded_role = infer_embedded_surface_role(e.name)
        active = active_by_role.get(embedded_role)

        embedded_payloads.append({
            "internal_path": e.internal_path,
            "name": e.name,
            "role": embedded_role,
            "sha256": embedded_sha,
            "size_bytes": len(data),
            "matches_active_root": bool(active and active.get("sha256") == embedded_sha),
        })

        if not active:
            findings.append(make_release_surface_finding(
                severity="blocker",
                category="unknown-embedded-public-role",
                container=outer.name,
                internal_path=e.internal_path,
                reason="embedded payload role is not part of active public surface",
                public_release_blocker=True,
                details={
                    "embedded_name": e.name,
                    "role": embedded_role,
                    "sha256": embedded_sha,
                },
            ))
            continue

        if active.get("sha256") != embedded_sha:
            findings.append(make_release_surface_finding(
                severity="blocker",
                category="embedded-payload-does-not-match-active-root",
                container=outer.name,
                internal_path=e.internal_path,
                reason=f"embedded {embedded_role} payload does not match active root file",
                public_release_blocker=True,
                details={
                    "embedded_name": e.name,
                    "embedded_sha256": embedded_sha,
                    "active_root_name": active.get("name"),
                    "active_root_sha256": active.get("sha256"),
                    "role": embedded_role,
                },
            ))

        findings.extend(audit_nested_embedded_pqcasset(
            outer_container=outer,
            embedded_internal_path=e.internal_path,
            embedded_name=e.name,
            embedded_data=data,
        ))

    required_roles = {"assets", "core", "readme", "manager", "launcher"}
    embedded_roles = {p0["role"] for p0 in embedded_payloads}

    for role in sorted(required_roles - embedded_roles):
        findings.append(make_release_surface_finding(
            severity="blocker",
            category="missing-embedded-role",
            container=outer.name,
            reason=f"PQCZIP candidate missing embedded role: {role}",
            public_release_blocker=True,
            details={"role": role},
        ))

    blocker_count = sum(1 for f in findings if f.get("public_release_blocker"))
    warning_count = sum(1 for f in findings if f.get("severity") == "warning")

    report.update({
        "created_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "embedded_payloads": embedded_payloads,
        "summary": {
            "finding_count": len(findings),
            "blocker_count": blocker_count,
            "warning_count": warning_count,
            "public_release_ready": blocker_count == 0,
            "embedded_payload_count": len(embedded_payloads),
        },
        "findings": findings,
        "passed": blocker_count == 0,
    })

    return report


def write_pqczip_audit(report: dict[str, Any]) -> str:
    export_dir = Path("export")
    export_dir.mkdir(exist_ok=True)
    safe_name = str(report.get("container", "PQCZIP")).replace("/", "_").replace("\\", "_")
    out = export_dir / f"C10_PQCZIP_AUDIT_{safe_name}.json"
    out.write_text(json.dumps(report, indent=2, sort_keys=True))
    return out.as_posix()


def print_build_c10_public_pqczip(*, write_pqczip: bool = False) -> int:
    report = build_c10_public_pqczip(write_pqczip=write_pqczip)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("passed") else 1


def print_audit_pqczip(file_name: str, *, write_report: bool = False, strict_public: bool = False) -> int:
    report = audit_one_pqczip_candidate(file_name)

    if write_report:
        report["written_report"] = write_pqczip_audit(report)

    print(json.dumps(report, indent=2, sort_keys=True))

    ready = bool(report.get("summary", {}).get("public_release_ready"))
    if strict_public and not ready:
        return 1
    return 0 if report.get("passed") else 1



def unique_quarantine_path(dst: Path) -> Path:
    if not dst.exists():
        return dst

    stem = dst.stem
    suffix = dst.suffix
    parent = dst.parent

    for i in range(1, 10000):
        candidate = parent / f"{stem}_{i:04d}{suffix}"
        if not candidate.exists():
            return candidate

    raise RuntimeError(f"could not create unique quarantine path for {dst.name}")


def stale_public_surface_files_for_quarantine(candidate_name: str) -> list[Path]:
    """
    Root-only stale public surface files that should not remain beside
    the final C10 PQCZIP.

    Device paths are not reported; only names are used in exported reports.
    """
    targets: list[Path] = []

    for p0 in sorted(Path.cwd().iterdir(), key=lambda x: x.name.lower()):
        name = p0.name

        if p0.is_dir():
            continue

        if name == candidate_name:
            continue

        if name.startswith("PQCZIP_CryptoChess_2.0.0-rc1_") and name.endswith(".pqcasset"):
            # Final public surface should contain exactly one promoted outer PQCZIP:
            # the selected candidate. Quarantine every older/different outer PQCZIP.
            targets.append(p0)
            continue

        if name.startswith("CryptoChess_2.0.0-rc1_C9I_R2_FINAL_STANDALONE_PQCZIP_"):
            targets.append(p0)
            continue

        if name == "unwrap_pqczip_outer.py":
            targets.append(p0)
            continue

    return targets


def promote_public_pqczip_candidate(candidate_file: str, *, apply_promote: bool = False, yes: bool = False) -> dict[str, Any]:
    """
    Promote a fresh C10 public PQCZIP candidate to root.

    Safety:
      - Dry-run by default.
      - Requires --apply-promote --yes to mutate root.
      - Candidate must audit clean with --audit-pqczip logic.
      - Stale old C9 public surface files are moved to c10_safety_backups.
      - Root inner containers are not changed.
    """
    candidate = Path(candidate_file)

    report: dict[str, Any] = {
        "tool": APP_NAME,
        "stage": C10_STAGE,
        "action": "promote-public-pqczip",
        "candidate": candidate.as_posix(),
        "dry_run": not (apply_promote and yes),
        "requested_apply": bool(apply_promote),
        "confirmed_yes": bool(yes),
        "mutates_root": bool(apply_promote and yes),
        "passed": False,
        "checks": {},
        "planned_changes": [],
        "steps": [],
        "privacy": "device paths redacted; root file names and candidate relative path only",
    }

    if not candidate.exists():
        report["error"] = "candidate PQCZIP not found"
        return report

    if candidate.suffix.lower() != ".pqcasset":
        report["error"] = "candidate is not a .pqcasset"
        return report

    if not candidate.name.startswith("PQCZIP_CryptoChess_2.0.0-rc1_C10E_R2C_PUBLIC_"):
        report["error"] = "candidate does not look like a C10E-R2C public PQCZIP"
        return report

    pqczip_audit = audit_one_pqczip_candidate(candidate.as_posix())
    report["checks"]["candidate_pqczip_audit"] = pqczip_audit

    if not pqczip_audit.get("passed"):
        report["error"] = "candidate PQCZIP audit failed"
        return report

    summary = pqczip_audit.get("summary", {})
    if summary.get("blocker_count", 999) != 0:
        report["error"] = "candidate PQCZIP has public-release blockers"
        return report

    candidate_sha = sha256_file(candidate)
    destination = Path(candidate.name)
    quarantine_dir = Path("c10_safety_backups") / "C10E_R2C_quarantined_stale_public_surface"

    stale_targets = stale_public_surface_files_for_quarantine(candidate.name)

    if destination.exists():
        if sha256_file(destination) == candidate_sha:
            report["planned_changes"].append({
                "step": "root-pqczip-already-present",
                "file_name": destination.name,
                "sha256": candidate_sha,
            })
        else:
            stale_targets.append(destination)
            report["planned_changes"].append({
                "step": "quarantine-existing-different-root-pqczip",
                "file_name": destination.name,
                "reason": "root file with candidate name exists but hash differs",
            })
    else:
        report["planned_changes"].append({
            "step": "copy-candidate-to-root",
            "from": candidate.as_posix(),
            "to": destination.name,
            "sha256": candidate_sha,
        })

    for target in stale_targets:
        report["planned_changes"].append({
            "step": "quarantine-stale-public-surface-file",
            "file_name": target.name,
            "to_dir": quarantine_dir.as_posix(),
        })

    if not apply_promote or not yes:
        report["passed"] = True
        report["note"] = "dry-run only; rerun with --apply-promote --yes to mutate root"
        return report

    quarantine_dir.mkdir(parents=True, exist_ok=True)

    moved: list[dict[str, Any]] = []

    for target in stale_targets:
        if not target.exists():
            continue
        dst = unique_quarantine_path(quarantine_dir / target.name)
        shutil.move(target.as_posix(), dst.as_posix())
        moved.append({
            "from": target.name,
            "to": dst.as_posix(),
            "passed": dst.exists(),
        })

    if not destination.exists():
        shutil.copy2(candidate.as_posix(), destination.as_posix())
        copied = True
    else:
        copied = sha256_file(destination) == candidate_sha

    report["steps"].append({
        "step": "copy-candidate-to-root",
        "from": candidate.as_posix(),
        "to": destination.name,
        "passed": bool(destination.exists() and sha256_file(destination) == candidate_sha),
    })

    for m in moved:
        report["steps"].append({
            "step": "quarantine-stale-public-surface-file",
            **m,
        })

    promoted_audit = audit_one_pqczip_candidate(destination.as_posix())
    release_surface = audit_release_surface()

    report["checks"]["promoted_pqczip_audit"] = promoted_audit
    report["checks"]["release_surface_after"] = {
        "summary": release_surface.get("summary", {}),
        "findings": release_surface.get("findings", []),
    }

    report["active_after"] = {
        "container": destination.name,
        "sha256": sha256_file(destination),
        "size_bytes": destination.stat().st_size,
    }

    passed = (
        copied
        and destination.exists()
        and sha256_file(destination) == candidate_sha
        and promoted_audit.get("passed")
        and release_surface.get("summary", {}).get("blocker_count") == 0
    )

    report["passed"] = bool(passed)

    export_dir = Path("export")
    export_dir.mkdir(exist_ok=True)
    out = export_dir / "C10E_R2C_PQCZIP_PROMOTION_REPORT.json"
    out.write_text(json.dumps(report, indent=2, sort_keys=True))
    report["written_report"] = out.as_posix()

    return report


def print_promote_public_pqczip(candidate_file: str, *, apply_promote: bool = False, yes: bool = False) -> int:
    report = promote_public_pqczip_candidate(
        candidate_file,
        apply_promote=apply_promote,
        yes=yes,
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("passed") else 1



def root_file_snapshot(name: str) -> dict[str, Any]:
    p = Path(name)
    if not p.exists():
        return {
            "name": name,
            "present": False,
        }
    return {
        "name": name,
        "present": True,
        "size_bytes": p.stat().st_size,
        "sha256": sha256_file(p),
    }


def find_root_public_pqczips() -> list[Path]:
    return sorted(
        [
            p0 for p0 in Path.cwd().glob("PQCZIP_CryptoChess_2.0.0-rc1_*.pqcasset")
            if p0.is_file()
        ],
        key=lambda x: x.name,
    )


def latest_root_public_pqczip() -> Path | None:
    pqczips = find_root_public_pqczips()
    if not pqczips:
        return None
    # Prefer final C10E-R1 if present; otherwise newest by mtime.
    e1 = [p0 for p0 in pqczips if p0.name.startswith("PQCZIP_CryptoChess_2.0.0-rc1_C10E_R2C_PUBLIC_")]
    if e1:
        return sorted(e1, key=lambda x: x.stat().st_mtime, reverse=True)[0]
    return sorted(pqczips, key=lambda x: x.stat().st_mtime, reverse=True)[0]


def final_public_release_doctor() -> dict[str, Any]:
    """
    Final read-only release doctor.

    This checks the public root after the final PQCZIP has been promoted.
    It does not mutate anything.
    """
    report: dict[str, Any] = {
        "tool": APP_NAME,
        "stage": C10_STAGE,
        "created_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "doctor": "final-public-release",
        "mutates": False,
        "privacy": "device paths redacted; root names and portable internal paths only",
        "checks": {},
        "summary": {},
        "passed": False,
    }

    active = active_public_surface_files()
    report["checks"]["active_public_surface_files"] = active

    required_roles = {"assets", "core", "readme", "manager", "launcher"}
    active_roles = {str(v.get("role")) for v in active.values()}
    missing_roles = sorted(required_roles - active_roles)

    report["checks"]["required_roles"] = {
        "required": sorted(required_roles),
        "present": sorted(active_roles),
        "missing": missing_roles,
        "passed": not missing_roles,
    }

    pqczips = find_root_public_pqczips()
    pqczip_names = [p0.name for p0 in pqczips]
    selected = latest_root_public_pqczip()

    report["checks"]["root_pqczip_count"] = {
        "count": len(pqczips),
        "files": pqczip_names,
        "passed": len(pqczips) == 1,
    }

    if selected:
        report["checks"]["selected_root_pqczip"] = root_file_snapshot(selected.name)
        pqczip_audit = audit_one_pqczip_candidate(selected.as_posix())
        report["checks"]["root_pqczip_audit"] = pqczip_audit
    else:
        report["checks"]["selected_root_pqczip"] = {
            "present": False,
            "passed": False,
            "error": "no root public PQCZIP found",
        }

    release_surface = audit_release_surface()
    report["checks"]["release_surface"] = {
        "summary": release_surface.get("summary", {}),
        "findings": release_surface.get("findings", []),
    }

    assets = find_role_container("assets")
    if assets:
        assets_findings, assets_summary = audit_container_privacy(assets.name)
        report["checks"]["assets_privacy"] = {
            "summary": assets_summary,
            "findings": [asdict(f) for f in assets_findings],
        }
    else:
        report["checks"]["assets_privacy"] = {
            "summary": {
                "public_release_ready": False,
                "blocker_count": 999,
            },
            "error": "assets container missing",
        }

    # Root stale/noise files that must not be present after final promotion.
    stale_patterns = [
        "CryptoChess_2.0.0-rc1_C9I_R2_FINAL_STANDALONE_PQCZIP_MANIFEST.json",
        "CryptoChess_2.0.0-rc1_C9I_R2_FINAL_STANDALONE_PQCZIP_SEAL.json",
        "CryptoChess_2.0.0-rc1_C9I_R2_FINAL_STANDALONE_PQCZIP_SHA256.txt",
        "unwrap_pqczip_outer.py",
    ]

    stale_present = [x for x in stale_patterns if Path(x).exists()]
    report["checks"]["stale_root_files_absent"] = {
        "checked": stale_patterns,
        "present": stale_present,
        "passed": not stale_present,
    }

    # Public root should not contain direct private runtime files.
    private_root_findings: list[dict[str, Any]] = []
    for child in sorted(Path.cwd().iterdir(), key=lambda x: x.name.lower()):
        if not child.is_file():
            continue
        severity, reason, blocker = classify_privacy_name(child.name, internal=False)
        if severity:
            private_root_findings.append({
                "file_name": child.name,
                "severity": severity,
                "reason": reason,
                "public_release_blocker": blocker,
            })

    report["checks"]["private_root_files_absent"] = {
        "findings": private_root_findings,
        "passed": not any(f.get("public_release_blocker") for f in private_root_findings),
    }

    # Sidecar artifacts from latest build are useful but not root blockers.
    sidecars = {
        "export/C10_public_release/C10_PACKAGE_MANIFEST.json": Path("export/C10_public_release/C10_PACKAGE_MANIFEST.json").exists(),
        "export/C10_public_release/C10_PACKAGE_PATH_MAP.json": Path("export/C10_public_release/C10_PACKAGE_PATH_MAP.json").exists(),
    }

    if selected:
        sidecars[f"export/C10_public_release/{selected.name}.sha256.txt"] = Path(
            f"export/C10_public_release/{selected.name}.sha256.txt"
        ).exists()

    report["checks"]["release_sidecars_present"] = {
        "files": sidecars,
        "passed": all(sidecars.values()) if sidecars else False,
    }

    check_results = []

    def add_check(name: str, value: bool) -> None:
        check_results.append({
            "check": name,
            "passed": bool(value),
        })

    add_check("required_roles", report["checks"]["required_roles"]["passed"])
    add_check("single_root_pqczip", report["checks"]["root_pqczip_count"]["passed"])
    add_check(
        "root_pqczip_audit",
        bool(report["checks"].get("root_pqczip_audit", {}).get("passed")),
    )
    add_check(
        "release_surface",
        release_surface.get("summary", {}).get("blocker_count") == 0
        and release_surface.get("summary", {}).get("public_release_ready") is True
        and release_surface.get("summary", {}).get("requires_new_pqczip_build") is False,
    )
    add_check(
        "assets_privacy",
        report["checks"]["assets_privacy"].get("summary", {}).get("blocker_count") == 0
        and report["checks"]["assets_privacy"].get("summary", {}).get("public_release_ready") is True,
    )
    add_check("stale_root_files_absent", report["checks"]["stale_root_files_absent"]["passed"])
    add_check("private_root_files_absent", report["checks"]["private_root_files_absent"]["passed"])
    add_check("release_sidecars_present", report["checks"]["release_sidecars_present"]["passed"])

    report["summary"] = {
        "check_count": len(check_results),
        "passed_count": sum(1 for c in check_results if c["passed"]),
        "failed_count": sum(1 for c in check_results if not c["passed"]),
        "checks": check_results,
        "public_release_ready": all(c["passed"] for c in check_results),
        "root_pqczip": selected.name if selected else None,
    }

    report["passed"] = bool(report["summary"]["public_release_ready"])

    return report


def write_final_public_release_report(report: dict[str, Any]) -> str:
    export_dir = Path("export")
    export_dir.mkdir(exist_ok=True)
    out = export_dir / "C10E_R2C_FINAL_PUBLIC_RELEASE_DOCTOR.json"
    out.write_text(json.dumps(report, indent=2, sort_keys=True))
    return out.as_posix()


def print_final_public_release_doctor(*, write_report: bool = False, strict_public: bool = False) -> int:
    report = final_public_release_doctor()

    if write_report:
        report["written_report"] = write_final_public_release_report(report)

    print(json.dumps(report, indent=2, sort_keys=True))

    if strict_public and not report.get("passed"):
        return 1
    return 0 if report.get("passed") else 1



def print_launch_game_direct(extra_args: list[str] | None = None) -> int:
    """
    Direct runtime launcher.

    This intentionally does NOT call ./cryptochess.sh, because the wrapper
    already routes into this manager. Calling the wrapper from here causes
    infinite launch recursion.

    Steps:
      1. Restore core/assets into .cryptochess_runtime/.
      2. Ensure runtime-local data/ exists.
      3. Launch .cryptochess_runtime/core/CryptoChess.py directly.
    """
    extra_args = list(extra_args or [])

    root = Path.cwd()
    print("Launching CryptoChess from restored runtime checkout.")
    print("No automatic return/repack will be performed by this manager.")

    # Restore runtime through the existing safe restore command.
    restore_cmd = [sys.executable, Path(__file__).name, "restore-runtime"]
    restore = subprocess.run(restore_cmd, cwd=root)

    if restore.returncode != 0:
        print(json.dumps({
            "command": "launch",
            "passed": False,
            "error": "runtime restore failed",
            "restore_returncode": restore.returncode,
        }, indent=2, sort_keys=True))
        return restore.returncode

    core_dir = root / ".cryptochess_runtime" / "core"
    asset_dir = root / ".cryptochess_runtime" / "assets"
    data_dir = asset_dir / "data"

    data_dir.mkdir(parents=True, exist_ok=True)

    core_candidates = [
        core_dir / "CryptoChess.py",
        core_dir / "cryptochess_app.py",
    ]

    core_entry = next((c for c in core_candidates if c.exists()), None)

    if not core_entry:
        print(json.dumps({
            "command": "launch",
            "passed": False,
            "error": "runtime core entry not found",
            "checked": [c.as_posix() for c in core_candidates],
        }, indent=2, sort_keys=True))
        return 1

    env = os.environ.copy()
    env["CRYPTOCHESS_REPO_ROOT"] = root.as_posix()
    env["CRYPTOCHESS_RUNTIME_DIR"] = (root / ".cryptochess_runtime").as_posix()
    env["CRYPTOCHESS_CORE_DIR"] = core_dir.as_posix()
    env["CRYPTOCHESS_ASSET_DIR"] = asset_dir.as_posix()
    env["CRYPTOCHESS_DATA_DIR"] = data_dir.as_posix()
    env["CRYPTOCHESS_PUBLIC_RELEASE"] = "1"

    old_py = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = core_dir.as_posix() + (os.pathsep + old_py if old_py else "")

    cmd = [sys.executable, core_entry.as_posix()] + extra_args

    print(json.dumps({
        "command": "launch",
        "passed": True,
        "mode": "direct-runtime",
        "core_entry": core_entry.relative_to(root).as_posix(),
        "asset_dir": asset_dir.relative_to(root).as_posix(),
        "data_dir": data_dir.relative_to(root).as_posix(),
        "cwd": asset_dir.relative_to(root).as_posix(),
        "wrapper_recursion": False,
    }, indent=2, sort_keys=True))

    return subprocess.call(cmd, cwd=asset_dir, env=env)


@dataclass
class ScanItem:
    name: str
    kind: str
    role: str
    size_bytes: int
    sha256: str | None
    trust: str
    marker: str
    warning: str


def scan_directory(base: Path) -> list[ScanItem]:
    items: list[ScanItem] = []

    for path in sorted(base.iterdir(), key=lambda p: p.name.lower()):
        if path.name.startswith("."):
            continue
        if path.is_dir():
            continue

        suffix = path.suffix.lower()
        role = infer_role(path.name)
        warning = ""
        sha = None
        kind = "release-file"
        trust = "not-verified"

        if looks_private_name(path.name):
            warning = "private/local file; do not include in public release"

        if suffix == ".pqcasset":
            try:
                report = Pah1Container(path).report()
                kind = report.container_kind
                sha = report.sha256
                trust = "structure-verified" if report.passed else "failed"
                if report.errors:
                    warning = "; ".join(report.errors[:2])
                elif report.warnings:
                    warning = "; ".join(report.warnings[:2])
            except Exception as exc:
                kind = "unknown"
                trust = "failed"
                warning = f"parse failed: {exc}"
        elif suffix in PRIVATE_EXTS:
            kind = "private"
            trust = "private"
        elif path.name == "CryptoChessAssetManager.py":
            kind = "manager"
        elif suffix in {".py", ".sh"}:
            kind = "script"
        elif suffix not in SAFE_PUBLIC_EXTS:
            kind = "strange"
            warning = "unrecognized file type"

        items.append(ScanItem(
            name=path.name,
            kind=kind,
            role=role,
            size_bytes=path.stat().st_size,
            sha256=sha,
            trust=trust,
            marker=marker_for(kind, warning),
            warning=warning,
        ))

    return items


def manager_status() -> None:
    items = scan_directory(Path.cwd())
    pqc = [i for i in items if i.name.lower().endswith(".pqcasset")]
    failed = [i for i in pqc if i.trust == "failed"]
    private = [i for i in items if i.kind == "private" or i.warning.startswith("private")]

    print(json.dumps({
        "tool": APP_NAME,
        "stage": C10_STAGE,
        "safe_default": True,
        "bare_run_mutates": False,
        "device_paths_exported": False,
        "pqcasset_count": len(pqc),
        "pqcasset_failed": len(failed),
        "private_local_files_seen": len(private),
        "next": [
            "Use --scan to list files.",
            "Use --verify <file.pqcasset> to verify a container.",
            "Use --gui to open the safe GUI.",
            "Use ./cryptochess.sh run to launch the game.",
        ],
    }, indent=2, sort_keys=True))


def print_scan() -> None:
    print(json.dumps({
        "tool": APP_NAME,
        "stage": C10_STAGE,
        "privacy": "device paths redacted; display uses local names only",
        "items": [asdict(i) for i in scan_directory(Path.cwd())],
    }, indent=2, sort_keys=True))


def verify_one(file_name: str) -> int:
    path = Path(file_name)
    if not path.exists():
        print(json.dumps({"passed": False, "error": "file not found", "file_name": path.name}, indent=2))
        return 2
    if path.suffix.lower() != ".pqcasset":
        print(json.dumps({"passed": False, "error": "not a .pqcasset", "file_name": path.name}, indent=2))
        return 2

    report = Pah1Container(path).report()
    print(json.dumps(asdict(report), indent=2, sort_keys=True))
    return 0 if report.passed else 1


def wrapper_status() -> int:
    core = find_role_container("core")
    readme = find_role_container("readme")
    assets = find_role_container("assets")

    print("CryptoChess C10 safe standalone-loader dev status")
    print("native_loader: enabled")
    print("external_scout_knife_required: false")

    for role, p in [("core", core), ("readme", readme), ("assets", assets)]:
        if p and p.exists():
            print(f"{role}: {p.name} ({p.stat().st_size} bytes)")
        else:
            print(f"{role}: MISSING")

    print(f"export: {'present' if Path('export').exists() else 'missing'}")
    return 0


def verify_pqcassets() -> int:
    roles = []
    overall = True

    for role in ["core", "readme", "assets"]:
        p = find_role_container(role)
        if not p:
            roles.append({"role": role, "present": False, "passed": False})
            overall = False
            continue

        report = Pah1Container(p).report()
        passed = bool(report.passed)
        overall = overall and passed

        roles.append({
            "role": role,
            "present": True,
            "container": p.name,
            "size_bytes": p.stat().st_size,
            "sha256": report.sha256,
            "native_loader": True,
            "passed": passed,
            "version": report.version,
            "entry_count_declared": report.entry_count_declared,
            "valid_entries": report.entry_count_declared if passed else report.valid_entries,
            "invalid_entries": 0 if passed else report.invalid_entries,
            "trailing_bytes": report.trailing_bytes,
            "warnings": report.warnings[:6],
            "errors": report.errors,
        })

    print(json.dumps({
        "diagnostic": "verify-pqcassets",
        "overall_passed": overall,
        "native_loader": True,
        "external_scout_knife_required": False,
        "roles": roles,
    }, indent=2))
    return 0 if overall else 1


def verify_assets() -> int:
    assets = find_role_container("assets")
    if not assets:
        print(json.dumps({"diagnostic": "verify-assets", "overall_passed": False, "error": "assets container missing"}, indent=2))
        return 1

    out = Path(".cryptochess_runtime/_diagnostics/assets_verify")
    restore = extract_container(assets, out, clean=True)

    data_dir_present = (out / "data").exists()
    legacy_present = (out / "_legacy_convert_from_pah2").exists()
    migrated_present = any(out.rglob("*.pah2"))
    restored_positive = restore.get("restored", 0) > 0

    overall = bool(restore.get("passed")) and data_dir_present and restored_positive

    print(json.dumps({
        "diagnostic": "verify-assets",
        "overall_passed": overall,
        "native_loader": True,
        "external_scout_knife_required": False,
        "checks": {
            "native_assets_restore_passed": bool(restore.get("passed")),
            "data_dir_present": data_dir_present,
            "legacy_convert_lane_present": legacy_present,
            "migrated_old_pqcasset_lane_present": migrated_present,
            "restored_files_positive": restored_positive,
        },
        "restore": restore,
    }, indent=2))
    return 0 if overall else 1


def restore_runtime() -> int:
    core = find_role_container("core")
    assets = find_role_container("assets")

    if not core:
        print("Missing container for role: core")
        return 1
    if not assets:
        print("Missing container for role: assets")
        return 1

    core_out = Path(".cryptochess_runtime/core")
    assets_out = Path(".cryptochess_runtime/assets")
    Path(".cryptochess_runtime").mkdir(exist_ok=True)

    core_restore = extract_container(core, core_out, clean=True)
    assets_restore = extract_container(assets, assets_out, clean=True)

    core_entry = core_out / "CryptoChess.py"
    data_dir = assets_out / "data"
    asset_dir = assets_out / "_legacy_convert_from_pah2"

    checkout_state = Path(".cryptochess_runtime/C9_CHECKOUT_STATE.json")
    checkout_state.write_text(json.dumps({
        "stage": C10_STAGE,
        "core_container": core.name,
        "assets_container": assets.name,
        "core_entry": core_entry.as_posix(),
        "data_dir": data_dir.as_posix(),
        "device_paths_exported": False,
        "note": "Runtime checkout paths are local operational paths; release manifests must use internal paths only.",
    }, indent=2, sort_keys=True))

    passed = (
        bool(core_restore.get("passed"))
        and bool(assets_restore.get("passed"))
        and core_entry.exists()
        and data_dir.exists()
    )

    print(json.dumps({
        "core": core_restore,
        "assets": assets_restore,
        "core_entry": core_entry.as_posix(),
        "data_dir": data_dir.as_posix(),
        "asset_dir": asset_dir.as_posix(),
        "core_entry_exists": core_entry.exists(),
        "data_dir_exists": data_dir.exists(),
        "checkout_state": checkout_state.as_posix(),
        "passed": passed,
    }, indent=2))
    return 0 if passed else 1


def launch_game() -> int:
    wrapper = Path("cryptochess.sh")
    if not wrapper.exists():
        print("cryptochess.sh not found.")
        return 2
    print("Launching CryptoChess through ./cryptochess.sh run")
    print("No automatic return/repack will be performed by this manager.")
    return subprocess.call(["./cryptochess.sh", "run"])


def open_gui() -> int:
    try:
        import tkinter as tk
        from tkinter import ttk, messagebox
    except Exception as exc:
        print(f"GUI unavailable: {exc}")
        manager_status()
        return 0

    root = tk.Tk()
    root.title(APP_TITLE)
    root.geometry("1100x660")

    top = tk.Frame(root)
    top.pack(side="top", fill="x")

    tk.Label(top, text="Search:").pack(side="left", padx=(8, 2))
    search_var = tk.StringVar()
    search_entry = tk.Entry(top, textvariable=search_var, width=34)
    search_entry.pack(side="left", padx=4)

    trust_var = tk.StringVar(value="All")
    role_var = tk.StringVar(value="All")

    tk.Label(top, text="Trust:").pack(side="left", padx=(8, 2))
    tk.OptionMenu(top, trust_var, "All", "structure-verified", "failed", "private", "not-verified").pack(side="left")

    tk.Label(top, text="Role:").pack(side="left", padx=(8, 2))
    tk.OptionMenu(top, role_var, "All", "core", "assets", "readme", "outer", "manager", "launcher", "manifest", "seal", "sha256", "unknown").pack(side="left")

    main = tk.PanedWindow(root, orient="horizontal")
    main.pack(fill="both", expand=True, padx=8, pady=8)

    left = tk.Frame(main)
    right = tk.Frame(main)
    main.add(left, width=650)
    main.add(right, width=450)

    tree = ttk.Treeview(left, columns=("name", "marker", "role", "kind", "trust", "size"), show="headings")
    for col, title, width in [
        ("name", "Name", 260),
        ("marker", "Tag", 70),
        ("role", "Role", 80),
        ("kind", "Type", 130),
        ("trust", "Trust", 140),
        ("size", "Size", 80),
    ]:
        tree.heading(col, text=title)
        tree.column(col, width=width)
    tree.pack(fill="both", expand=True)

    name_label = tk.Label(right, text="Select an item", font=("Arial", 14, "bold"), anchor="w")
    name_label.pack(fill="x")

    detail = tk.Text(right, height=24, wrap="word")
    detail.pack(fill="both", expand=True, pady=(8, 8))

    scan_items: list[ScanItem] = []

    def refresh() -> None:
        nonlocal scan_items
        scan_items = scan_directory(Path.cwd())
        tree.delete(*tree.get_children())

        q = search_var.get().lower().strip()
        tf = trust_var.get()
        rf = role_var.get()

        for idx, item in enumerate(scan_items):
            if q and q not in item.name.lower() and q not in item.kind.lower() and q not in item.role.lower():
                continue
            if tf != "All" and item.trust != tf:
                continue
            if rf != "All" and item.role != rf:
                continue
            tree.insert("", "end", iid=str(idx), values=(item.name, item.marker, item.role, item.kind, item.trust, item.size_bytes))

    def on_select(_event=None) -> None:
        sel = tree.selection()
        if not sel:
            return
        item = scan_items[int(sel[0])]
        name_label.config(text=item.name)
        detail.delete("1.0", "end")
        detail.insert("end", json.dumps(asdict(item), indent=2, sort_keys=True))

    def verify_selected() -> None:
        sel = tree.selection()
        if not sel:
            messagebox.showinfo(APP_TITLE, "Select a .pqcasset first.")
            return
        item = scan_items[int(sel[0])]
        if not item.name.lower().endswith(".pqcasset"):
            messagebox.showinfo(APP_TITLE, "Selected item is not a .pqcasset.")
            return
        report = Pah1Container(Path(item.name)).report()
        detail.delete("1.0", "end")
        detail.insert("end", json.dumps(asdict(report), indent=2, sort_keys=True))
        name_label.config(text=f"Verified: {item.name}")
        refresh()

    def inspect_selected() -> None:
        sel = tree.selection()
        if not sel:
            messagebox.showinfo(APP_TITLE, "Select a .pqcasset first.")
            return

        item = scan_items[int(sel[0])]
        if not item.name.lower().endswith(".pqcasset"):
            messagebox.showinfo(APP_TITLE, "Selected item is not a .pqcasset.")
            return

        container_name = item.name
        entries, warnings, errors = virtual_entries_for_container(Path(container_name))

        browser = tk.Toplevel(root)
        browser.title(f"PIAL-T-L Container Browser - {container_name}")
        browser.geometry("1180x720")

        top2 = tk.Frame(browser)
        top2.pack(side="top", fill="x")

        tk.Label(top2, text="Internal Search:").pack(side="left", padx=(8, 2))
        internal_search = tk.StringVar()
        internal_search_entry = tk.Entry(top2, textvariable=internal_search, width=42)
        internal_search_entry.pack(side="left", padx=4)

        stats_label = tk.Label(
            top2,
            text=f"{len(entries)} internal entries | device paths redacted",
            anchor="w",
        )
        stats_label.pack(side="left", padx=12)

        body = tk.PanedWindow(browser, orient="horizontal")
        body.pack(fill="both", expand=True, padx=8, pady=8)

        left2 = tk.Frame(body)
        right2 = tk.Frame(body)
        body.add(left2, width=720)
        body.add(right2, width=460)

        internal_tree = ttk.Treeview(
            left2,
            columns=("path", "marker", "type", "size", "sha"),
            show="headings",
        )

        for col, title, width in [
            ("path", "Internal Path", 380),
            ("marker", "Tag", 80),
            ("type", "Type", 80),
            ("size", "Size", 80),
            ("sha", "SHA256", 220),
        ]:
            internal_tree.heading(col, text=title)
            internal_tree.column(col, width=width)

        internal_tree.pack(fill="both", expand=True)

        preview_title = tk.Label(right2, text="Select an internal entry", font=("Arial", 12, "bold"), anchor="w")
        preview_title.pack(fill="x")

        preview_box = tk.Text(right2, height=28, wrap="word")
        preview_box.pack(fill="both", expand=True, pady=(8, 8))

        filtered_entries: list[VirtualEntry] = []

        def entry_matches(e: VirtualEntry, q: str) -> bool:
            q = q.lower().strip()
            if not q:
                return True
            return (
                q in e.internal_path.lower()
                or q in e.name.lower()
                or q in e.parent.lower()
                or q in e.type.lower()
                or q in e.marker.lower()
                or q in e.warning.lower()
            )

        def refresh_internal() -> None:
            nonlocal filtered_entries
            q = internal_search.get()
            filtered_entries = [e for e in entries if entry_matches(e, q)]
            internal_tree.delete(*internal_tree.get_children())

            for idx, e in enumerate(filtered_entries):
                internal_tree.insert(
                    "",
                    "end",
                    iid=str(idx),
                    values=(
                        e.internal_path,
                        e.marker,
                        e.type,
                        e.size_bytes,
                        (e.sha256[:24] + "...") if e.sha256 else "",
                    ),
                )

            stats_label.config(
                text=f"{len(filtered_entries)} shown / {len(entries)} total | device paths redacted"
            )

        def show_internal_details(_event=None) -> None:
            sel2 = internal_tree.selection()
            if not sel2:
                return

            e = filtered_entries[int(sel2[0])]
            preview_title.config(text=e.internal_path)
            preview_box.delete("1.0", "end")
            preview_box.insert("end", json.dumps(asdict(e), indent=2, sort_keys=True))

        def preview_selected_internal() -> None:
            sel2 = internal_tree.selection()
            if not sel2:
                messagebox.showinfo(APP_TITLE, "Select an internal file first.")
                return

            e = filtered_entries[int(sel2[0])]

            if e.type == "dir":
                messagebox.showinfo(APP_TITLE, "Directories do not have preview content.")
                return

            suffix = PurePosixPath(e.internal_path).suffix.lower()
            if suffix not in TEXT_PREVIEW_EXTS:
                preview_box.delete("1.0", "end")
                preview_box.insert("end", json.dumps({
                    "container": container_name,
                    "internal_path": e.internal_path,
                    "preview": "binary or unsupported preview type",
                    "size_bytes": e.size_bytes,
                    "sha256": e.sha256,
                    "privacy": "device path redacted; internal path only",
                }, indent=2, sort_keys=True))
                return

            try:
                data, encoded = read_internal_payload(Path(container_name), e.internal_path)
                sample = data[:12000].decode("utf-8", errors="replace")
                preview_title.config(text=f"Preview: {e.internal_path}")
                preview_box.delete("1.0", "end")
                preview_box.insert("end", json.dumps({
                    "container": container_name,
                    "internal_path": e.internal_path,
                    "encoded_name": encoded,
                    "size_bytes": len(data),
                    "sha256": sha256_bytes(data),
                    "truncated": len(data) > 12000,
                    "privacy": "device path redacted; internal path only",
                    "preview": sample,
                }, indent=2, sort_keys=True))
            except Exception as exc:
                preview_box.delete("1.0", "end")
                preview_box.insert("end", json.dumps({
                    "passed": False,
                    "container": container_name,
                    "internal_path": e.internal_path,
                    "error": str(exc),
                }, indent=2, sort_keys=True))

        def copy_internal_path() -> None:
            sel2 = internal_tree.selection()
            if not sel2:
                return
            e = filtered_entries[int(sel2[0])]
            browser.clipboard_clear()
            browser.clipboard_append(e.internal_path)
            stats_label.config(text=f"Copied internal path: {e.internal_path}")

        btnbar = tk.Frame(right2)
        btnbar.pack(fill="x")

        tk.Button(btnbar, text="Preview Text", command=preview_selected_internal).pack(side="left", padx=2)
        tk.Button(btnbar, text="Copy Internal Path", command=copy_internal_path).pack(side="left", padx=2)
        tk.Button(btnbar, text="Close", command=browser.destroy).pack(side="right", padx=2)

        warning_text = ""
        if warnings:
            warning_text += "Warnings:\\n" + "\\n".join(warnings[:12]) + "\\n\\n"
        if errors:
            warning_text += "Errors:\\n" + "\\n".join(errors[:12]) + "\\n\\n"
        warning_text += "Privacy rule: only portable internal paths are displayed."
        preview_box.insert("end", warning_text)

        internal_tree.bind("<<TreeviewSelect>>", show_internal_details)
        internal_tree.bind("<Double-Button-1>", lambda _e: preview_selected_internal())
        internal_search.trace_add("write", lambda *_: refresh_internal())

        refresh_internal()
        internal_search_entry.focus_set()

        # Keep main panel useful too.
        detail.delete("1.0", "end")
        detail.insert("end", json.dumps({
            "container": container_name,
            "entry_count": len(entries),
            "browser": "opened",
            "privacy": "device paths redacted; internal paths only",
            "warnings": warnings[:12],
            "errors": errors,
        }, indent=2, sort_keys=True))
        name_label.config(text=f"Browsing: {container_name}")

    def safe_notice() -> None:
        messagebox.showinfo(
            APP_TITLE,
            "C10A-R3 safe mode is active.\n\n"
            "No bare-run mutation.\n"
            "No legacy unsafe delegation.\n"
            "No hidden return/repack.\n"
            "Wrapper diagnostics are handled by this safe manager.",
        )

    btns = tk.Frame(right)
    btns.pack(fill="x")
    tk.Button(btns, text="Refresh", command=refresh).pack(side="left", padx=2)
    tk.Button(btns, text="Verify Selected", command=verify_selected).pack(side="left", padx=2)
    tk.Button(btns, text="Inspect Container", command=inspect_selected).pack(side="left", padx=2)
    tk.Button(btns, text="Launch Game", command=launch_game).pack(side="left", padx=2)
    tk.Button(btns, text="Safe Mode Info", command=safe_notice).pack(side="left", padx=2)

    tree.bind("<<TreeviewSelect>>", on_select)
    search_var.trace_add("write", lambda *_: refresh())
    trust_var.trace_add("write", lambda *_: refresh())
    role_var.trace_add("write", lambda *_: refresh())

    bottom = tk.Label(root, text=f"{APP_NAME} {C10_STAGE} | Device paths are private | No hidden launch/return/repack", anchor="w")
    bottom.pack(side="bottom", fill="x")

    refresh()
    root.mainloop()
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="CryptoChessAssetManager.py", description=f"{APP_TITLE} - {C10_STAGE}")
    p.add_argument("command", nargs="?", help="C9/C10 positional command compatibility.")
    p.add_argument("command_args", nargs=argparse.REMAINDER)
    p.add_argument("--status", action="store_true", help="Show safe manager status.")
    p.add_argument("--scan", action="store_true", help="Scan current folder without exposing device paths.")
    p.add_argument("--verify", metavar="FILE.pqcasset", help="Verify one PAH1/PQCAsset container.")
    p.add_argument("--list-container", metavar="FILE.pqcasset", help="List virtual internal container contents.")
    p.add_argument("--limit", type=int, default=500, help="Limit list-container output rows.")
    p.add_argument("--find", default="", help="Filter --list-container output by internal path/name/parent/type/warning.")
    p.add_argument("--preview-container", metavar="FILE.pqcasset", help="Preview a text-like internal file.")
    p.add_argument("--internal-path", metavar="PATH", help="Portable internal path for preview-container.")
    p.add_argument("--audit-privacy", action="store_true", help="Run read-only public-release privacy audit.")
    p.add_argument("--audit-container", metavar="FILE.pqcasset", help="Audit one container for privacy/public-release blockers.")
    p.add_argument("--plan-public-cleanup", action="store_true", help="Dry-run public release cleanup plan. Does not mutate.")
    p.add_argument("--write-cleanup-plan", action="store_true", help="Explicitly write export/C10_PUBLIC_CLEANUP_PLAN.json.")
    p.add_argument("--build-public-assets-candidate", action="store_true", help="Build public assets candidate plan; writes only with --write-candidate.")
    p.add_argument("--write-candidate", action="store_true", help="Explicitly write public assets candidate under export/C10_public_candidates/.")
    p.add_argument("--promote-public-assets-candidate", metavar="FILE.pqcasset", help="Promote verified public assets candidate to root; dry-run unless --apply-promote --yes.")
    p.add_argument("--audit-release-surface", action="store_true", help="Audit root release surface including nested old PQCZIP payloads.")
    p.add_argument("--write-release-surface-audit", action="store_true", help="Explicitly write export/C10_RELEASE_SURFACE_AUDIT.json.")
    p.add_argument("--build-public-pqczip", action="store_true", help="Build fresh C10 public PQCZIP; writes only with --write-pqczip.")
    p.add_argument("--write-pqczip", action="store_true", help="Explicitly write fresh C10 public PQCZIP under export/C10_public_release/.")
    p.add_argument("--audit-pqczip", metavar="FILE.pqcasset", help="Audit one PQCZIP candidate directly.")
    p.add_argument("--write-pqczip-audit", action="store_true", help="Explicitly write one-PQCZIP audit report under export/.")
    p.add_argument("--promote-public-pqczip", metavar="FILE.pqcasset", help="Promote fresh C10E-R2C public PQCZIP to root; dry-run unless --apply-promote --yes.")
    p.add_argument("--final-release-doctor", action="store_true", help="Run final public release doctor.")
    p.add_argument("--write-final-release-report", action="store_true", help="Explicitly write export/C10E_R2C_FINAL_PUBLIC_RELEASE_DOCTOR.json.")
    p.add_argument("--apply-promote", action="store_true", help="Allow promote-public-assets-candidate to mutate root.")
    p.add_argument("--yes", action="store_true", help="Confirm an explicit mutating promotion action.")
    p.add_argument("--write-report", action="store_true", help="Explicitly write audit report under export/.")
    p.add_argument("--strict-public", action="store_true", help="Return nonzero if audit finds public-release blockers.")
    p.add_argument("--gui", action="store_true", help="Open safe PIAL-T-L GUI.")
    p.add_argument("--launch-game", action="store_true", help="Explicitly launch the game without auto-return/repack.")
    return p


def handle_positional(command: str, rest: list[str]) -> int | None:
    cmd = command.strip()

    if cmd == "status":
        return wrapper_status()
    if cmd == "verify-pqcassets":
        return verify_pqcassets()
    if cmd == "verify-assets":
        return verify_assets()
    if cmd in {"restore-runtime", "restore-runtime-only"}:
        return restore_runtime()
    if cmd in {"scan", "list"}:
        print_scan()
        return 0
    if cmd == "verify" and rest:
        return verify_one(rest[0])
    if cmd in {"list-container", "inspect-container"} and rest:
        return print_container_listing(rest[0])
    if cmd in {"preview-container", "preview"} and len(rest) >= 2:
        return preview_internal_file(rest[0], rest[1])
    if cmd in {"audit-privacy", "privacy-audit"}:
        return print_audit_privacy(
            write_report="--write-report" in rest,
            strict_public="--strict-public" in rest,
        )
    if cmd in {"audit-container", "privacy-container"} and rest:
        return print_audit_container(
            rest[0],
            write_report="--write-report" in rest[1:],
            strict_public="--strict-public" in rest[1:],
        )
    if cmd in {"plan-public-cleanup", "cleanup-plan", "public-cleanup-plan"}:
        return print_cleanup_plan(
            write_report=("--write-report" in rest or "--write-cleanup-plan" in rest),
            strict_public="--strict-public" in rest,
        )
    if cmd in {"build-public-assets-candidate", "public-assets-candidate"}:
        return print_public_assets_candidate(
            write_candidate="--write-candidate" in rest,
            strict_public="--strict-public" in rest,
        )
    if cmd in {"promote-public-assets-candidate", "promote-assets-candidate"} and rest:
        return print_promote_public_assets_candidate(
            rest[0],
            apply_promote="--apply-promote" in rest[1:],
            yes="--yes" in rest[1:],
        )
    if cmd in {"audit-release-surface", "release-surface-audit"}:
        return print_release_surface_audit(
            write_report=("--write-report" in rest or "--write-release-surface-audit" in rest),
            strict_public="--strict-public" in rest,
        )
    if cmd in {"build-public-pqczip", "build-c10-pqczip"}:
        return print_build_c10_public_pqczip(
            write_pqczip="--write-pqczip" in rest,
        )
    if cmd in {"audit-pqczip", "audit-public-pqczip"} and rest:
        return print_audit_pqczip(
            rest[0],
            write_report=("--write-report" in rest[1:] or "--write-pqczip-audit" in rest[1:]),
            strict_public="--strict-public" in rest[1:],
        )
    if cmd in {"promote-public-pqczip", "promote-pqczip"} and rest:
        return print_promote_public_pqczip(
            rest[0],
            apply_promote="--apply-promote" in rest[1:],
            yes="--yes" in rest[1:],
        )
    if cmd in {"final-release-doctor", "release-doctor", "final-doctor"}:
        return print_final_public_release_doctor(
            write_report=("--write-report" in rest or "--write-final-release-report" in rest),
            strict_public="--strict-public" in rest,
        )
    if cmd in {"run", "launch", "launch-game"}:
        return print_launch_game_direct(rest)
    if cmd in {"gui", "wizard"}:
        return open_gui()
    if cmd in {"return", "repack", "repack-assets", "auto-return"}:
        print(json.dumps({
            "passed": False,
            "blocked": True,
            "command": cmd,
            "reason": "C10A-R3 blocks return/repack until explicit safe C10 return workflow is added.",
        }, indent=2, sort_keys=True))
        return 2
    if cmd in {"help", "-h", "--help"}:
        build_parser().print_help()
        return 0

    return None


def _c10_original_main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv

    if not argv:
        if os.environ.get("DISPLAY") or sys.platform in ("win32", "darwin"):
            return open_gui()
        manager_status()
        return 0

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command:
        result = handle_positional(args.command, args.command_args)
        if result is not None:
            return result
        print(json.dumps({
            "passed": False,
            "error": "unrecognized command",
            "command": args.command,
            "hint": "Use --help, --status, --scan, --gui, --launch-game, run, launch, status, verify-pqcassets, verify-assets, or restore-runtime.",
        }, indent=2, sort_keys=True))
        return 2

    if args.status:
        manager_status()
        return 0
    if args.scan:
        print_scan()
        return 0
    if args.verify:
        return verify_one(args.verify)
    if args.list_container:
        return print_container_listing(args.list_container, limit=max(1, args.limit), find=args.find)
    if args.preview_container:
        if not args.internal_path:
            print(json.dumps({
                "passed": False,
                "error": "--preview-container requires --internal-path",
            }, indent=2))
            return 2
        return preview_internal_file(args.preview_container, args.internal_path)
    if args.audit_privacy:
        return print_audit_privacy(
            write_report=args.write_report,
            strict_public=args.strict_public,
        )
    if args.audit_container:
        return print_audit_container(
            args.audit_container,
            write_report=args.write_report,
            strict_public=args.strict_public,
        )
    if args.plan_public_cleanup:
        return print_cleanup_plan(
            write_report=(args.write_report or args.write_cleanup_plan),
            strict_public=args.strict_public,
        )
    if args.build_public_assets_candidate:
        return print_public_assets_candidate(
            write_candidate=args.write_candidate,
            strict_public=args.strict_public,
        )
    if args.promote_public_assets_candidate:
        return print_promote_public_assets_candidate(
            args.promote_public_assets_candidate,
            apply_promote=args.apply_promote,
            yes=args.yes,
        )
    if args.audit_release_surface:
        return print_release_surface_audit(
            write_report=(args.write_report or args.write_release_surface_audit),
            strict_public=args.strict_public,
        )
    if args.build_public_pqczip:
        return print_build_c10_public_pqczip(
            write_pqczip=args.write_pqczip,
        )
    if args.audit_pqczip:
        return print_audit_pqczip(
            args.audit_pqczip,
            write_report=(args.write_report or args.write_pqczip_audit),
            strict_public=args.strict_public,
        )
    if args.promote_public_pqczip:
        return print_promote_public_pqczip(
            args.promote_public_pqczip,
            apply_promote=args.apply_promote,
            yes=args.yes,
        )
    if args.final_release_doctor:
        return print_final_public_release_doctor(
            write_report=(args.write_report or args.write_final_release_report),
            strict_public=args.strict_public,
        )
    if args.gui:
        return open_gui()
    if args.launch_game:
        return print_launch_game_direct([])

# BEGIN C10E_R2C_EMERGENCY_DISPATCHER

def _c10e_r2c_direct_launch(extra_args=None):
    """
    Direct runtime launcher.

    Never calls ./cryptochess.sh from inside the manager.
    That avoids wrapper recursion.
    """
    extra_args = list(extra_args or [])
    root = Path.cwd()

    print("Launching CryptoChess from restored runtime checkout.", flush=True)
    print("No automatic return/repack will be performed by this manager.", flush=True)

    restore_cmd = [sys.executable, Path(__file__).name, "restore-runtime"]
    restore = subprocess.run(restore_cmd, cwd=root)

    if restore.returncode != 0:
        print(json.dumps({
            "command": "launch",
            "passed": False,
            "error": "runtime restore failed",
            "restore_returncode": restore.returncode,
        }, indent=2, sort_keys=True), flush=True)
        return restore.returncode

    runtime_dir = root / ".cryptochess_runtime"
    core_dir = runtime_dir / "core"
    asset_dir = runtime_dir / "assets"
    data_dir = asset_dir / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    candidates = [
        core_dir / "CryptoChess.py",
        core_dir / "cryptochess_app.py",
    ]
    core_entry = next((x for x in candidates if x.exists()), None)

    if not core_entry:
        print(json.dumps({
            "command": "launch",
            "passed": False,
            "error": "runtime core entry not found",
            "checked": [x.as_posix() for x in candidates],
        }, indent=2, sort_keys=True), flush=True)
        return 1

    env = os.environ.copy()
    env["CRYPTOCHESS_REPO_ROOT"] = root.as_posix()
    env["CRYPTOCHESS_RUNTIME_DIR"] = runtime_dir.as_posix()
    env["CRYPTOCHESS_CORE_DIR"] = core_dir.as_posix()
    env["CRYPTOCHESS_ASSET_DIR"] = asset_dir.as_posix()
    env["CRYPTOCHESS_DATA_DIR"] = data_dir.as_posix()
    env["CRYPTOCHESS_PUBLIC_RELEASE"] = "1"

    old_pythonpath = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = core_dir.as_posix() + (os.pathsep + old_pythonpath if old_pythonpath else "")

    print(json.dumps({
        "command": "launch",
        "passed": True,
        "mode": "direct-runtime",
        "wrapper_recursion": False,
        "core_entry": core_entry.relative_to(root).as_posix(),
        "asset_dir": asset_dir.relative_to(root).as_posix(),
        "data_dir": data_dir.relative_to(root).as_posix(),
    }, indent=2, sort_keys=True), flush=True)

    return subprocess.call([sys.executable, core_entry.as_posix()] + extra_args, cwd=asset_dir, env=env)


def main(argv=None):
    """
    C10E-R2C emergency dispatcher.

    Only launch commands are intercepted here.
    Everything else is delegated to the existing manager main.
    """
    argv = list(sys.argv[1:] if argv is None else argv)

    if argv:
        cmd = argv[0]
        rest = argv[1:]

        if cmd in {"run", "launch", "launch-game", "--launch-game"}:
            return _c10e_r2c_direct_launch(rest)

    return _c10_original_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())

# END C10E_R2C_EMERGENCY_DISPATCHER

