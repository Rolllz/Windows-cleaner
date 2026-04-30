# WiperX — src/modules/jumplists.py
# Парсинг и очистка Windows Jump Lists
# automaticDestinations-ms (OLE/CFB) + customDestinations-ms (binary LNK chain)
# Зависимости: olefile, LnkParse3, config

import os
import io
import re
import csv
import json
import struct
import logging
import hashlib
import secrets
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

import olefile
import LnkParse3

from config import (
    WIPERX_LOG_LEVEL,
    JUMPLIST_AUTO_DIRS,
    JUMPLIST_CUSTOM_DIRS,
    SECURE_WIPE_PASSES,
)

logger = logging.getLogger(__name__)
logger.setLevel(WIPERX_LOG_LEVEL)

AUTOMATIC_EXT = ".automaticDestinations-ms"
CUSTOM_EXT    = ".customDestinations-ms"

DESTLIST_HEADER_SIZE = 32
DESTLIST_ENTRY_SIZE  = 114


# ──────────────────────────────────────────────────────────────
# УТИЛИТЫ
# ──────────────────────────────────────────────────────────────

def _filetime_to_dt(filetime: int) -> Optional[datetime]:
    if filetime == 0:
        return None
    try:
        ts = (filetime - 116444736000000000) / 10_000_000
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    except Exception:
        return None


def _secure_wipe(path: Path, passes: int = SECURE_WIPE_PASSES) -> bool:
    try:
        size = path.stat().st_size
        with open(path, "r+b") as f:
            for _ in range(passes):
                f.seek(0)
                f.write(secrets.token_bytes(size))
                f.flush()
                os.fsync(f.fileno())
        path.unlink()
        logger.debug(f"Wiped: {path}")
        return True
    except Exception as e:
        logger.error(f"Wipe failed [{path}]: {e}")
        return False


def _parse_lnk_bytes(data: bytes) -> dict:
    try:
        lnk = LnkParse3.lnk_file(indata=io.BytesIO(data))
        info = lnk.get_json()
        return info if isinstance(info, dict) else json.loads(info)
    except Exception:
        return {}


def _appid_from_filename(filename: str) -> str:
    return filename.split(".")[0]


# ──────────────────────────────────────────────────────────────
# ПАРСИНГ automaticDestinations-ms  (OLE/CFB)
# ──────────────────────────────────────────────────────────────

def _parse_destlist_entry(data: bytes, offset: int) -> Optional[dict]:
    try:
        entry = {}
        entry["checksum"]     = struct.unpack_from("<I", data, offset)[0]
        entry["new_volume"]   = data[offset+4:offset+8].hex()
        entry["object_id"]    = data[offset+8:offset+24].hex()
        entry["birth_volume"] = data[offset+24:offset+40].hex()
        entry["birth_object"] = data[offset+40:offset+56].hex()

        net_name_offset  = struct.unpack_from("<I", data, offset+72)[0]
        device_offset    = struct.unpack_from("<I", data, offset+76)[0]

        entry["access_count"]  = struct.unpack_from("<I", data, offset+88)[0]
        filetime_val           = struct.unpack_from("<Q", data, offset+96)[0]
        entry["last_accessed"] = _filetime_to_dt(filetime_val).isoformat() if _filetime_to_dt(filetime_val) else None
        entry["pin_status"]    = struct.unpack_from("<I", data, offset+104)[0]

        str_offset = offset + DESTLIST_ENTRY_SIZE
        path_len   = struct.unpack_from("<H", data, str_offset)[0]
        path_raw   = data[str_offset+2 : str_offset+2 + path_len*2]
        entry["target_path"] = path_raw.decode("utf-16-le", errors="replace")

        return entry
    except Exception as e:
        logger.debug(f"DestList entry parse error at offset {offset}: {e}")
        return None


def _parse_destlist(raw: bytes) -> list[dict]:
    entries = []
    if len(raw) < DESTLIST_HEADER_SIZE:
        return entries
    count = struct.unpack_from("<I", raw, 4)[0]
    offset = DESTLIST_HEADER_SIZE
    for _ in range(count):
        entry = _parse_destlist_entry(raw, offset)
        if entry:
            entries.append(entry)
            entry_total = DESTLIST_ENTRY_SIZE + 2 + len(entry.get("target_path","")) * 2
            offset += entry_total
        else:
            break
    return entries


def parse_automatic(path: Path) -> dict:
    result = {
        "file":    str(path),
        "app_id":  _appid_from_filename(path.name),
        "type":    "automatic",
        "entries": [],
        "destlist": [],
    }
    try:
        if not olefile.isOleFile(path):
            logger.warning(f"Not a valid OLE file: {path}")
            return result

        ole = olefile.OleFileIO(path)
        streams = ole.listdir()

        if ole.exists("DestList"):
            raw_dest = ole.openstream("DestList").read()
            result["destlist"] = _parse_destlist(raw_dest)

        for stream in streams:
            name = stream[0] if len(stream) == 1 else "/".join(stream)
            if re.match(r"^[0-9a-fA-F]+$", name.split("/")[-1]):
                try:
                    data = ole.openstream(stream).read()
                    lnk_info = _parse_lnk_bytes(data)
                    lnk_info["stream"] = name
                    result["entries"].append(lnk_info)
                except Exception as e:
                    logger.debug(f"Stream {name} parse error: {e}")

        ole.close()
    except Exception as e:
        logger.error(f"parse_automatic [{path}]: {e}")

    return result


# ──────────────────────────────────────────────────────────────
# ПАРСИНГ customDestinations-ms  (binary LNK chain)
# ──────────────────────────────────────────────────────────────

LNK_MAGIC = b"\x4C\x00\x00\x00\x01\x14\x02\x00"

def parse_custom(path: Path) -> dict:
    result = {
        "file":    str(path),
        "app_id":  _appid_from_filename(path.name),
        "type":    "custom",
        "entries": [],
    }
    try:
        data = path.read_bytes()
        positions = [m.start() for m in re.finditer(re.escape(LNK_MAGIC), data)]
        for pos in positions:
            chunk = data[pos:]
            lnk_info = _parse_lnk_bytes(chunk)
            if lnk_info:
                lnk_info["offset"] = pos
                result["entries"].append(lnk_info)
    except Exception as e:
        logger.error(f"parse_custom [{path}]: {e}")
    return result


# ──────────────────────────────────────────────────────────────
# ПОИСК ФАЙЛОВ
# ──────────────────────────────────────────────────────────────

def find_jumplist_files(
    dirs: Optional[list[str]] = None,
    include_auto:   bool = True,
    include_custom: bool = True,
) -> list[Path]:
    search_dirs = [Path(d) for d in (dirs or JUMPLIST_AUTO_DIRS + JUMPLIST_CUSTOM_DIRS)]
    found = []
    for d in search_dirs:
        if not d.exists():
            continue
        for f in d.iterdir():
            if include_auto   and f.suffix.lower() == AUTOMATIC_EXT.split(".")[-1] and "automaticDestinations" in f.name:
                found.append(f)
            if include_custom and f.suffix.lower() == CUSTOM_EXT.split(".")[-1]    and "customDestinations"   in f.name:
                found.append(f)
    return found


# ──────────────────────────────────────────────────────────────
# ПАРСИНГ ВСЕГО
# ──────────────────────────────────────────────────────────────

def parse_all(dirs: Optional[list[str]] = None) -> list[dict]:
    results = []
    for path in find_jumplist_files(dirs):
        if "automaticDestinations" in path.name:
            results.append(parse_automatic(path))
        elif "customDestinations" in path.name:
            results.append(parse_custom(path))
    return results


# ──────────────────────────────────────────────────────────────
# ФИЛЬТРАЦИЯ
# ──────────────────────────────────────────────────────────────

def filter_by_app_id(results: list[dict], app_id: str) -> list[dict]:
    return [r for r in results if r.get("app_id", "").lower() == app_id.lower()]


def filter_by_target_path(results: list[dict], pattern: str) -> list[dict]:
    rx = re.compile(pattern, re.IGNORECASE)
    matched = []
    for r in results:
        hits = []
        for e in r.get("entries", []):
            tp = e.get("target", {}).get("target_file_dosname", "") or \
                 e.get("link_info", {}).get("local_base_path", "")
            if rx.search(tp):
                hits.append(e)
        if hits:
            matched.append({**r, "entries": hits})
    return matched


# ──────────────────────────────────────────────────────────────
# УДАЛЕНИЕ
# ──────────────────────────────────────────────────────────────

def delete_by_app_id(
    app_id:  str,
    dirs:    Optional[list[str]] = None,
    secure:  bool = True,
) -> list[str]:
    deleted = []
    for path in find_jumplist_files(dirs):
        if _appid_from_filename(path.name).lower() == app_id.lower():
            ok = _secure_wipe(path) if secure else (path.unlink(), True)[1]
            if ok:
                deleted.append(str(path))
    return deleted


def delete_by_target_path(
    pattern: str,
    dirs:    Optional[list[str]] = None,
    secure:  bool = True,
) -> list[str]:
    all_parsed = parse_all(dirs)
    matched    = filter_by_target_path(all_parsed, pattern)
    deleted    = []
    for r in matched:
        path = Path(r["file"])
        if path.exists():
            ok = _secure_wipe(path) if secure else (path.unlink(), True)[1]
            if ok:
                deleted.append(str(path))
    return deleted


def delete_all(
    dirs:   Optional[list[str]] = None,
    secure: bool = True,
) -> list[str]:
    deleted = []
    for path in find_jumplist_files(dirs):
        ok = _secure_wipe(path) if secure else (path.unlink(), True)[1]
        if ok:
            deleted.append(str(path))
    return deleted


# ──────────────────────────────────────────────────────────────
# ЭКСПОРТ
# ──────────────────────────────────────────────────────────────

def export_json(results: list[dict], out_path: str) -> bool:
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False, default=str)
        logger.info(f"JSON exported → {out_path}")
        return True
    except Exception as e:
        logger.error(f"export_json: {e}")
        return False


def export_csv(results: list[dict], out_path: str) -> bool:
    rows = []
    for r in results:
        for e in r.get("entries", []):
            rows.append({
                "file":        r["file"],
                "app_id":      r["app_id"],
                "type":        r["type"],
                "target_path": e.get("target", {}).get("target_file_dosname", ""),
                "local_path":  e.get("link_info", {}).get("local_base_path", ""),
                "created":     e.get("header", {}).get("creation_time", ""),
                "modified":    e.get("header", {}).get("write_time", ""),
                "accessed":    e.get("header", {}).get("access_time", ""),
                "machine_id":  e.get("extra", {}).get("machine_id", ""),
            })
    try:
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys() if rows else [])
            writer.writeheader()
            writer.writerows(rows)
        logger.info(f"CSV exported → {out_path}")
        return True
    except Exception as e:
        logger.error(f"export_csv: {e}")
        return False


# ──────────────────────────────────────────────────────────────
# ХЭШИ / ЦЕЛОСТНОСТЬ
# ──────────────────────────────────────────────────────────────

def hash_jumplist_files(dirs: Optional[list[str]] = None) -> dict[str, str]:
    hashes = {}
    for path in find_jumplist_files(dirs):
        try:
            data = path.read_bytes()
            hashes[str(path)] = hashlib.sha256(data).hexdigest()
        except Exception as e:
            logger.error(f"hash [{path}]: {e}")
    return hashes


# ──────────────────────────────────────────────────────────────
# БЫСТРЫЙ ОТЧЁТ
# ──────────────────────────────────────────────────────────────

def report(dirs: Optional[list[str]] = None) -> dict:
    all_parsed = parse_all(dirs)
    total_files   = len(all_parsed)
    total_entries = sum(len(r.get("entries", [])) for r in all_parsed)
    app_ids = list({r["app_id"] for r in all_parsed})
    return {
        "total_files":   total_files,
        "total_entries": total_entries,
        "app_ids":       app_ids,
        "files":         [r["file"] for r in all_parsed],
    }
