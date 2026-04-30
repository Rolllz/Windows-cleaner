# WiperX — src/modules/amcache.py
# Парсинг и очистка Windows Amcache.hve
# Зависимости: regipy, config

import os
import csv
import json
import logging
import secrets
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

from regipy.registry import RegistryHive
from regipy.exceptions import RegistryKeyNotFoundException

from config import (
    WIPERX_LOG_LEVEL,
    AMCACHE_PATH,
    SECURE_WIPE_PASSES,
)

logger = logging.getLogger(__name__)
logger.setLevel(WIPERX_LOG_LEVEL)

AMCACHE_DEFAULT = Path(AMCACHE_PATH)

ROOT_FILE              = "Root\\File"
ROOT_INVENTORY_APP     = "Root\\InventoryApplication"
ROOT_INVENTORY_FILE    = "Root\\InventoryFile"
ROOT_INVENTORY_DRIVER  = "Root\\InventoryDriverBinary"

FILE_VALUE_MAP = {
    "0":  "product_name",
    "1":  "company_name",
    "2":  "file_version_number",
    "3":  "language",
    "4":  "switchback_context",
    "5":  "file_version",
    "6":  "file_size",
    "7":  "pe_size_of_image",
    "8":  "pe_header_hash",
    "9":  "pe_header_checksum",
    "a":  "pe_borndate_low",
    "b":  "pe_borndate_high",
    "c":  "file_description",
    "d":  "linker_version",
    "f":  "link_date",
    "10": "bin_file_version",
    "11": "bin_product_version",
    "12": "file_id",
    "13": "last_modified_timestamp",
    "14": "created_timestamp",
    "15": "full_path",
    "16": "program_id",
    "17": "sha1_hash",
    "100": "program_id_ref",
    "101": "pe_checksum",
}


# ──────────────────────────────────────────────────────────────
# УТИЛИТЫ
# ──────────────────────────────────────────────────────────────

def _ts_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _secure_wipe(path: Path, passes: int = SECURE_WIPE_PASSES) -> bool:
    try:
        size = path.stat().st_size
        with open(path, "r+b") as f:
            for _ in range(passes):
                f.seek(0)
                f.write(secrets.token_bytes(size))
                f.flush()
                os.fsync(f.fileno())
        return True
    except Exception as e:
        logger.error(f"[amcache] secure_wipe error: {e}")
        return False


def _open_hive(hive_path: Path) -> Optional[RegistryHive]:
    try:
        hive = RegistryHive(str(hive_path))
        logger.info(f"[amcache] opened hive: {hive_path}")
        return hive
    except Exception as e:
        logger.error(f"[amcache] cannot open hive: {e}")
        return None


def _values_to_dict(key) -> dict:
    result = {}
    try:
        for val in key.get_values():
            name = val.name if val.name else "(default)"
            result[name] = val.value
    except Exception:
        pass
    return result


# ──────────────────────────────────────────────────────────────
# ПАРСИНГ Root\File
# ──────────────────────────────────────────────────────────────

def parse_root_file(hive_path: Path = AMCACHE_DEFAULT) -> list[dict]:
    hive = _open_hive(hive_path)
    if not hive:
        return []

    records = []
    try:
        volume_key = hive.get_key(ROOT_FILE)
        for volume_subkey in volume_key.iter_subkeys():
            volume_guid = volume_subkey.name
            for file_key in volume_subkey.iter_subkeys():
                raw = _values_to_dict(file_key)
                record = {
                    "source":       "Root\\File",
                    "volume_guid":  volume_guid,
                    "entry_id":     file_key.name,
                    "last_write":   file_key.header.last_modified.isoformat()
                                    if file_key.header.last_modified else None,
                }
                for hex_key, friendly in FILE_VALUE_MAP.items():
                    record[friendly] = raw.get(hex_key)
                records.append(record)
    except RegistryKeyNotFoundException:
        logger.warning("[amcache] Root\\File not found")
    except Exception as e:
        logger.error(f"[amcache] parse_root_file error: {e}")

    logger.info(f"[amcache] Root\\File — {len(records)} records")
    return records


# ──────────────────────────────────────────────────────────────
# ПАРСИНГ Root\InventoryApplication
# ──────────────────────────────────────────────────────────────

def parse_inventory_application(hive_path: Path = AMCACHE_DEFAULT) -> list[dict]:
    hive = _open_hive(hive_path)
    if not hive:
        return []

    records = []
    try:
        root_key = hive.get_key(ROOT_INVENTORY_APP)
        for app_key in root_key.iter_subkeys():
            raw = _values_to_dict(app_key)
            record = {
                "source":          "Root\\InventoryApplication",
                "key_name":        app_key.name,
                "last_write":      app_key.header.last_modified.isoformat()
                                   if app_key.header.last_modified else None,
                "name":            raw.get("Name"),
                "version":         raw.get("Version"),
                "publisher":       raw.get("Publisher"),
                "install_date":    raw.get("InstallDate"),
                "root_dir_path":   raw.get("RootDirPath"),
                "uninstall_string":raw.get("UninstallString"),
                "language":        raw.get("Language"),
                "type":            raw.get("Type"),
                "source_field":    raw.get("Source"),
                "program_id":      raw.get("ProgramId"),
                "msi_package_code":raw.get("MsiPackageCode"),
                "msi_product_code":raw.get("MsiProductCode"),
            }
            records.append(record)
    except RegistryKeyNotFoundException:
        logger.warning("[amcache] Root\\InventoryApplication not found")
    except Exception as e:
        logger.error(f"[amcache] parse_inventory_application error: {e}")

    logger.info(f"[amcache] InventoryApplication — {len(records)} records")
    return records


# ──────────────────────────────────────────────────────────────
# ПАРСИНГ Root\InventoryFile
# ──────────────────────────────────────────────────────────────

def parse_inventory_file(hive_path: Path = AMCACHE_DEFAULT) -> list[dict]:
    hive = _open_hive(hive_path)
    if not hive:
        return []

    records = []
    try:
        root_key = hive.get_key(ROOT_INVENTORY_FILE)
        for file_key in root_key.iter_subkeys():
            raw = _values_to_dict(file_key)
            record = {
                "source":       "Root\\InventoryFile",
                "key_name":     file_key.name,
                "last_write":   file_key.header.last_modified.isoformat()
                                if file_key.header.last_modified else None,
                "lower_case_long_path": raw.get("LowerCaseLongPath"),
                "name":                 raw.get("Name"),
                "size":                 raw.get("Size"),
                "product_name":         raw.get("ProductName"),
                "product_version":      raw.get("ProductVersion"),
                "file_version":         raw.get("FileVersion"),
                "bin_product_version":  raw.get("BinProductVersion"),
                "sha1_hash":            raw.get("FileId"),
                "link_date":            raw.get("LinkDate"),
                "program_id":           raw.get("ProgramId"),
                "language":             raw.get("Language"),
                "is_pe_file":           raw.get("IsPeFile"),
                "is_os_component":      raw.get("IsOsComponent"),
            }
            records.append(record)
    except RegistryKeyNotFoundException:
        logger.warning("[amcache] Root\\InventoryFile not found")
    except Exception as e:
        logger.error(f"[amcache] parse_inventory_file error: {e}")

    logger.info(f"[amcache] InventoryFile — {len(records)} records")
    return records


# ──────────────────────────────────────────────────────────────
# ПАРСИНГ Root\InventoryDriverBinary
# ──────────────────────────────────────────────────────────────

def parse_inventory_driver(hive_path: Path = AMCACHE_DEFAULT) -> list[dict]:
    hive = _open_hive(hive_path)
    if not hive:
        return []

    records = []
    try:
        root_key = hive.get_key(ROOT_INVENTORY_DRIVER)
        for drv_key in root_key.iter_subkeys():
            raw = _values_to_dict(drv_key)
            record = {
                "source":              "Root\\InventoryDriverBinary",
                "key_name":            drv_key.name,
                "last_write":          drv_key.header.last_modified.isoformat()
                                       if drv_key.header.last_modified else None,
                "driver_name":         raw.get("DriverName"),
                "driver_version":      raw.get("DriverVersion"),
                "product":             raw.get("Product"),
                "product_version":     raw.get("ProductVersion"),
                "wdf_version":         raw.get("WdfVersion"),
                "driver_company":      raw.get("DriverCompany"),
                "driver_package_strong_name": raw.get("DriverPackageStrongName"),
                "driver_signed":       raw.get("DriverSigned"),
                "driver_is_kernel_mode": raw.get("DriverIsKernelMode"),
                "driver_last_write_time": raw.get("DriverLastWriteTime"),
                "driver_timestamp":    raw.get("DriverTimestamp"),
                "inf":                 raw.get("Inf"),
                "image_size":          raw.get("ImageSize"),
                "sha1_hash":           raw.get("DriverId"),
                "service":             raw.get("Service"),
            }
            records.append(record)
    except RegistryKeyNotFoundException:
        logger.warning("[amcache] Root\\InventoryDriverBinary not found")
    except Exception as e:
        logger.error(f"[amcache] parse_inventory_driver error: {e}")

    logger.info(f"[amcache] InventoryDriverBinary — {len(records)} records")
    return records


# ──────────────────────────────────────────────────────────────
# ПОИСК
# ──────────────────────────────────────────────────────────────

def search_records(
    hive_path: Path = AMCACHE_DEFAULT,
    filename:  Optional[str] = None,
    sha1:      Optional[str] = None,
    path_contains: Optional[str] = None,
    sources: list[str] | None = None,
) -> list[dict]:

    all_sources = {
        "root_file":   parse_root_file,
        "inv_app":     parse_inventory_application,
        "inv_file":    parse_inventory_file,
        "inv_driver":  parse_inventory_driver,
    }

    active = {k: v for k, v in all_sources.items()
              if sources is None or k in sources}

    results = []
    for key, parser in active.items():
        for rec in parser(hive_path):
            match = True

            if filename:
                name_fields = [
                    str(rec.get("full_path", "") or ""),
                    str(rec.get("name", "") or ""),
                    str(rec.get("lower_case_long_path", "") or ""),
                    str(rec.get("driver_name", "") or ""),
                ]
                if not any(filename.lower() in f.lower() for f in name_fields):
                    match = False

            if sha1 and match:
                hash_fields = [
                    str(rec.get("sha1_hash", "") or ""),
                    str(rec.get("file_id", "") or ""),
                ]
                if not any(sha1.lower() in h.lower() for h in hash_fields):
                    match = False

            if path_contains and match:
                path_fields = [
                    str(rec.get("full_path", "") or ""),
                    str(rec.get("lower_case_long_path", "") or ""),
                    str(rec.get("root_dir_path", "") or ""),
                ]
                if not any(path_contains.lower() in p.lower() for p in path_fields):
                    match = False

            if match:
                results.append(rec)

    logger.info(f"[amcache] search → {len(results)} matches")
    return results


# ──────────────────────────────────────────────────────────────
# УДАЛЕНИЕ / WIPE (копия hive + offline-патч)
# ──────────────────────────────────────────────────────────────

def wipe_hive(
    hive_path: Path = AMCACHE_DEFAULT,
    backup: bool = True,
    secure: bool = True,
) -> dict:
    result = {
        "hive_path": str(hive_path),
        "backup":    None,
        "wiped":     False,
        "timestamp": _ts_now(),
        "error":     None,
    }

    if not hive_path.exists():
        result["error"] = "hive not found"
        return result

    if backup:
        backup_path = hive_path.with_suffix(".hve.bak")
        try:
            import shutil
            shutil.copy2(hive_path, backup_path)
            result["backup"] = str(backup_path)
            logger.info(f"[amcache] backup → {backup_path}")
        except Exception as e:
            result["error"] = f"backup failed: {e}"
            return result

    if secure:
        _secure_wipe(hive_path)

    try:
        hive_path.write_bytes(b"\x00" * hive_path.stat().st_size)
        result["wiped"] = True
        logger.info(f"[amcache] hive wiped: {hive_path}")
    except Exception as e:
        result["error"] = str(e)
        logger.error(f"[amcache] wipe_hive error: {e}")

    return result


def delete_hive(
    hive_path: Path = AMCACHE_DEFAULT,
    secure: bool = True,
) -> dict:
    result = {
        "hive_path": str(hive_path),
        "deleted":   False,
        "timestamp": _ts_now(),
        "error":     None,
    }

    if not hive_path.exists():
        result["error"] = "hive not found"
        return result

    if secure:
        _secure_wipe(hive_path)

    try:
        hive_path.unlink()
        result["deleted"] = True
        logger.info(f"[amcache] hive deleted: {hive_path}")
    except Exception as e:
        result["error"] = str(e)
        logger.error(f"[amcache] delete_hive error: {e}")

    return result


# ──────────────────────────────────────────────────────────────
# ЭКСПОРТ
# ──────────────────────────────────────────────────────────────

def export_json(records: list[dict], output_path: Path) -> bool:
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(records, f, ensure_ascii=False, indent=2, default=str)
        logger.info(f"[amcache] JSON export → {output_path}")
        return True
    except Exception as e:
        logger.error(f"[amcache] export_json error: {e}")
        return False


def export_csv(records: list[dict], output_path: Path) -> bool:
    if not records:
        logger.warning("[amcache] export_csv: no records")
        return False
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        fieldnames = sorted({k for r in records for k in r.keys()})
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(records)
        logger.info(f"[amcache] CSV export → {output_path}")
        return True
    except Exception as e:
        logger.error(f"[amcache] export_csv error: {e}")
        return False


# ──────────────────────────────────────────────────────────────
# ОТЧЁТ
# ──────────────────────────────────────────────────────────────

def report(hive_path: Path = AMCACHE_DEFAULT) -> dict:
    root_file  = parse_root_file(hive_path)
    inv_app    = parse_inventory_application(hive_path)
    inv_file   = parse_inventory_file(hive_path)
    inv_driver = parse_inventory_driver(hive_path)

    return {
        "timestamp":           _ts_now(),
        "hive_path":           str(hive_path),
        "root_file_count":     len(root_file),
        "inv_app_count":       len(inv_app),
        "inv_file_count":      len(inv_file),
        "inv_driver_count":    len(inv_driver),
        "total":               len(root_file) + len(inv_app) +
                               len(inv_file)  + len(inv_driver),
        "root_file":           root_file,
        "inv_app":             inv_app,
        "inv_file":            inv_file,
        "inv_driver":          inv_driver,
    }
