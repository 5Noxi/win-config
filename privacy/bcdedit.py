from __future__ import annotations

from collections import defaultdict
import re
from typing import Any, Callable, Optional

RunCommand = Callable[[list[str]], Any]
RunSubprocess = Callable[..., Any]

_RUN_COMMAND: Optional[RunCommand] = None
_RUN_SUBPROCESS: Optional[RunSubprocess] = None
_BCDEDIT_CACHE: Optional[dict[str, list[tuple[str, str]]]] = None
_BCD_OBJECT_ID_CACHE: dict[str, str] = {}
_BOOL_TRUE = {"true", "yes", "1", "on", "enabled"}
_BOOL_FALSE = {"false", "no", "0", "off", "disabled"}
_BCD_GUID_RE = re.compile(r"^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$")


def configure(*, run_command: RunCommand, run_subprocess: RunSubprocess) -> None:
    global _RUN_COMMAND, _RUN_SUBPROCESS
    _RUN_COMMAND = run_command
    _RUN_SUBPROCESS = run_subprocess

def _require_run_command() -> RunCommand:
    if _RUN_COMMAND is None:
        raise RuntimeError("bcdedit helpers not configured (run_command missing)")
    return _RUN_COMMAND

def _require_run_subprocess() -> RunSubprocess:
    if _RUN_SUBPROCESS is None:
        raise RuntimeError("bcdedit helpers not configured (run_subprocess missing)")
    return _RUN_SUBPROCESS

def _invalidate_cache() -> None:
    global _BCDEDIT_CACHE, _BCD_OBJECT_ID_CACHE
    _BCDEDIT_CACHE = None
    _BCD_OBJECT_ID_CACHE.clear()


def _normalize_identifier(value: Optional[str]) -> Optional[str]:
    text = str(value or "").strip()
    if not text:
        return None
    lowered = text.lower()
    if lowered.startswith("{") and lowered.endswith("}"):
        return lowered
    return f"{{{lowered}}}"


def _normalize_bcd_bool(value: Optional[str]) -> Optional[str]:
    if value is True:
        return "true"
    if value is False:
        return "false"
    text = str(value or "").strip().lower()
    if not text:
        return None
    if text in _BOOL_TRUE:
        return "true"
    if text in _BOOL_FALSE:
        return "false"
    return text


def _prefer_identifier_matches(
    matches: list[tuple[str, str]], preferred_identifiers: tuple[str, ...]
) -> list[tuple[str, str]]:
    if not matches:
        return matches
    preferred_norms = []
    for value in preferred_identifiers:
        normalized = _normalize_identifier(value)
        if not normalized:
            continue
        if _BCD_GUID_RE.fullmatch(normalized):
            preferred_norms.append(normalized)
            continue
        resolved = _resolve_bcd_object_id(normalized)
        if resolved:
            preferred_norms.append(resolved)
    if not preferred_norms:
        return matches
    for preferred_norm in preferred_norms:
        subset = [entry for entry in matches if entry[0] == preferred_norm]
        if subset:
            return subset
    return matches

def _parse_bcdedit_output(raw_output: str) -> dict[str, list[tuple[str, str]]]:
    entries: dict[str, list[tuple[str, str]]] = defaultdict(list)
    current_identifier = ""
    for line in raw_output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            key, value = stripped.split(None, 1)
        except ValueError:
            continue
        key_lower = key.lower()
        value_text = value.strip()
        if key_lower == "identifier":
            current_identifier = value_text.lower()
            continue
        entries[key_lower].append((current_identifier, value_text))
    return entries


def _run_bcdedit_enum(args: list[str]) -> str:
    run_subprocess = _require_run_subprocess()
    completed = run_subprocess(
        ["bcdedit", *args],
        capture_output=True,
        text=True,
        shell=False,
    )
    if completed.returncode != 0:
        return ""
    return completed.stdout or ""


def _extract_identifier_from_output(raw_output: str) -> Optional[str]:
    for line in raw_output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        parts = stripped.split(None, 1)
        if len(parts) != 2:
            continue
        if parts[0].lower() == "identifier":
            return parts[1].strip().lower()
    return None


def _resolve_bcd_object_id(alias: str) -> Optional[str]:
    key = alias.strip().lower().strip("{}")
    cached = _BCD_OBJECT_ID_CACHE.get(key)
    if cached:
        return cached
    output = _run_bcdedit_enum(["/enum", f"{{{key}}}", "/v"])
    identifier = _extract_identifier_from_output(output)
    if identifier:
        _BCD_OBJECT_ID_CACHE[key] = identifier
        return identifier
    return None


def _run_bcdedit_command(args: list[str]) -> None:
    _require_run_command()(["bcdedit", *args])
    _invalidate_cache()


def resolve_bcd_object_guid(object_name: Optional[str]) -> str:
    text = str(object_name or "").strip()
    if not text:
        raise ValueError("BCD object is required")
    normalized = _normalize_identifier(text)
    if not normalized:
        raise ValueError("BCD object is required")
    if _BCD_GUID_RE.fullmatch(normalized):
        return normalized.lower()
    fallback = _resolve_bcd_object_id(normalized.strip("{}"))
    if fallback:
        return fallback
    raise RuntimeError(f"Unable to resolve BCD object GUID for {text}")


def build_bcd_registry_payload(object_name: Optional[str], values_map: dict) -> dict:
    guid = resolve_bcd_object_guid(object_name)
    if not isinstance(values_map, dict) or not values_map:
        raise ValueError("Values map is required for BCD registry payload")
    payload: dict[str, dict] = {}
    for raw_path, entries in values_map.items():
        if not isinstance(raw_path, str):
            raise ValueError("BCD registry path must be a string")
        if not isinstance(entries, dict):
            raise ValueError(f"Invalid registry entries for {raw_path}")
        resolved_path = raw_path.replace("{GUID}", guid).replace("{guid}", guid)
        payload[resolved_path] = dict(entries)
    return payload


def _resolve_target_identifier(identifier: Optional[str]) -> Optional[str]:
    normalized = _normalize_identifier(identifier)
    if not normalized:
        return None
    if _BCD_GUID_RE.fullmatch(normalized):
        return normalized
    return resolve_bcd_object_guid(normalized)

def refresh_cache(force: bool = False) -> dict[str, list[tuple[str, str]]]:
    global _BCDEDIT_CACHE
    if not force and _BCDEDIT_CACHE is not None:
        return _BCDEDIT_CACHE

    run_subprocess = _require_run_subprocess()
    try:
        completed = run_subprocess(
            ["bcdedit", "/enum", "all", "/v"],
            capture_output=True,
            text=True,
            shell=False,
        )
        if completed.returncode != 0:
            _BCDEDIT_CACHE = {}
            return _BCDEDIT_CACHE
        stdout = completed.stdout or ""
        if not stdout:
            _BCDEDIT_CACHE = {}
            return _BCDEDIT_CACHE
        _BCDEDIT_CACHE = _parse_bcdedit_output(stdout)
        return _BCDEDIT_CACHE
    except Exception:
        _BCDEDIT_CACHE = {}
        return _BCDEDIT_CACHE


def set_bcdedit(
    name: Optional[str],
    value: Optional[str],
    delete: bool = False,
    identifier: Optional[str] = None,
) -> str:
    option = str(name or "").strip()
    if not option:
        raise ValueError("Name is required for bcdedit action")
    identifier_norm = _normalize_identifier(identifier)

    if delete or value in (None, ""):
        if identifier_norm:
            _run_bcdedit_command(["/deletevalue", identifier_norm, option])
        else:
            _run_bcdedit_command(["/deletevalue", option])
        return f"[+] Deleted {option}"

    raw_value = str(value or "").strip()
    if not raw_value:
        raise ValueError("Value is required when setting a BCD option")

    if identifier_norm:
        _run_bcdedit_command(["/set", identifier_norm, option, raw_value])
    else:
        _run_bcdedit_command(["/set", option, raw_value])
    return f"[+] {option} = {raw_value}"


def check_bcdedit(
    name: Optional[str],
    expected_value: Optional[str],
    identifier: Optional[str] = None,
) -> Optional[bool]:
    option = str(name or "").strip()
    if not option:
        return None
    option_lower = option.lower()
    identifier_norm = _resolve_target_identifier(identifier)
    entries = refresh_cache()
    matches = entries.get(option_lower)
    if not matches:
        return expected_value in (None, "")
    if identifier_norm:
        matches = [entry for entry in matches if entry[0] == identifier_norm]
    else:
        matches = _prefer_identifier_matches(matches, ("{current}", "{default}"))
    if not matches:
        return expected_value in (None, "")
    if expected_value in (None, ""):
        return False
    expected_lower = _normalize_bcd_bool(expected_value)
    for _identifier, current_value in matches:
        current_norm = _normalize_bcd_bool(current_value)
        if current_norm == expected_lower:
            return True
    return False
