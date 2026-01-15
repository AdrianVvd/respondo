"""
JSON Utilities Module

Provides JSON parsing, extraction, and safe nested access.
No external dependencies - uses stdlib only (json).
"""

import json
from typing import Any, List


def _json_segments(text: str) -> List[tuple[int, int]]:
    """Find JSON object/array boundaries in text."""
    segments: List[tuple[int, int]] = []
    stack: List[str] = []
    start = -1
    in_string = False
    escaped = False

    for idx, ch in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
                continue
            if ch == "\\":
                escaped = True
                continue
            if ch == '"':
                in_string = False
            continue

        if ch == '"':
            in_string = True
            continue
        if ch in "{[":
            if not stack:
                start = idx
            stack.append(ch)
        elif ch in "}]":
            if not stack:
                continue
            open_ch = stack.pop()
            if (open_ch == "{" and ch == "}") or (open_ch == "[" and ch == "]"):
                if not stack and start >= 0:
                    segments.append((start, idx + 1))
                    start = -1
            else:
                start = -1
                stack.clear()
    return segments


def find_first(text: str) -> Any:
    """
    Find and parse the first JSON object or array in text.

    Args:
        text: Text that may contain embedded JSON

    Returns:
        Parsed JSON object/array, or None if not found
    """
    for start, end in _json_segments(text):
        chunk = text[start:end]
        try:
            return json.loads(chunk)
        except Exception:
            continue
    return None


def find_all(text: str) -> List[Any]:
    """
    Find and parse all JSON objects and arrays in text.

    Args:
        text: Text that may contain embedded JSON

    Returns:
        List of parsed JSON objects/arrays
    """
    items: List[Any] = []
    for start, end in _json_segments(text):
        chunk = text[start:end]
        try:
            items.append(json.loads(chunk))
        except Exception:
            continue
    return items


def get(obj: Any, *path: Any) -> Any:
    """
    Safely access nested JSON properties.

    Never throws - returns None for any missing key/index.

    Args:
        obj: JSON object (dict or list)
        *path: Keys (str) or indices (int) to traverse

    Returns:
        Value at path, or None if not found

    Examples:
        >>> get({"user": {"name": "Alice"}}, "user", "name")
        'Alice'
        >>> get([{"id": 1}], 0, "id")
        1
        >>> get({}, "missing", "key")
        None
    """
    current = obj
    for part in path:
        if isinstance(part, str):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        elif isinstance(part, int):
            if isinstance(current, list) and 0 <= part < len(current):
                current = current[part]
            else:
                return None
        else:
            return None
    return current


# Aliases for backward compatibility
find_first_json = find_first
find_all_json = find_all
json_get = get


__all__ = [
    "find_first",
    "find_all",
    "get",
    # Aliases
    "find_first_json",
    "find_all_json",
    "json_get",
]
