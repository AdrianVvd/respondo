import json
from typing import Any


def _json_segments(text: str) -> list[tuple[int, int]]:
    segments: list[tuple[int, int]] = []
    stack: list[str] = []
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


def find_first_json(text: str) -> Any:
    for start, end in _json_segments(text):
        chunk = text[start:end]
        try:
            return json.loads(chunk)
        except Exception:
            continue
    return None


def find_all_json(text: str) -> list[Any]:
    items: list[Any] = []
    for start, end in _json_segments(text):
        chunk = text[start:end]
        try:
            items.append(json.loads(chunk))
        except Exception:
            continue
    return items


def json_get(obj: Any, *path: Any) -> Any:
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
