import json
import re
from typing import Any, Dict, Optional

from htmlutil import strip_scripts_styles as _strip_scripts_styles
from htmlutil import extract_links as _extract_links
from htmlutil import json_in_html as _json_in_html


class Response:
    def __init__(self, status: int, headers: Dict[str, str], body: bytes, raw_headers: Optional[list[tuple[str, str]]] = None):
        self.status = status
        self.headers = headers
        self.body = body
        pairs = raw_headers or []
        self._headers_multi: Dict[str, list[str]] = {}
        for k, v in pairs:
            lk = k.lower()
            self._headers_multi.setdefault(lk, []).append(v)
        for k, v in headers.items():
            lk = k.lower()
            if lk not in self._headers_multi:
                self._headers_multi[lk] = [v]

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self) -> Any:
        return json.loads(self.body)

    def is_informational(self) -> bool:
        return 100 <= self.status < 200

    def is_success(self) -> bool:
        return 200 <= self.status < 300

    def is_redirect(self) -> bool:
        return 300 <= self.status < 400

    def is_client_error(self) -> bool:
        return 400 <= self.status < 500

    def is_server_error(self) -> bool:
        return 500 <= self.status < 600

    def header(self, name: str) -> str:
        values = self.headers_all(name)
        return values[0] if values else ""

    def headers_all(self, name: str) -> list[str]:
        return list(self._headers_multi.get(name.lower(), []))

    def cookies(self) -> list[dict[str, Any]]:
        set_cookies = self._headers_multi.get("set-cookie", [])
        cookies: list[dict[str, Any]] = []
        for raw in set_cookies:
            parts = [p.strip() for p in raw.split(";") if p.strip()]
            if not parts or "=" not in parts[0]:
                continue
            name, value = parts[0].split("=", 1)
            attrs: Dict[str, str] = {}
            for attr in parts[1:]:
                if "=" in attr:
                    k, v = attr.split("=", 1)
                    attrs[k.strip().lower()] = v.strip().strip('"')
                else:
                    attrs[attr.strip().lower()] = ""
            cookies.append({"name": name.strip(), "value": value.strip(), "attrs": attrs})
        return cookies

    def content_type(self) -> tuple[str, str]:
        raw = self.header("content-type")
        if not raw:
            return "", ""
        parts = [p.strip() for p in raw.split(";") if p.strip()]
        media_type = parts[0].lower() if parts else ""
        charset = ""
        for part in parts[1:]:
            if part.lower().startswith("charset="):
                charset = part.split("=", 1)[1].strip().strip('"').lower()
                break
        return media_type, charset

    def charset_sniff(self) -> tuple[str, str]:
        """
        Detect charset from Content-Type or meta tags, then decode body.
        Returns (text, charset).
        """
        ct_charset = self.content_type()[1]
        candidates = []
        if ct_charset:
            candidates.append(ct_charset)
        meta_match = re.search(
            r'<meta[^>]+charset=["\']?([A-Za-z0-9._-]+)["\']?',
            self.body.decode("ascii", errors="ignore"),
            flags=re.IGNORECASE,
        )
        if meta_match:
            candidates.append(meta_match.group(1))
        for charset in candidates + ["utf-8", "latin-1"]:
            try:
                return self.body.decode(charset, errors="replace"), charset.lower()
            except Exception:
                continue
        return self.body.decode("utf-8", errors="replace"), "utf-8"

    def strip_scripts_styles(self) -> str:
        return _strip_scripts_styles(self.text)

    def extract_links(self, base: str | None = None, same_host: bool = False, extensions: list[str] | None = None) -> list[str]:
        return _extract_links(self.text, base=base, same_host=same_host, extensions=extensions)

    def extract_json(self) -> list[Any]:
        return _json_in_html(self.text)
