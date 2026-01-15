"""
HTTP Response Handling Module

Provides a Response class for handling HTTP responses with convenient methods
for status checking, header access, cookie parsing, and content extraction.
"""

import json
import os
import re
import zipfile
from typing import Any, Dict, List, Optional, Tuple

# Import from htmlparse module
from htmlparse import strip_scripts_styles as _strip_scripts_styles
from htmlparse import extract_links as _extract_links
from htmlparse import json_in_html as _json_in_html


class Response:
    """
    HTTP Response wrapper with convenient access methods.

    Attributes:
        status: HTTP status code
        headers: Response headers (dict)
        body: Raw response body (bytes)
    """

    def __init__(
        self,
        status: int,
        headers: Dict[str, str],
        body: bytes,
        raw_headers: Optional[List[Tuple[str, str]]] = None
    ):
        """
        Initialize Response.

        Args:
            status: HTTP status code
            headers: Response headers
            body: Raw response body
            raw_headers: Optional list of (name, value) tuples for multi-value headers
        """
        self.status = status
        self.headers = headers
        self.body = body
        pairs = raw_headers or []
        self._headers_multi: Dict[str, List[str]] = {}
        for k, v in pairs:
            lk = k.lower()
            self._headers_multi.setdefault(lk, []).append(v)
        for k, v in headers.items():
            lk = k.lower()
            if lk not in self._headers_multi:
                self._headers_multi[lk] = [v]

    @property
    def text(self) -> str:
        """Get response body as text (UTF-8 decoded)."""
        return self.body.decode("utf-8", errors="replace")

    def json(self) -> Any:
        """Parse response body as JSON."""
        return json.loads(self.body)

    # Status checks

    def is_informational(self) -> bool:
        """Check if status is 1xx (informational)."""
        return 100 <= self.status < 200

    def is_success(self) -> bool:
        """Check if status is 2xx (success)."""
        return 200 <= self.status < 300

    def is_redirect(self) -> bool:
        """Check if status is 3xx (redirect)."""
        return 300 <= self.status < 400

    def is_client_error(self) -> bool:
        """Check if status is 4xx (client error)."""
        return 400 <= self.status < 500

    def is_server_error(self) -> bool:
        """Check if status is 5xx (server error)."""
        return 500 <= self.status < 600

    # Header access

    def header(self, name: str) -> str:
        """
        Get header value (case-insensitive).

        Args:
            name: Header name

        Returns:
            First header value, or empty string if not found
        """
        values = self.headers_all(name)
        return values[0] if values else ""

    def headers_all(self, name: str) -> List[str]:
        """
        Get all values for a header (case-insensitive).

        Args:
            name: Header name

        Returns:
            List of header values
        """
        return list(self._headers_multi.get(name.lower(), []))

    def cookies(self) -> List[Dict[str, Any]]:
        """
        Parse Set-Cookie headers.

        Returns:
            List of cookie dicts with 'name', 'value', 'attrs'
        """
        set_cookies = self._headers_multi.get("set-cookie", [])
        cookies: List[Dict[str, Any]] = []
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

    def content_type(self) -> Tuple[str, str]:
        """
        Parse Content-Type header.

        Returns:
            Tuple of (media_type, charset)
        """
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

    def charset_sniff(self) -> Tuple[str, str]:
        """
        Detect charset from Content-Type or meta tags, then decode body.

        Returns:
            Tuple of (text, charset)
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

    # HTML convenience methods

    def strip_scripts_styles(self) -> str:
        """Remove scripts and styles from HTML body, return text."""
        return _strip_scripts_styles(self.text)

    def extract_links(
        self,
        base: Optional[str] = None,
        same_host: bool = False,
        extensions: Optional[List[str]] = None
    ) -> List[str]:
        """Extract all links from HTML body."""
        return _extract_links(self.text, base=base, same_host=same_host, extensions=extensions)

    def extract_json(self) -> List[Any]:
        """Extract embedded JSON from HTML body."""
        return _json_in_html(self.text)

    # File operations

    def save(self, filepath: str) -> bool:
        """
        Save response body to a file.

        Args:
            filepath: Path to save the file to

        Returns:
            True if successful, False on error
        """
        if not filepath:
            return False
        try:
            # Create directory if needed
            directory = os.path.dirname(filepath)
            if directory and not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)
            with open(filepath, "wb") as f:
                f.write(self.body)
            return True
        except Exception:
            return False

    def save_text(self, filepath: str, encoding: str = "utf-8") -> bool:
        """
        Save response body as text to a file.

        Args:
            filepath: Path to save the file to
            encoding: Text encoding (default: utf-8)

        Returns:
            True if successful, False on error
        """
        if not filepath:
            return False
        try:
            directory = os.path.dirname(filepath)
            if directory and not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)
            with open(filepath, "w", encoding=encoding) as f:
                f.write(self.text)
            return True
        except Exception:
            return False

    def save_zip(
        self,
        filepath: str,
        filename: Optional[str] = None,
        compression: int = zipfile.ZIP_DEFLATED
    ) -> bool:
        """
        Save response body to a zip file.

        Args:
            filepath: Path to save the zip file to
            filename: Name of file inside the zip (default: derived from filepath)
            compression: Compression method (default: ZIP_DEFLATED)

        Returns:
            True if successful, False on error
        """
        if not filepath:
            return False
        try:
            directory = os.path.dirname(filepath)
            if directory and not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)
            # Default filename inside zip
            if not filename:
                base = os.path.basename(filepath)
                # Remove .zip extension if present
                if base.lower().endswith(".zip"):
                    filename = base[:-4] or "content"
                else:
                    filename = base + "_content"
            with zipfile.ZipFile(filepath, "w", compression=compression) as zf:
                zf.writestr(filename, self.body)
            return True
        except Exception:
            return False

    def save_json(self, filepath: str, indent: int = 2) -> bool:
        """
        Save response body as formatted JSON to a file.

        Args:
            filepath: Path to save the file to
            indent: JSON indentation (default: 2)

        Returns:
            True if successful, False on error
        """
        if not filepath:
            return False
        try:
            directory = os.path.dirname(filepath)
            if directory and not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)
            data = self.json()
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=indent, ensure_ascii=False)
            return True
        except Exception:
            return False


__all__ = [
    "Response",
]
