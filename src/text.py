import base64
import html
import json
import re
import unicodedata
import urllib.parse
from typing import Any, Mapping, Sequence


def between(s: str, left: str, right: str) -> str:
    if not left or not right:
        return ""
    start = s.find(left)
    if start == -1:
        return ""
    start += len(left)
    end = s.find(right, start)
    if end == -1:
        return ""
    return s[start:end]


def betweens(s: str, left: str, right: str) -> list[str]:
    if not left or not right:
        return []
    res: list[str] = []
    pos = 0
    while True:
        start = s.find(left, pos)
        if start == -1:
            break
        start += len(left)
        end = s.find(right, start)
        if end == -1:
            break
        res.append(s[start:end])
        pos = end + len(right)
    return res


def between_last(s: str, left: str, right: str) -> str:
    if not left or not right:
        return ""
    start = s.rfind(left)
    if start == -1:
        return ""
    start += len(left)
    end = s.find(right, start)
    if end == -1:
        return ""
    return s[start:end]


def between_n(s: str, left: str, right: str, n: int) -> str:
    if n < 1:
        return ""
    matches = betweens(s, left, right)
    if n - 1 < len(matches):
        return matches[n - 1]
    return ""


def normalize_space(s: str) -> str:
    return " ".join(s.split())


def strip_tags(html_text: str) -> str:
    cleaned = re.sub(r"<[^>]*>", " ", html_text, flags=re.DOTALL)
    return normalize_space(cleaned)


def unescape_html(s: str) -> str:
    return html.unescape(s)


def regex_first(s: str, pattern: str) -> str:
    try:
        compiled = re.compile(pattern)
    except re.error:
        return ""
    match = compiled.search(s)
    if not match:
        return ""
    if match.groups():
        return match.group(1)
    return match.group(0)


def regex_all(s: str, pattern: str) -> list[str]:
    try:
        compiled = re.compile(pattern)
    except re.error:
        return []
    results: list[str] = []
    for m in compiled.finditer(s):
        if m.groups():
            results.append(m.group(1))
        else:
            results.append(m.group(0))
    return results


def parse_csrf_token(html_text: str) -> str:
    """
    Extracts a CSRF token from common hidden input, meta, or inline script patterns.
    Returns empty string when not found.
    """
    patterns = [
        r'<input[^>]*name=["\']csrf_token["\'][^>]*value=["\']([^"\']+)["\']',
        r'<input[^>]*name=["\']_csrf["\'][^>]*value=["\']([^"\']+)["\']',
        r'<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)["\']',
        r'<meta[^>]*name=["\']csrf_token["\'][^>]*content=["\']([^"\']+)["\']',
        r"csrfToken\s*[:=]\s*['\"]([^'\"]+)['\"]",
    ]
    for pattern in patterns:
        match = re.search(pattern, html_text, flags=re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1)
    return ""


def url_encode(params: Mapping[str, Any] | Sequence[tuple[str, Any]]) -> str:
    clean_params: Mapping[str, Any] | Sequence[tuple[str, Any]] = params
    if isinstance(params, Mapping):
        clean_params = {k: "" if v is None else v for k, v in params.items()}
    return urllib.parse.urlencode(clean_params, doseq=True)


def url_decode(query: str) -> dict[str, list[str]]:
    return urllib.parse.parse_qs(query, keep_blank_values=True)


def b64_encode(data: str | bytes, *, urlsafe: bool = False) -> str:
    raw = data.encode("utf-8") if isinstance(data, str) else data
    if urlsafe:
        return base64.urlsafe_b64encode(raw).decode("ascii")
    return base64.b64encode(raw).decode("ascii")


def b64_decode(data: str, *, urlsafe: bool = False) -> bytes:
    if not data:
        return b""
    padded = data + "=" * (-len(data) % 4)
    try:
        if urlsafe:
            return base64.urlsafe_b64decode(padded)
        return base64.b64decode(padded)
    except Exception:
        return b""


# =============================================================================
# Validation
# =============================================================================

_EMAIL_PATTERN = re.compile(
    r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
)

_URL_PATTERN = re.compile(
    r"^https?://[^\s/$.?#].[^\s]*$", re.IGNORECASE
)


def is_valid_email(text: str) -> bool:
    """Check if text is a valid email address."""
    if not text or not isinstance(text, str):
        return False
    return bool(_EMAIL_PATTERN.match(text.strip()))


def is_valid_url(text: str) -> bool:
    """Check if text is a valid HTTP/HTTPS URL."""
    if not text or not isinstance(text, str):
        return False
    return bool(_URL_PATTERN.match(text.strip()))


def is_valid_json(text: str) -> bool:
    """Check if text is valid JSON."""
    if not text or not isinstance(text, str):
        return False
    try:
        json.loads(text)
        return True
    except Exception:
        return False


# =============================================================================
# Text Extraction
# =============================================================================

_EMAIL_EXTRACT_PATTERN = re.compile(
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
)

_URL_EXTRACT_PATTERN = re.compile(
    r"https?://[^\s<>\"')\]}>]+", re.IGNORECASE
)

_NUMBER_PATTERN = re.compile(
    r"[$€£¥]?\s*\d+(?:[.,]\d+)*(?:\s*(?:USD|EUR|GBP|JPY|CAD|AUD))?|\d+(?:[.,]\d+)*\s*[$€£¥%]?"
)


def extract_emails(text: str) -> list[str]:
    """Extract all email addresses from text."""
    if not text:
        return []
    return list(set(_EMAIL_EXTRACT_PATTERN.findall(text)))


def extract_urls(text: str) -> list[str]:
    """Extract all URLs from text."""
    if not text:
        return []
    urls = _URL_EXTRACT_PATTERN.findall(text)
    # Clean trailing punctuation
    cleaned = []
    for url in urls:
        url = url.rstrip(".,;:!?")
        if url:
            cleaned.append(url)
    return list(set(cleaned))


def extract_numbers(text: str) -> list[str]:
    """Extract all numbers and prices from text."""
    if not text:
        return []
    matches = _NUMBER_PATTERN.findall(text)
    return [m.strip() for m in matches if m.strip()]


def clean_text(text: str) -> str:
    """
    Clean text by normalizing unicode, removing extra whitespace,
    and converting to consistent format.
    """
    if not text:
        return ""
    # Normalize unicode (NFKC normalizes compatibility characters)
    text = unicodedata.normalize("NFKC", text)
    # Replace common unicode whitespace and dashes
    text = re.sub(r"[\u00a0\u2000-\u200b\u202f\u205f\u3000]", " ", text)
    text = re.sub(r"[\u2013\u2014\u2212]", "-", text)
    text = re.sub(r"[\u2018\u2019\u201a\u201b]", "'", text)
    text = re.sub(r"[\u201c\u201d\u201e\u201f]", '"', text)
    # Collapse whitespace
    text = " ".join(text.split())
    return text.strip()


# =============================================================================
# Social Media Extraction
# =============================================================================

_DISCORD_INVITE_PATTERN = re.compile(
    r"(?:https?://)?(?:www\.)?(?:discord\.gg|discord(?:app)?\.com/invite)/([a-zA-Z0-9-]+)",
    re.IGNORECASE,
)

_TELEGRAM_LINK_PATTERN = re.compile(
    r"(?:https?://)?(?:www\.)?(?:t\.me|telegram\.me)/([a-zA-Z0-9_]+)",
    re.IGNORECASE,
)

_TWITTER_LINK_PATTERN = re.compile(
    r"(?:https?://)?(?:www\.)?(?:twitter\.com|x\.com)/[a-zA-Z0-9_/]+",
    re.IGNORECASE,
)

_YOUTUBE_LINK_PATTERN = re.compile(
    r"(?:https?://)?(?:www\.)?(?:youtube\.com|youtu\.be)/[^\s<>\"']+",
    re.IGNORECASE,
)

_INSTAGRAM_LINK_PATTERN = re.compile(
    r"(?:https?://)?(?:www\.)?instagram\.com/[a-zA-Z0-9_./-]+",
    re.IGNORECASE,
)

_TIKTOK_LINK_PATTERN = re.compile(
    r"(?:https?://)?(?:www\.)?tiktok\.com/@[a-zA-Z0-9_./-]+",
    re.IGNORECASE,
)

_REDDIT_LINK_PATTERN = re.compile(
    r"(?:https?://)?(?:www\.)?reddit\.com/[ru]/[a-zA-Z0-9_/-]+",
    re.IGNORECASE,
)


def extract_discord_invites(text: str) -> list[str]:
    """Extract Discord invite codes from text."""
    if not text:
        return []
    matches = _DISCORD_INVITE_PATTERN.findall(text)
    return list(dict.fromkeys(matches))


def extract_telegram_links(text: str) -> list[str]:
    """Extract Telegram usernames/channels from text."""
    if not text:
        return []
    matches = _TELEGRAM_LINK_PATTERN.findall(text)
    return list(dict.fromkeys(matches))


def extract_twitter_links(text: str) -> list[str]:
    """Extract Twitter/X URLs from text."""
    if not text:
        return []
    matches = _TWITTER_LINK_PATTERN.findall(text)
    result = []
    for match in matches:
        url = match if match.startswith("http") else f"https://{match}"
        if url not in result:
            result.append(url)
    return result


def extract_youtube_links(text: str) -> list[str]:
    """Extract YouTube URLs from text."""
    if not text:
        return []
    matches = _YOUTUBE_LINK_PATTERN.findall(text)
    result = []
    for match in matches:
        url = match if match.startswith("http") else f"https://{match}"
        url = url.rstrip(".,;:!?")
        if url not in result:
            result.append(url)
    return result


def extract_instagram_links(text: str) -> list[str]:
    """Extract Instagram URLs from text."""
    if not text:
        return []
    matches = _INSTAGRAM_LINK_PATTERN.findall(text)
    result = []
    for match in matches:
        url = match if match.startswith("http") else f"https://{match}"
        if url not in result:
            result.append(url)
    return result


def extract_tiktok_links(text: str) -> list[str]:
    """Extract TikTok URLs from text."""
    if not text:
        return []
    matches = _TIKTOK_LINK_PATTERN.findall(text)
    result = []
    for match in matches:
        url = match if match.startswith("http") else f"https://{match}"
        if url not in result:
            result.append(url)
    return result


def extract_reddit_links(text: str) -> list[str]:
    """Extract Reddit URLs from text."""
    if not text:
        return []
    matches = _REDDIT_LINK_PATTERN.findall(text)
    result = []
    for match in matches:
        url = match if match.startswith("http") else f"https://{match}"
        if url not in result:
            result.append(url)
    return result


def extract_social_links(text: str) -> dict[str, list[str]]:
    """Extract all social media links from text."""
    return {
        "discord": extract_discord_invites(text),
        "telegram": extract_telegram_links(text),
        "twitter": extract_twitter_links(text),
        "youtube": extract_youtube_links(text),
        "instagram": extract_instagram_links(text),
        "tiktok": extract_tiktok_links(text),
        "reddit": extract_reddit_links(text),
    }


# =============================================================================
# Crypto/Web3 Extraction
# =============================================================================

_ETH_ADDRESS_PATTERN = re.compile(r"\b0x[a-fA-F0-9]{40}\b")

_BTC_LEGACY_PATTERN = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
_BTC_BECH32_PATTERN = re.compile(r"\bbc1[a-z0-9]{39,59}\b")

_SOL_ADDRESS_PATTERN = re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b")

_ENS_NAME_PATTERN = re.compile(r"\b[a-zA-Z0-9][-a-zA-Z0-9]*\.eth\b")


def extract_eth_addresses(text: str) -> list[str]:
    """Extract Ethereum addresses from text."""
    if not text:
        return []
    matches = _ETH_ADDRESS_PATTERN.findall(text)
    return list(dict.fromkeys(matches))


def extract_btc_addresses(text: str) -> list[str]:
    """Extract Bitcoin addresses from text."""
    if not text:
        return []
    legacy = _BTC_LEGACY_PATTERN.findall(text)
    bech32 = _BTC_BECH32_PATTERN.findall(text)
    all_matches = legacy + bech32
    return list(dict.fromkeys(all_matches))


def extract_sol_addresses(text: str) -> list[str]:
    """Extract Solana addresses from text."""
    if not text:
        return []
    matches = _SOL_ADDRESS_PATTERN.findall(text)
    # Filter out potential false positives (too short, contains invalid chars)
    valid = []
    for match in matches:
        if len(match) >= 32 and len(match) <= 44:
            # Exclude matches that look like other patterns (ETH, BTC, etc.)
            if not match.startswith("0x") and not match.startswith("bc1"):
                valid.append(match)
    return list(dict.fromkeys(valid))


def extract_ens_names(text: str) -> list[str]:
    """Extract ENS names from text."""
    if not text:
        return []
    matches = _ENS_NAME_PATTERN.findall(text)
    return list(dict.fromkeys(matches))


def extract_crypto_addresses(text: str) -> dict[str, list[str]]:
    """Extract all crypto addresses from text."""
    return {
        "eth": extract_eth_addresses(text),
        "btc": extract_btc_addresses(text),
        "sol": extract_sol_addresses(text),
        "ens": extract_ens_names(text),
    }


# =============================================================================
# Security Token Extraction
# =============================================================================

_API_KEY_PATTERNS = [
    ("openai", re.compile(r"\bsk-[a-zA-Z0-9]{20,}\b")),
    ("anthropic", re.compile(r"\bsk-ant-[a-zA-Z0-9-]{20,}\b")),
    ("aws", re.compile(r"\bAKIA[A-Z0-9]{16}\b")),
    ("stripe_live", re.compile(r"\bsk_live_[a-zA-Z0-9]{24,}\b")),
    ("stripe_test", re.compile(r"\bsk_test_[a-zA-Z0-9]{24,}\b")),
    ("github", re.compile(r"\bgh[pousr]_[a-zA-Z0-9]{36,}\b")),
    ("google", re.compile(r"\bAIza[a-zA-Z0-9_-]{35}\b")),
    ("discord_bot", re.compile(r"\b[MN][a-zA-Z0-9]{23,}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27,}\b")),
    ("telegram_bot", re.compile(r"\b[0-9]{8,10}:[a-zA-Z0-9_-]{35}\b")),
]

_JWT_PATTERN = re.compile(
    r"\beyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]+\b"
)

_BEARER_PATTERN = re.compile(r"\b[Bb]earer\s+([a-zA-Z0-9_.-]+)")


def extract_api_keys(text: str) -> list[dict[str, str]]:
    """Extract API keys from text with type detection."""
    if not text:
        return []
    results = []
    seen = set()
    for key_type, pattern in _API_KEY_PATTERNS:
        for match in pattern.findall(text):
            if match not in seen:
                seen.add(match)
                results.append({"type": key_type, "key": match})
    return results


def extract_jwts(text: str) -> list[str]:
    """Extract JWT tokens from text."""
    if not text:
        return []
    matches = _JWT_PATTERN.findall(text)
    return list(dict.fromkeys(matches))


def decode_jwt(token: str) -> dict[str, Any] | None:
    """Decode JWT without verification. Returns header and payload."""
    if not token:
        return None
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        # Decode header
        header_b64 = parts[0]
        header_padded = header_b64 + "=" * (-len(header_b64) % 4)
        header_json = base64.urlsafe_b64decode(header_padded).decode("utf-8")
        header = json.loads(header_json)
        # Decode payload
        payload_b64 = parts[1]
        payload_padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        payload_json = base64.urlsafe_b64decode(payload_padded).decode("utf-8")
        payload = json.loads(payload_json)
        return {"header": header, "payload": payload}
    except Exception:
        return None


def extract_bearer_tokens(text: str) -> list[str]:
    """Extract Bearer tokens from text."""
    if not text:
        return []
    matches = _BEARER_PATTERN.findall(text)
    return list(dict.fromkeys(matches))


# =============================================================================
# Contact Info Extraction
# =============================================================================

_PHONE_PATTERN = re.compile(
    r"(?:\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}"
    r"|\+\d{1,3}[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,4}"
)

_DATE_PATTERNS = [
    # ISO format: 2024-01-15
    re.compile(r"\b\d{4}-\d{2}-\d{2}\b"),
    # US format: 01/15/2024 or 01-15-2024
    re.compile(r"\b\d{2}[/-]\d{2}[/-]\d{4}\b"),
    # Long format: January 15, 2024
    re.compile(
        r"\b(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4}\b"
    ),
    # Short format: 15 Jan 2024
    re.compile(
        r"\b\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{4}\b"
    ),
]


def extract_phone_numbers(text: str) -> list[str]:
    """Extract phone numbers from text."""
    if not text:
        return []
    matches = _PHONE_PATTERN.findall(text)
    return list(dict.fromkeys(matches))


def extract_dates(text: str) -> list[str]:
    """Extract dates from text in various formats."""
    if not text:
        return []
    results = []
    seen = set()
    for pattern in _DATE_PATTERNS:
        for match in pattern.findall(text):
            if match not in seen:
                seen.add(match)
                results.append(match)
    return results


# =============================================================================
# Captcha Extraction
# =============================================================================

# reCAPTCHA patterns (site keys are typically 40 chars but can vary)
_RECAPTCHA_SITEKEY_PATTERNS = [
    # data-sitekey attribute (keys start with 6L and are 40+ chars)
    re.compile(r'data-sitekey=["\']([a-zA-Z0-9_-]{20,50})["\']'),
    # Script src with render parameter
    re.compile(r'google\.com/recaptcha/(?:api|enterprise)\.js\?[^"\']*render=([a-zA-Z0-9_-]{20,50})'),
    # grecaptcha.execute('sitekey', ...)
    re.compile(r'grecaptcha\.execute\s*\(\s*["\']([a-zA-Z0-9_-]{10,50})["\']'),
    # grecaptcha.render with sitekey
    re.compile(r'grecaptcha\.render\s*\([^)]*sitekey\s*:\s*["\']([a-zA-Z0-9_-]{20,50})["\']'),
]

# Turnstile (Cloudflare) patterns
_TURNSTILE_SITEKEY_PATTERNS = [
    # data-sitekey on cf-turnstile
    re.compile(r'class=["\'][^"\']*cf-turnstile[^"\']*["\'][^>]*data-sitekey=["\']([a-zA-Z0-9_-]+)["\']'),
    re.compile(r'data-sitekey=["\']([0x][a-zA-Z0-9_-]+)["\']'),
    # turnstile.render with sitekey
    re.compile(r'turnstile\.render\s*\([^)]*sitekey\s*:\s*["\']([0x][a-zA-Z0-9_-]+)["\']'),
    # Script with render parameter
    re.compile(r'challenges\.cloudflare\.com/turnstile/[^"\']*\?[^"\']*render=([0x][a-zA-Z0-9_-]+)'),
]

# hCaptcha patterns
_HCAPTCHA_SITEKEY_PATTERNS = [
    # data-sitekey on h-captcha
    re.compile(r'class=["\'][^"\']*h-captcha[^"\']*["\'][^>]*data-sitekey=["\']([a-f0-9-]{36})["\']'),
    re.compile(r'data-sitekey=["\']([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})["\']'),
    # Script with sitekey parameter
    re.compile(r'hcaptcha\.com/[^"\']*\?[^"\']*sitekey=([a-f0-9-]{36})'),
    # hcaptcha.render with sitekey
    re.compile(r'hcaptcha\.render\s*\([^)]*sitekey\s*:\s*["\']([a-f0-9-]{36})["\']'),
]

def extract_recaptcha_sitekey(html: str) -> list[str]:
    """Extract reCAPTCHA site keys from HTML."""
    if not html:
        return []
    results = []
    seen = set()
    for pattern in _RECAPTCHA_SITEKEY_PATTERNS:
        for match in pattern.findall(html):
            if match not in seen:
                seen.add(match)
                results.append(match)
    return results


def extract_turnstile_sitekey(html: str) -> list[str]:
    """Extract Cloudflare Turnstile site keys from HTML."""
    if not html:
        return []
    results = []
    seen = set()
    for pattern in _TURNSTILE_SITEKEY_PATTERNS:
        for match in pattern.findall(html):
            if match not in seen:
                seen.add(match)
                results.append(match)
    return results


def extract_hcaptcha_sitekey(html: str) -> list[str]:
    """Extract hCaptcha site keys from HTML."""
    if not html:
        return []
    results = []
    seen = set()
    for pattern in _HCAPTCHA_SITEKEY_PATTERNS:
        for match in pattern.findall(html):
            if match not in seen:
                seen.add(match)
                results.append(match)
    return results


def extract_captcha_params(html: str) -> dict[str, list[str]]:
    """Extract all captcha parameters from HTML."""
    return {
        "recaptcha": extract_recaptcha_sitekey(html),
        "turnstile": extract_turnstile_sitekey(html),
        "hcaptcha": extract_hcaptcha_sitekey(html),
    }


# Captcha detection patterns
_RECAPTCHA_DETECT_PATTERNS = [
    re.compile(r'class=["\'][^"\']*g-recaptcha', re.IGNORECASE),
    re.compile(r'google\.com/recaptcha/', re.IGNORECASE),
    re.compile(r'grecaptcha\.', re.IGNORECASE),
    re.compile(r'www\.gstatic\.com/recaptcha/', re.IGNORECASE),
]

_TURNSTILE_DETECT_PATTERNS = [
    re.compile(r'class=["\'][^"\']*cf-turnstile', re.IGNORECASE),
    re.compile(r'challenges\.cloudflare\.com/turnstile/', re.IGNORECASE),
    re.compile(r'turnstile\.render', re.IGNORECASE),
]

_HCAPTCHA_DETECT_PATTERNS = [
    re.compile(r'class=["\'][^"\']*h-captcha', re.IGNORECASE),
    re.compile(r'hcaptcha\.com/', re.IGNORECASE),
    re.compile(r'hcaptcha\.render', re.IGNORECASE),
]


def contains_recaptcha(html: str) -> bool:
    """Check if HTML contains reCAPTCHA."""
    if not html:
        return False
    return any(p.search(html) for p in _RECAPTCHA_DETECT_PATTERNS)


def contains_turnstile(html: str) -> bool:
    """Check if HTML contains Cloudflare Turnstile."""
    if not html:
        return False
    return any(p.search(html) for p in _TURNSTILE_DETECT_PATTERNS)


def contains_hcaptcha(html: str) -> bool:
    """Check if HTML contains hCaptcha."""
    if not html:
        return False
    return any(p.search(html) for p in _HCAPTCHA_DETECT_PATTERNS)


# =============================================================================
# Network/Identifier Extraction
# =============================================================================

_IPV4_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)

_IPV6_PATTERN = re.compile(
    r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
    r'|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b'
    r'|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b'
    r'|\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b'
)

_DOMAIN_PATTERN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
)

_UUID_PATTERN = re.compile(
    r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'
)

_MAC_ADDRESS_PATTERN = re.compile(
    r'\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b'
)


def extract_ipv4(text: str) -> list[str]:
    """Extract IPv4 addresses from text."""
    if not text:
        return []
    matches = _IPV4_PATTERN.findall(text)
    return list(dict.fromkeys(matches))


def extract_ipv6(text: str) -> list[str]:
    """Extract IPv6 addresses from text."""
    if not text:
        return []
    matches = _IPV6_PATTERN.findall(text)
    return list(dict.fromkeys(matches))


def extract_ips(text: str) -> list[str]:
    """Extract all IP addresses (IPv4 and IPv6) from text."""
    if not text:
        return []
    ipv4 = extract_ipv4(text)
    ipv6 = extract_ipv6(text)
    return ipv4 + ipv6


def extract_domains(text: str) -> list[str]:
    """Extract domain names from text."""
    if not text:
        return []
    matches = _DOMAIN_PATTERN.findall(text)
    # Filter out common false positives
    filtered = []
    for domain in matches:
        lower = domain.lower()
        # Skip file extensions that look like domains
        if not any(lower.endswith(ext) for ext in ['.js', '.css', '.png', '.jpg', '.gif', '.svg']):
            if domain not in filtered:
                filtered.append(domain)
    return filtered


def extract_uuids(text: str) -> list[str]:
    """Extract UUIDs from text."""
    if not text:
        return []
    matches = _UUID_PATTERN.findall(text)
    return list(dict.fromkeys(matches))


def extract_mac_addresses(text: str) -> list[str]:
    """Extract MAC addresses from text."""
    if not text:
        return []
    matches = _MAC_ADDRESS_PATTERN.findall(text)
    return list(dict.fromkeys(matches))


# =============================================================================
# API/Endpoint Extraction
# =============================================================================

_API_ENDPOINT_PATTERN = re.compile(
    r'["\'](?:https?://[^"\']*)?(/(?:api|v\d+|graphql|rest)/[^"\']*)["\']',
    re.IGNORECASE,
)

_GRAPHQL_ENDPOINT_PATTERN = re.compile(
    r'["\']([^"\']*(?:graphql|gql)[^"\']*)["\']',
    re.IGNORECASE,
)

_WEBSOCKET_URL_PATTERN = re.compile(
    r'["\']?(wss?://[^\s"\'<>]+)["\']?',
    re.IGNORECASE,
)

_FULL_API_URL_PATTERN = re.compile(
    r'https?://[^\s"\'<>]*(?:/api/|/v\d+/|/rest/)[^\s"\'<>]*',
    re.IGNORECASE,
)


def extract_api_endpoints(text: str) -> list[str]:
    """Extract API endpoint paths from text."""
    if not text:
        return []
    # Get relative paths
    paths = _API_ENDPOINT_PATTERN.findall(text)
    # Get full URLs
    urls = _FULL_API_URL_PATTERN.findall(text)
    all_endpoints = paths + urls
    return list(dict.fromkeys(all_endpoints))


def extract_graphql_endpoints(text: str) -> list[str]:
    """Extract GraphQL endpoint URLs from text."""
    if not text:
        return []
    matches = _GRAPHQL_ENDPOINT_PATTERN.findall(text)
    # Filter to likely endpoints
    endpoints = []
    for match in matches:
        if '/' in match or match.endswith('graphql') or match.endswith('gql'):
            if match not in endpoints:
                endpoints.append(match)
    return endpoints


def extract_websocket_urls(text: str) -> list[str]:
    """Extract WebSocket URLs from text."""
    if not text:
        return []
    matches = _WEBSOCKET_URL_PATTERN.findall(text)
    return list(dict.fromkeys(matches))


# =============================================================================
# Media URL Extraction
# =============================================================================

_VIDEO_URL_PATTERN = re.compile(
    r'["\']?(https?://[^\s"\'<>]+\.(?:mp4|webm|m3u8|mpd|avi|mov|mkv|flv|wmv)(?:\?[^\s"\'<>]*)?)["\']?',
    re.IGNORECASE,
)

_VIDEO_SRC_PATTERN = re.compile(
    r'<(?:video|source)[^>]*src=["\']([^"\']+)["\']',
    re.IGNORECASE,
)

_AUDIO_URL_PATTERN = re.compile(
    r'["\']?(https?://[^\s"\'<>]+\.(?:mp3|wav|ogg|m4a|flac|aac|wma)(?:\?[^\s"\'<>]*)?)["\']?',
    re.IGNORECASE,
)

_AUDIO_SRC_PATTERN = re.compile(
    r'<(?:audio|source)[^>]*src=["\']([^"\']+)["\']',
    re.IGNORECASE,
)

_STREAM_URL_PATTERN = re.compile(
    r'["\']?(https?://[^\s"\'<>]*(?:\.m3u8|\.mpd|/manifest|/playlist)[^\s"\'<>]*)["\']?',
    re.IGNORECASE,
)


def extract_video_urls(text: str) -> list[str]:
    """Extract video URLs from text/HTML."""
    if not text:
        return []
    # Direct URLs
    urls = _VIDEO_URL_PATTERN.findall(text)
    # From video/source tags
    src_urls = _VIDEO_SRC_PATTERN.findall(text)
    # Streaming URLs
    stream_urls = _STREAM_URL_PATTERN.findall(text)
    all_urls = urls + src_urls + stream_urls
    return list(dict.fromkeys(all_urls))


def extract_audio_urls(text: str) -> list[str]:
    """Extract audio URLs from text/HTML."""
    if not text:
        return []
    # Direct URLs
    urls = _AUDIO_URL_PATTERN.findall(text)
    # From audio/source tags
    src_urls = _AUDIO_SRC_PATTERN.findall(text)
    all_urls = urls + src_urls
    return list(dict.fromkeys(all_urls))


def extract_stream_urls(text: str) -> list[str]:
    """Extract streaming URLs (m3u8, mpd) from text."""
    if not text:
        return []
    matches = _STREAM_URL_PATTERN.findall(text)
    return list(dict.fromkeys(matches))


# =============================================================================
# E-commerce/Price Extraction
# =============================================================================

_PRICE_PATTERN = re.compile(
    r'(?:[$\u20ac\u00a3\u00a5]|USD|EUR|GBP|JPY|CAD|AUD)\s*[\d,]+(?:\.\d{2})?'
    r'|[\d,]+(?:\.\d{2})?\s*(?:[$\u20ac\u00a3\u00a5]|USD|EUR|GBP|JPY|CAD|AUD)'
    r'|\d{1,3}(?:,\d{3})*(?:\.\d{2})?(?=\s*(?:dollars?|euros?|pounds?))',
    re.IGNORECASE,
)

_SKU_PATTERN = re.compile(
    r'(?:sku|item|product|part)[\s:_-]*#?\s*([A-Z0-9][-A-Z0-9]{3,20})',
    re.IGNORECASE,
)

_CURRENCY_MAP = {
    '$': 'USD', '\u20ac': 'EUR', '\u00a3': 'GBP', '\u00a5': 'JPY',
    'USD': 'USD', 'EUR': 'EUR', 'GBP': 'GBP', 'JPY': 'JPY',
    'CAD': 'CAD', 'AUD': 'AUD',
}


def extract_prices(text: str) -> list[dict[str, Any]]:
    """Extract prices with currency from text."""
    if not text:
        return []
    matches = _PRICE_PATTERN.findall(text)
    results = []
    seen = set()
    for match in matches:
        if match in seen:
            continue
        seen.add(match)
        # Detect currency
        currency = 'USD'
        for symbol, curr in _CURRENCY_MAP.items():
            if symbol in match:
                currency = curr
                break
        # Extract numeric value
        nums = re.findall(r'[\d,]+(?:\.\d{2})?', match)
        if nums:
            value = nums[0].replace(',', '')
            results.append({
                'raw': match.strip(),
                'value': float(value) if '.' in value else int(value),
                'currency': currency,
            })
    return results


def extract_skus(text: str) -> list[str]:
    """Extract product SKUs from text."""
    if not text:
        return []
    matches = _SKU_PATTERN.findall(text)
    return list(dict.fromkeys(matches))


# =============================================================================
# Structured Data Extraction
# =============================================================================

_CANONICAL_URL_PATTERN = re.compile(
    r'<link[^>]*rel=["\']canonical["\'][^>]*href=["\']([^"\']+)["\']',
    re.IGNORECASE,
)

_OG_TAG_PATTERN = re.compile(
    r'<meta[^>]*property=["\']og:([^"\']+)["\'][^>]*content=["\']([^"\']*)["\']'
    r'|<meta[^>]*content=["\']([^"\']*)["\'][^>]*property=["\']og:([^"\']+)["\']',
    re.IGNORECASE,
)

_TWITTER_CARD_PATTERN = re.compile(
    r'<meta[^>]*name=["\']twitter:([^"\']+)["\'][^>]*content=["\']([^"\']*)["\']'
    r'|<meta[^>]*content=["\']([^"\']*)["\'][^>]*name=["\']twitter:([^"\']+)["\']',
    re.IGNORECASE,
)

_SCHEMA_ORG_PATTERN = re.compile(
    r'<script[^>]*type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',
    re.IGNORECASE | re.DOTALL,
)


def extract_canonical_url(html: str) -> str:
    """Extract canonical URL from HTML."""
    if not html:
        return ""
    match = _CANONICAL_URL_PATTERN.search(html)
    return match.group(1) if match else ""


def extract_og_tags(html: str) -> dict[str, str]:
    """Extract Open Graph meta tags from HTML."""
    if not html:
        return {}
    tags = {}
    for match in _OG_TAG_PATTERN.finditer(html):
        if match.group(1) and match.group(2):
            tags[match.group(1)] = match.group(2)
        elif match.group(3) and match.group(4):
            tags[match.group(4)] = match.group(3)
    return tags


def extract_twitter_cards(html: str) -> dict[str, str]:
    """Extract Twitter Card meta tags from HTML."""
    if not html:
        return {}
    cards = {}
    for match in _TWITTER_CARD_PATTERN.finditer(html):
        if match.group(1) and match.group(2):
            cards[match.group(1)] = match.group(2)
        elif match.group(3) and match.group(4):
            cards[match.group(4)] = match.group(3)
    return cards


def extract_schema_org(html: str) -> list[Any]:
    """Extract Schema.org JSON-LD data from HTML."""
    if not html:
        return []
    results = []
    for match in _SCHEMA_ORG_PATTERN.finditer(html):
        try:
            data = json.loads(match.group(1))
            results.append(data)
        except (json.JSONDecodeError, ValueError):
            continue
    return results


def extract_structured_data(html: str) -> dict[str, Any]:
    """Extract all structured data (OG, Twitter, Schema.org, canonical)."""
    return {
        'canonical': extract_canonical_url(html),
        'og': extract_og_tags(html),
        'twitter': extract_twitter_cards(html),
        'schema_org': extract_schema_org(html),
    }
