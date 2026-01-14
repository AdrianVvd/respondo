<div align="center">

<img src="https://github.com/user-attachments/assets/0370a117-cff9-43bd-8cd1-76d4d9cc64bd" alt="Respondo - Web scraping, text extraction & AI parsing for Python" width="100%">

<br>

[![PyPI version](https://img.shields.io/pypi/v/respondo?color=00d4aa&label=PyPI&style=flat-square)](https://pypi.org/project/respondo/)
[![Python](https://img.shields.io/badge/Python-3.9+-3776ab?logo=python&logoColor=white&style=flat-square)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-a855f7?style=flat-square)](https://opensource.org/licenses/MIT)
[![Downloads](https://img.shields.io/pypi/dm/respondo?color=fbbf24&style=flat-square)](https://pypi.org/project/respondo/)
[![Discord](https://img.shields.io/badge/Discord-Join-5865F2?logo=discord&logoColor=white&style=flat-square)](https://discord.gg/n9cdFy7ngN)

**Zero dependencies** · **Type hints** · **10 AI providers** · **Structured outputs**

[Installation](#installation) · [Quick Start](#quick-start) · [Documentation](#documentation) · [AI Parsing](#-ai-parsing)

</div>

---

## Installation

```bash
pip install respondo
```

---

## Quick Start

```python
from respondo import between, extract_emails, parse_ai, Response

# Extract text between delimiters
between("<title>Hello World</title>", "<title>", "</title>")
# => "Hello World"

# Find all emails in text
extract_emails("Contact us at hello@example.com or support@example.com")
# => ["hello@example.com", "support@example.com"]

# AI-powered extraction (10 providers supported)
parse_ai("Extract the price", "The item costs $29.99", provider="openai")
# => "$29.99"
```

---

## Documentation

### Text Extraction

```python
from respondo import between, betweens, regex_first, regex_all

# Extract between delimiters
between("Hello [World]!", "[", "]")           # => "World"
betweens("[a][b][c]", "[", "]")               # => ["a", "b", "c"]

# Regex extraction (returns capture group if present)
regex_first("Price: $42.99", r"\$([\d.]+)")   # => "42.99"
regex_all("<id>1</id><id>2</id>", r"<id>(\d+)</id>")  # => ["1", "2"]
```

### Extract Emails, URLs & Numbers

```python
from respondo import extract_emails, extract_urls, extract_numbers

text = "Contact john@example.com or visit https://example.com. Price: $99.99"

extract_emails(text)   # => ["john@example.com"]
extract_urls(text)     # => ["https://example.com"]
extract_numbers(text)  # => ["$99.99"]
```

### Validation

```python
from respondo import is_valid_email, is_valid_url, is_valid_json

is_valid_email("test@example.com")  # => True
is_valid_url("https://example.com") # => True
is_valid_json('{"key": "value"}')   # => True
```

### Text Utilities

```python
from respondo import normalize_space, clean_text, strip_tags, unescape_html

normalize_space("  hello   world  ")          # => "hello world"
clean_text("Cafe - Recipe's")                 # => "Cafe - Recipe's" (normalized)
strip_tags("<p>Hello <b>World</b></p>")       # => "Hello World"
unescape_html("&lt;div&gt;")                  # => "<div>"
```

---

### HTML Parsing

```python
from respondo import get_text, extract_links, extract_meta, extract_images, html_to_markdown

html = """
<html>
  <head>
    <title>My Page</title>
    <meta name="description" content="A sample page">
    <meta property="og:image" content="https://example.com/image.jpg">
  </head>
  <body>
    <h1>Welcome</h1>
    <p>Visit our <a href="/about">about page</a></p>
    <img src="/logo.png" alt="Logo">
  </body>
</html>
"""

# Extract visible text
get_text(html)  # => "My Page Welcome Visit our about page"

# Extract all links
extract_links(html, base="https://example.com")
# => ["https://example.com/about", "https://example.com/logo.png"]

# Extract meta tags (title, description, og:*, twitter:*)
extract_meta(html)
# => {"title": "My Page", "description": "A sample page", "og:image": "https://example.com/image.jpg"}

# Extract images with attributes
extract_images(html, base="https://example.com")
# => [{"src": "https://example.com/logo.png", "alt": "Logo", ...}]

# Convert HTML to Markdown
html_to_markdown("<h1>Title</h1><p>Hello <strong>world</strong></p>")
# => "# Title\n\nHello **world**"
```

### Forms & Tables

```python
from respondo import extract_forms, extract_tables

# Extract forms with all fields
html = '<form action="/login"><input name="user"><input name="pass" type="password"></form>'
extract_forms(html, base="https://example.com")
# => [{"action": "https://example.com/login", "method": "get", "fields": {"user": "", "pass": ""}}]

# Extract tables as structured data
html = "<table><tr><th>Name</th><th>Age</th></tr><tr><td>Alice</td><td>30</td></tr></table>"
extract_tables(html)
# => [{"headers": ["Name", "Age"], "rows": [{"Name": "Alice", "Age": "30"}]}]
```

---

### JSON Utilities

```python
from respondo import find_first_json, find_all_json, json_get

# Find JSON embedded in text
find_first_json('callback({"user": "alice", "id": 42})')
# => {"user": "alice", "id": 42}

# Safe nested access (never throws)
data = {"user": {"profile": {"name": "Alice"}}}
json_get(data, "user", "profile", "name")     # => "Alice"
json_get(data, "user", "missing", "key")      # => None

# Works with arrays too
json_get([{"id": 1}, {"id": 2}], 0, "id")     # => 1
```

---

### Response Handling

```python
from respondo import Response

resp = Response(
    status=200,
    headers={"Content-Type": "application/json"},
    body=b'{"success": true}'
)

# Status checks
resp.is_success()        # => True (200-299)
resp.is_redirect()       # => False (300-399)
resp.is_client_error()   # => False (400-499)

# Body access
resp.text                # => '{"success": true}'
resp.json()              # => {"success": True}

# Headers (case-insensitive)
resp.header("content-type")       # => "application/json"
resp.content_type()               # => ("application/json", "")

# Cookie parsing
resp.cookies()
# => [{"name": "session", "value": "abc", "attrs": {"path": "/", "httponly": ""}}]
```

---

### Encoding Utilities

```python
from respondo import url_encode, url_decode, b64_encode, b64_decode

# URL encoding
url_encode({"q": "hello world", "page": 1})   # => "q=hello+world&page=1"
url_decode("a=1&b=2&b=3")                     # => {"a": ["1"], "b": ["2", "3"]}

# Base64
b64_encode("hello")                           # => "aGVsbG8="
b64_decode("aGVsbG8=")                        # => b"hello"
```

---

### Social Media Extraction

```python
from respondo import (
    extract_discord_invites, extract_telegram_links, extract_twitter_links,
    extract_youtube_links, extract_instagram_links, extract_tiktok_links,
    extract_reddit_links, extract_social_links
)

# Extract individual platforms
extract_discord_invites("Join discord.gg/abc123")     # => ["abc123"]
extract_telegram_links("Follow t.me/channel")         # => ["channel"]
extract_twitter_links("Check twitter.com/elonmusk")   # => ["https://twitter.com/elonmusk"]
extract_youtube_links("Watch https://youtu.be/xyz")   # => ["https://youtu.be/xyz"]

# Extract all social links at once
extract_social_links("discord.gg/test t.me/channel twitter.com/user")
# => {"discord": ["test"], "telegram": ["channel"], "twitter": ["https://twitter.com/user"], ...}
```

### Crypto/Web3 Extraction

```python
from respondo import (
    extract_eth_addresses, extract_btc_addresses, extract_sol_addresses,
    extract_ens_names, extract_crypto_addresses
)

# Ethereum
extract_eth_addresses("Send to 0x742d35Cc6634C0532925a3b844Bc9e7595f1dE2B")
# => ["0x742d35Cc6634C0532925a3b844Bc9e7595f1dE2B"]

# Bitcoin (legacy and SegWit)
extract_btc_addresses("BTC: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")
# => ["1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"]

# ENS names
extract_ens_names("Contact vitalik.eth")  # => ["vitalik.eth"]

# All crypto at once
extract_crypto_addresses(text)  # => {"eth": [...], "btc": [...], "sol": [...], "ens": [...]}
```

### Security Token Extraction

```python
from respondo import extract_api_keys, extract_jwts, decode_jwt, extract_bearer_tokens

# Detect exposed API keys (OpenAI, AWS, Stripe, GitHub, Google, etc.)
extract_api_keys("OPENAI_API_KEY=sk-abc123...")
# => [{"type": "openai", "key": "sk-abc123..."}]

# Extract and decode JWTs
tokens = extract_jwts("token=eyJhbGciOiJIUzI1NiIs...")
decode_jwt(tokens[0])  # => {"header": {"alg": "HS256"}, "payload": {"sub": "123"}}

# Bearer tokens
extract_bearer_tokens("Authorization: Bearer abc123")  # => ["abc123"]
```

### Contact Info Extraction

```python
from respondo import extract_phone_numbers, extract_dates

extract_phone_numbers("Call +1 (555) 123-4567 or +44 20 7946 0958")
# => ["+1 (555) 123-4567", "+44 20 7946 0958"]

extract_dates("Date: 2024-01-15 and January 15, 2024")
# => ["2024-01-15", "January 15, 2024"]
```

---

### Captcha Extraction & Detection

```python
from respondo import (
    # Extraction
    extract_recaptcha_sitekey, extract_turnstile_sitekey, extract_hcaptcha_sitekey,
    extract_captcha_params,
    # Detection
    contains_recaptcha, contains_turnstile, contains_hcaptcha
)

html = '<div class="g-recaptcha" data-sitekey="6Lc..."></div>'

# Extract site keys for captcha solving services
extract_recaptcha_sitekey(html)   # => ["6Lc..."]
extract_turnstile_sitekey(html)   # => ["0x4AAA..."]
extract_hcaptcha_sitekey(html)    # => ["uuid-format-key"]

# Check what captcha is present
contains_recaptcha(html)          # => True
contains_turnstile(html)          # => False
contains_hcaptcha(html)           # => False

# Get all captcha params at once
extract_captcha_params(html)
# => {"recaptcha": [...], "turnstile": [...], "hcaptcha": [...]}
```

### Network/Identifier Extraction

```python
from respondo import (
    extract_ipv4, extract_ipv6, extract_ips, extract_domains,
    extract_uuids, extract_mac_addresses
)

extract_ipv4("Server: 192.168.1.1")                  # => ["192.168.1.1"]
extract_domains("Visit example.com or api.test.org") # => ["example.com", "api.test.org"]
extract_uuids("ID: 550e8400-e29b-41d4-a716-...")     # => ["550e8400-..."]
extract_mac_addresses("MAC: 00:1A:2B:3C:4D:5E")      # => ["00:1A:2B:3C:4D:5E"]
```

### API/Endpoint Extraction

```python
from respondo import extract_api_endpoints, extract_graphql_endpoints, extract_websocket_urls

extract_api_endpoints(js_code)      # => ["/api/v1/users", "https://api.example.com/v2/data"]
extract_graphql_endpoints(html)     # => ["/graphql", "/api/gql"]
extract_websocket_urls(html)        # => ["wss://example.com/socket"]
```

### Media URL Extraction

```python
from respondo import extract_video_urls, extract_audio_urls, extract_stream_urls

extract_video_urls(html)   # => ["https://cdn.com/video.mp4", "https://stream.com/playlist.m3u8"]
extract_audio_urls(html)   # => ["https://cdn.com/song.mp3"]
extract_stream_urls(html)  # => ["https://cdn.com/playlist.m3u8", "https://cdn.com/manifest.mpd"]
```

### E-commerce Extraction

```python
from respondo import extract_prices, extract_skus

extract_prices("Price: $19.99 and EUR 29.99")
# => [{"raw": "$19.99", "value": 19.99, "currency": "USD"},
#     {"raw": "EUR 29.99", "value": 29.99, "currency": "EUR"}]

extract_skus("SKU: ABC-12345")  # => ["ABC-12345"]
```

### Structured Data Extraction

```python
from respondo import (
    extract_canonical_url, extract_og_tags, extract_twitter_cards,
    extract_schema_org, extract_structured_data
)

# Individual extractions
extract_canonical_url(html)   # => "https://example.com/page"
extract_og_tags(html)         # => {"title": "My Page", "image": "https://..."}
extract_twitter_cards(html)   # => {"card": "summary", "site": "@example"}
extract_schema_org(html)      # => [{"@type": "Product", "name": "Widget"}]

# All structured data at once
extract_structured_data(html)
# => {"canonical": "...", "og": {...}, "twitter": {...}, "schema_org": [...]}
```

---

## AI Parsing

Parse text using LLM APIs. **10 providers supported** with structured output.

```python
from respondo import parse_ai, parse_ai_json, list_providers

# See all providers
list_providers()
# => {"openai": "gpt-4o-mini", "anthropic": "claude-3-5-haiku-latest", ...}

# Basic extraction
parse_ai("Extract all prices", "$29.99 and $49.99", provider="openai")
# => "$29.99, $49.99"

# Custom model
parse_ai("Summarize", text, provider="anthropic", model="claude-3-5-sonnet-latest")

# JSON response
parse_ai_json("Extract name and age", "John is 30", provider="openai")
# => {"name": "John", "age": 30}

# Structured output with schema (enforced by provider)
schema = {
    "type": "object",
    "properties": {
        "name": {"type": "string"},
        "age": {"type": "integer"}
    },
    "required": ["name", "age"],
    "additionalProperties": False
}
parse_ai_json("Extract person", text, provider="openai", schema=schema)
```

### Supported Providers

| Provider | Environment Variable | Default Model |
|:---------|:--------------------|:--------------|
| `openai` | `OPENAI_API_KEY` | `gpt-4o-mini` |
| `anthropic` | `ANTHROPIC_API_KEY` | `claude-3-5-haiku-latest` |
| `gemini` | `GEMINI_API_KEY` | `gemini-2.0-flash` |
| `grok` | `GROK_API_KEY` | `grok-2-latest` |
| `mistral` | `MISTRAL_API_KEY` | `mistral-small-latest` |
| `groq` | `GROQ_API_KEY` | `llama-3.3-70b-versatile` |
| `cohere` | `COHERE_API_KEY` | `command-r` |
| `together` | `TOGETHER_API_KEY` | `Llama-3.3-70B-Instruct-Turbo` |
| `deepseek` | `DEEPSEEK_API_KEY` | `deepseek-chat` |
| `perplexity` | `PERPLEXITY_API_KEY` | `sonar` |

---

## Features Overview

<div align="center">
<img src="https://github.com/user-attachments/assets/f5635db0-4ede-4736-9014-2a4be814981b" alt="Features" width="100%">
</div>

---

## Error Handling

All functions return empty values instead of raising exceptions - ideal for scraping workflows where missing data is expected.

| Return Type | On Failure |
|:------------|:-----------|
| `str` | `""` |
| `list` | `[]` |
| `dict` | `{}` |
| `Any` (JSON) | `None` |

```python
between("no match", "<", ">")      # => ""
find_first_json("not json")        # => None
is_valid_email("invalid")          # => False
extract_emails("no emails here")   # => []
parse_ai("prompt", "text")         # => "" (if no API key)
```

---

<div align="center">

**MIT License** - Made for web scrapers

</div>
