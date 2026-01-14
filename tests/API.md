# Respondo Specification

Respondo provides small, scraping-friendly helpers for text extraction, JSON handling, and response parsing for Python.

## Layout
- spec/README.md — this document
- spec/testdata/*.json — canonical examples
- src/ — Python modules

## Conventions
- Functions return empty string/array/null on missing matches rather than raising.
- Regex helpers return the first capture group when present; otherwise the whole match.
- Whitespace normalization collapses any whitespace into single spaces and trims.

## text (alias strutil)
- between(s,left,right): first match; empty string if boundaries are missing or empty.
- betweens(...): all non-overlapping matches scanning left-to-right.
- between_last(...): uses the last occurrence of `left` and the first `right` that follows it.
- between_n(..., n): 1-based nth match from betweens; empty when out of range.
- normalize_space(s): trim and collapse whitespace to single spaces.
- strip_tags(html): remove `<...>` tags, normalize whitespace; entities are not decoded.
- unescape_html(s): decode HTML entities (named and numeric).
- regex_first(s, pattern): first capture group if present else first full match; empty on no match or invalid pattern.
- regex_all(s, pattern): same capture preference for all matches.
- parse_csrf_token(html): pulls the first CSRF token found in common hidden input/meta/script patterns.
- url_encode(params): percent-encode query parameters (doseq).
- url_decode(query): parse query string into key -> list of values (keeps blanks).
- b64_encode(data, urlsafe=False): base64 encode bytes/str (urlsafe optional).
- b64_decode(data, urlsafe=False): base64 decode, forgiving padding/errors; returns bytes or empty on invalid.

### Social Media Extraction
- extract_discord_invites(text): extracts Discord invite codes/URLs (discord.gg/xxx, discord.com/invite/xxx); returns list of invite codes.
- extract_telegram_links(text): extracts Telegram links (t.me/xxx, telegram.me/xxx); returns list of usernames/channels.
- extract_twitter_links(text): extracts Twitter/X links (twitter.com/xxx, x.com/xxx); returns list of full URLs.
- extract_youtube_links(text): extracts YouTube links (youtube.com/watch, youtu.be/xxx); returns list of full URLs.
- extract_instagram_links(text): extracts Instagram links (instagram.com/xxx); returns list of full URLs.
- extract_tiktok_links(text): extracts TikTok links (tiktok.com/@xxx); returns list of full URLs.
- extract_reddit_links(text): extracts Reddit links (reddit.com/r/xxx, /u/xxx); returns list of full URLs.
- extract_social_links(text): extracts all social media links; returns dict with platform keys mapping to URL lists.

### Contact Info Extraction
- extract_phone_numbers(text): extracts phone numbers in international formats; returns list of phone strings.
- extract_dates(text): extracts dates in common formats (ISO, US, EU); returns list of date strings as found.

### Crypto/Web3 Extraction
- extract_eth_addresses(text): extracts Ethereum addresses (0x + 40 hex chars); returns list of addresses.
- extract_btc_addresses(text): extracts Bitcoin addresses (1/3/bc1 formats); returns list of addresses.
- extract_sol_addresses(text): extracts Solana addresses (base58, 32-44 chars); returns list of addresses.
- extract_ens_names(text): extracts ENS names (xxx.eth); returns list of names.
- extract_crypto_addresses(text): extracts all crypto addresses; returns dict with chain keys mapping to address lists.

### Security Token Extraction
- extract_api_keys(text): detects exposed API keys from common providers; returns list of dicts with "type" and "key" fields.
- extract_jwts(text): extracts JWT tokens (eyJ...); returns list of token strings.
- decode_jwt(token): decodes JWT without verification; returns dict with "header" and "payload" or None on invalid.
- extract_bearer_tokens(text): extracts Bearer tokens from Authorization headers; returns list of token strings.

### Captcha Extraction
Site key extraction for captcha solving services:
- extract_recaptcha_sitekey(html): extracts reCAPTCHA v2/v3 site keys from data-sitekey, script src, or grecaptcha calls; returns list of site keys.
- extract_turnstile_sitekey(html): extracts Cloudflare Turnstile site keys from data-sitekey or turnstile.render calls; returns list of site keys.
- extract_hcaptcha_sitekey(html): extracts hCaptcha site keys from data-sitekey or script src; returns list of site keys.
- extract_captcha_params(html): extracts all captcha parameters; returns dict with captcha type keys mapping to extracted data.

Captcha detection (boolean checks):
- contains_recaptcha(html): returns True if page contains reCAPTCHA.
- contains_turnstile(html): returns True if page contains Cloudflare Turnstile.
- contains_hcaptcha(html): returns True if page contains hCaptcha.

### Network/Identifier Extraction
- extract_ipv4(text): extracts IPv4 addresses; returns list of IP strings.
- extract_ipv6(text): extracts IPv6 addresses; returns list of IP strings.
- extract_ips(text): extracts all IP addresses (v4 and v6); returns list of IP strings.
- extract_domains(text): extracts domain names; returns list of domain strings.
- extract_uuids(text): extracts UUIDs; returns list of UUID strings.
- extract_mac_addresses(text): extracts MAC addresses; returns list of MAC strings.

### API/Endpoint Extraction
- extract_api_endpoints(text): extracts REST API endpoint paths/URLs; returns list of endpoints.
- extract_graphql_endpoints(text): extracts GraphQL endpoint URLs; returns list of endpoints.
- extract_websocket_urls(text): extracts WebSocket URLs (ws://, wss://); returns list of URLs.

### Media URL Extraction
- extract_video_urls(text): extracts video URLs (mp4, webm, m3u8, etc.); returns list of URLs.
- extract_audio_urls(text): extracts audio URLs (mp3, wav, etc.); returns list of URLs.
- extract_stream_urls(text): extracts streaming URLs (m3u8, mpd); returns list of URLs.

### E-commerce Extraction
- extract_prices(text): extracts prices with currency; returns list of dicts with "raw", "value", "currency".
- extract_skus(text): extracts product SKU codes; returns list of SKU strings.

### Structured Data Extraction
- extract_canonical_url(html): extracts canonical URL from link tag; returns URL string or empty.
- extract_og_tags(html): extracts Open Graph meta tags; returns dict of property->content.
- extract_twitter_cards(html): extracts Twitter Card meta tags; returns dict of name->content.
- extract_schema_org(html): extracts JSON-LD Schema.org data; returns list of parsed objects.
- extract_structured_data(html): extracts all structured data; returns dict with canonical, og, twitter, schema_org.

## jsonutil
- find_first_json(text): scans for the first valid JSON object/array using balanced braces that respect quoted strings; returns parsed value or null/None.
- find_all_json(text): all parsed values in order.
- json_get(obj, path...): safe traversal by string keys or integer indices; returns null/None when any segment is missing.

## response
- Response helpers:
  - status helpers: `is_informational`, `is_success`, `is_redirect`, `is_client_error`, `is_server_error`
  - header helpers: `header(name)` (first) and `headers(name)` (all, case-insensitive)
  - cookies: `cookies()` parses `Set-Cookie` headers into name/value/attrs
  - content type: `content_type()` returns media type and charset (if present)
  - body helpers: raw bytes, `text()`, `json()`
  - hash helpers: `hash(algo="sha256")` for body bytes; `hash_text(algo="sha256")` after decoding.
  - charset_sniff: detect encoding from headers or `<meta charset>`; returns text + charset used.
  - json_in_html: find JSON blocks in `<script type="application/json">` or inline assignments; returns parsed objects list.
  - links: extract href/src values, optionally resolve against base; filters for same-host or allowed extensions.
  - strip_scripts_styles: remove `<script>`/`<style>` blocks and collapse whitespace/entities.

## htmlutil
- strip_scripts_styles(html): remove `<script>`/`<style>` and collapse whitespace/entities.
- get_text(html, separator=" ", strip=True): extract visible text.
- extract_links(html, base=None, same_host=False, extensions=None): href/src harvesting with optional resolution/filters.
- extract_forms(html, base=None): extract forms with action/method/fields (inputs, textarea, select).
- extract_tables(html): convert HTML tables to headers+row dicts.
- json_in_html(html): find and parse JSON blocks in `<script type="application/json">` or inline assignments.

## Test Data
- between.json — substring helpers
- normalize_space.json — whitespace, tag stripping, regex helpers
- json_extract.json — JSON detection and safe access
- response_helpers.json — status/header/cookie/content-type helpers
- encoding.json — CSRF/URL/base64 helpers
- response_extras.json — hashing, cleanup, links, JSON-in-HTML, charset
- htmlutil.json — text extraction, forms, tables
- social.json — social media link extraction
- crypto.json — crypto address extraction
- security.json — API keys and JWT extraction
- contact.json — phone numbers and dates extraction
- captcha.json — captcha site key extraction and detection
- network.json — IP, domain, UUID, MAC extraction
- api.json — API endpoint extraction
- media.json — video/audio URL extraction
- ecommerce.json — price and SKU extraction
- structured.json — Open Graph, Twitter Cards, Schema.org extraction
