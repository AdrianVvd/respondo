#!/usr/bin/env python3
"""
Respondo - Complete Test Suite
Tests all 100+ extraction functions
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from text import (
    # Core text extraction
    between, betweens, between_last, between_n,
    normalize_space, strip_tags, unescape_html,
    regex_first, regex_all, parse_csrf_token,
    # Encoding
    url_encode, url_decode, b64_encode, b64_decode,
    # Validation
    is_valid_email, is_valid_url, is_valid_json,
    # Basic extraction
    extract_emails, extract_urls, extract_numbers, clean_text,
    # Social media
    extract_discord_invites, extract_telegram_links, extract_twitter_links,
    extract_youtube_links, extract_instagram_links, extract_tiktok_links,
    extract_reddit_links, extract_social_links,
    # Crypto
    extract_eth_addresses, extract_btc_addresses, extract_sol_addresses,
    extract_ens_names, extract_crypto_addresses,
    # Security
    extract_api_keys, extract_jwts, decode_jwt, extract_bearer_tokens,
    # Contact
    extract_phone_numbers, extract_dates,
    # Captcha extraction
    extract_recaptcha_sitekey, extract_turnstile_sitekey, extract_hcaptcha_sitekey,
    extract_captcha_params,
    # Captcha detection
    contains_recaptcha, contains_turnstile, contains_hcaptcha,
    # Network
    extract_ipv4, extract_ipv6, extract_ips, extract_domains,
    extract_uuids, extract_mac_addresses,
    # API
    extract_api_endpoints, extract_graphql_endpoints, extract_websocket_urls,
    # Media
    extract_video_urls, extract_audio_urls, extract_stream_urls,
    # E-commerce
    extract_prices, extract_skus,
    # Structured data
    extract_canonical_url, extract_og_tags, extract_twitter_cards,
    extract_schema_org, extract_structured_data,
)

passed = 0
failed = 0


def test(name: str, result, expected):
    global passed, failed
    if result == expected:
        print(f"  [PASS] {name}")
        passed += 1
    else:
        print(f"  [FAIL] {name}")
        print(f"         Expected: {expected}")
        print(f"         Got:      {result}")
        failed += 1


def test_true(name: str, result):
    test(name, result, True)


def test_false(name: str, result):
    test(name, result, False)


def test_not_empty(name: str, result):
    global passed, failed
    if result and len(result) > 0:
        print(f"  [PASS] {name}")
        passed += 1
    else:
        print(f"  [FAIL] {name} - Expected non-empty result, got: {result}")
        failed += 1


def section(title: str):
    print(f"\n{'='*60}")
    print(f" {title}")
    print('='*60)


def main():
    global passed, failed

    print("\n" + "="*60)
    print("       RESPONDO - Complete Test Suite")
    print("="*60)

    # =========================================================================
    section("CORE TEXT EXTRACTION")
    # =========================================================================

    test("between - basic", between("<title>Hello</title>", "<title>", "</title>"), "Hello")
    test("between - not found", between("no match", "<", ">"), "")
    test("between - empty delimiters", between("test", "", ">"), "")

    test("betweens - multiple", betweens("[a][b][c]", "[", "]"), ["a", "b", "c"])
    test("betweens - none", betweens("no brackets", "[", "]"), [])

    test("between_last", between_last("[first][second]", "[", "]"), "second")
    test("between_n - 2nd match", between_n("<i>1</i><i>2</i><i>3</i>", "<i>", "</i>", 2), "2")
    test("between_n - out of range", between_n("<i>1</i>", "<i>", "</i>", 5), "")

    test("normalize_space", normalize_space("  hello   world  "), "hello world")
    test("strip_tags", strip_tags("<p>Hello <b>World</b></p>"), "Hello World")
    test("unescape_html", unescape_html("&lt;div&gt;"), "<div>")

    test("regex_first - with group", regex_first("Price: $42.99", r"\$([\d.]+)"), "42.99")
    test("regex_first - no match", regex_first("no price", r"\$([\d.]+)"), "")

    test("regex_all", regex_all("v1 v2 v3", r"v(\d)"), ["1", "2", "3"])

    test("parse_csrf_token", parse_csrf_token('<input name="csrf_token" value="abc123">'), "abc123")

    # =========================================================================
    section("ENCODING")
    # =========================================================================

    test("url_encode", url_encode({"q": "hello world", "page": 1}), "q=hello+world&page=1")
    test("url_decode", url_decode("a=1&b=2&b=3"), {"a": ["1"], "b": ["2", "3"]})

    test("b64_encode", b64_encode("hello"), "aGVsbG8=")
    test("b64_decode", b64_decode("aGVsbG8="), b"hello")
    test("b64_decode - empty", b64_decode(""), b"")

    # =========================================================================
    section("VALIDATION")
    # =========================================================================

    test_true("is_valid_email - valid", is_valid_email("test@example.com"))
    test_false("is_valid_email - invalid", is_valid_email("not-an-email"))

    test_true("is_valid_url - valid", is_valid_url("https://example.com"))
    test_false("is_valid_url - invalid", is_valid_url("not-a-url"))

    test_true("is_valid_json - valid", is_valid_json('{"key": "value"}'))
    test_false("is_valid_json - invalid", is_valid_json("not json"))

    # =========================================================================
    section("BASIC EXTRACTION")
    # =========================================================================

    test_not_empty("extract_emails", extract_emails("Contact: test@example.com"))
    test("extract_emails - none", extract_emails("no emails here"), [])

    test_not_empty("extract_urls", extract_urls("Visit https://example.com"))
    test("extract_urls - none", extract_urls("no urls"), [])

    test_not_empty("extract_numbers", extract_numbers("Price: $19.99"))

    test("clean_text", clean_text("  hello   world  "), "hello world")

    # =========================================================================
    section("SOCIAL MEDIA EXTRACTION")
    # =========================================================================

    test("extract_discord_invites", extract_discord_invites("Join discord.gg/abc123"), ["abc123"])
    test("extract_discord_invites - discord.com", extract_discord_invites("discord.com/invite/xyz"), ["xyz"])
    test("extract_discord_invites - none", extract_discord_invites("no discord"), [])

    test("extract_telegram_links", extract_telegram_links("Follow t.me/channel"), ["channel"])
    test("extract_telegram_links - none", extract_telegram_links("no telegram"), [])

    test_not_empty("extract_twitter_links", extract_twitter_links("Check twitter.com/user"))
    test_not_empty("extract_twitter_links - x.com", extract_twitter_links("Check x.com/user"))

    test_not_empty("extract_youtube_links", extract_youtube_links("https://youtu.be/abc123"))
    test_not_empty("extract_youtube_links - full", extract_youtube_links("https://youtube.com/watch?v=abc"))

    test_not_empty("extract_instagram_links", extract_instagram_links("instagram.com/user"))
    test_not_empty("extract_tiktok_links", extract_tiktok_links("tiktok.com/@user"))
    test_not_empty("extract_reddit_links", extract_reddit_links("reddit.com/r/python"))

    social = extract_social_links("discord.gg/test t.me/channel")
    test("extract_social_links - discord", social["discord"], ["test"])
    test("extract_social_links - telegram", social["telegram"], ["channel"])

    # =========================================================================
    section("CRYPTO/WEB3 EXTRACTION")
    # =========================================================================

    test("extract_eth_addresses",
         extract_eth_addresses("0x742d35Cc6634C0532925a3b844Bc9e7595f1dE2B"),
         ["0x742d35Cc6634C0532925a3b844Bc9e7595f1dE2B"])
    test("extract_eth_addresses - none", extract_eth_addresses("no eth"), [])

    test("extract_btc_addresses - legacy",
         extract_btc_addresses("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"),
         ["1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"])
    test_not_empty("extract_btc_addresses - bech32",
         extract_btc_addresses("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"))

    test("extract_ens_names", extract_ens_names("vitalik.eth"), ["vitalik.eth"])
    test("extract_ens_names - multiple", extract_ens_names("alice.eth bob.eth"), ["alice.eth", "bob.eth"])

    crypto = extract_crypto_addresses("0x742d35Cc6634C0532925a3b844Bc9e7595f1dE2B vitalik.eth")
    test_not_empty("extract_crypto_addresses - eth", crypto["eth"])
    test_not_empty("extract_crypto_addresses - ens", crypto["ens"])

    # =========================================================================
    section("SECURITY TOKEN EXTRACTION")
    # =========================================================================

    keys = extract_api_keys("sk-1234567890abcdefghijklmnopqrstuvwxyz1234")
    test_not_empty("extract_api_keys - openai", keys)
    test("extract_api_keys - type", keys[0]["type"] if keys else None, "openai")

    keys_aws = extract_api_keys("AKIAIOSFODNN7EXAMPLE")
    test_not_empty("extract_api_keys - aws", keys_aws)

    keys_github = extract_api_keys("ghp_1234567890abcdefghijklmnopqrstuvwxyz")
    test_not_empty("extract_api_keys - github", keys_github)

    test("extract_api_keys - none", extract_api_keys("no keys"), [])

    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    test("extract_jwts", extract_jwts(f"token={jwt}"), [jwt])
    test("extract_jwts - none", extract_jwts("no jwt"), [])

    decoded = decode_jwt(jwt)
    test("decode_jwt - header alg", decoded["header"]["alg"] if decoded else None, "HS256")
    test("decode_jwt - payload sub", decoded["payload"]["sub"] if decoded else None, "1234567890")
    test("decode_jwt - invalid", decode_jwt("invalid"), None)

    test("extract_bearer_tokens", extract_bearer_tokens("Bearer abc123"), ["abc123"])
    test("extract_bearer_tokens - none", extract_bearer_tokens("no bearer"), [])

    # =========================================================================
    section("CONTACT INFO EXTRACTION")
    # =========================================================================

    test_not_empty("extract_phone_numbers - US", extract_phone_numbers("+1 (555) 123-4567"))
    test_not_empty("extract_phone_numbers - simple", extract_phone_numbers("555-123-4567"))
    test("extract_phone_numbers - none", extract_phone_numbers("no phone"), [])

    test_not_empty("extract_dates - ISO", extract_dates("2024-01-15"))
    test_not_empty("extract_dates - US", extract_dates("01/15/2024"))
    test_not_empty("extract_dates - long", extract_dates("January 15, 2024"))
    test("extract_dates - none", extract_dates("no dates"), [])

    # =========================================================================
    section("CAPTCHA EXTRACTION")
    # =========================================================================

    recaptcha_html = '<div class="g-recaptcha" data-sitekey="6LcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxAA"></div>'
    test("extract_recaptcha_sitekey", extract_recaptcha_sitekey(recaptcha_html), ["6LcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxAA"])

    turnstile_html = '<div class="cf-turnstile" data-sitekey="0x4AAAAAAADnPIDROrmt1Wwj"></div>'
    test("extract_turnstile_sitekey", extract_turnstile_sitekey(turnstile_html), ["0x4AAAAAAADnPIDROrmt1Wwj"])

    hcaptcha_html = '<div class="h-captcha" data-sitekey="10000000-ffff-ffff-ffff-000000000001"></div>'
    test("extract_hcaptcha_sitekey", extract_hcaptcha_sitekey(hcaptcha_html), ["10000000-ffff-ffff-ffff-000000000001"])

    params = extract_captcha_params(recaptcha_html)
    test_not_empty("extract_captcha_params - recaptcha", params["recaptcha"])

    # =========================================================================
    section("CAPTCHA DETECTION")
    # =========================================================================

    test_true("contains_recaptcha - class", contains_recaptcha('<div class="g-recaptcha"></div>'))
    test_true("contains_recaptcha - script", contains_recaptcha('google.com/recaptcha/api.js'))
    test_false("contains_recaptcha - none", contains_recaptcha('<div>no captcha</div>'))

    test_true("contains_turnstile", contains_turnstile('<div class="cf-turnstile"></div>'))
    test_false("contains_turnstile - none", contains_turnstile('<div>nothing</div>'))

    test_true("contains_hcaptcha", contains_hcaptcha('<div class="h-captcha"></div>'))

    # =========================================================================
    section("NETWORK/IDENTIFIER EXTRACTION")
    # =========================================================================

    test("extract_ipv4", extract_ipv4("192.168.1.1 and 10.0.0.1"), ["192.168.1.1", "10.0.0.1"])
    test("extract_ipv4 - none", extract_ipv4("no ips"), [])

    test_not_empty("extract_ipv6", extract_ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334"))

    test("extract_ips - combined", len(extract_ips("192.168.1.1")) > 0, True)

    test("extract_domains", extract_domains("example.com and test.org"), ["example.com", "test.org"])
    test("extract_domains - none", extract_domains("no domains"), [])

    test("extract_uuids", extract_uuids("550e8400-e29b-41d4-a716-446655440000"),
         ["550e8400-e29b-41d4-a716-446655440000"])

    test("extract_mac_addresses", extract_mac_addresses("00:1A:2B:3C:4D:5E"), ["00:1A:2B:3C:4D:5E"])

    # =========================================================================
    section("API/ENDPOINT EXTRACTION")
    # =========================================================================

    test("extract_api_endpoints", extract_api_endpoints('"/api/v1/users"'), ["/api/v1/users"])
    test_not_empty("extract_api_endpoints - full url",
         extract_api_endpoints("https://api.example.com/api/v2/data"))

    test("extract_graphql_endpoints", extract_graphql_endpoints('"/graphql"'), ["/graphql"])

    test("extract_websocket_urls", extract_websocket_urls("wss://example.com/socket"),
         ["wss://example.com/socket"])
    test("extract_websocket_urls - ws", extract_websocket_urls("ws://localhost:8080"),
         ["ws://localhost:8080"])

    # =========================================================================
    section("MEDIA URL EXTRACTION")
    # =========================================================================

    test("extract_video_urls - mp4", extract_video_urls("https://cdn.com/video.mp4"),
         ["https://cdn.com/video.mp4"])
    test_not_empty("extract_video_urls - m3u8", extract_video_urls("https://cdn.com/playlist.m3u8"))

    test("extract_audio_urls - mp3", extract_audio_urls("https://cdn.com/song.mp3"),
         ["https://cdn.com/song.mp3"])

    test_not_empty("extract_stream_urls", extract_stream_urls("https://cdn.com/playlist.m3u8"))

    # =========================================================================
    section("E-COMMERCE EXTRACTION")
    # =========================================================================

    prices = extract_prices("$19.99")
    test_not_empty("extract_prices - USD", prices)
    test("extract_prices - value", prices[0]["value"] if prices else None, 19.99)
    test("extract_prices - currency", prices[0]["currency"] if prices else None, "USD")

    prices_eur = extract_prices("EUR 29.99")
    test("extract_prices - EUR currency", prices_eur[0]["currency"] if prices_eur else None, "EUR")

    test("extract_skus", extract_skus("SKU: ABC-12345"), ["ABC-12345"])
    test("extract_skus - none", extract_skus("no sku"), [])

    # =========================================================================
    section("STRUCTURED DATA EXTRACTION")
    # =========================================================================

    html = '''
    <link rel="canonical" href="https://example.com/page">
    <meta property="og:title" content="My Page">
    <meta property="og:image" content="https://example.com/image.jpg">
    <meta name="twitter:card" content="summary">
    <script type="application/ld+json">{"@type": "Product", "name": "Widget"}</script>
    '''

    test("extract_canonical_url", extract_canonical_url(html), "https://example.com/page")
    test("extract_canonical_url - none", extract_canonical_url("<div>no canonical</div>"), "")

    og = extract_og_tags(html)
    test("extract_og_tags - title", og.get("title"), "My Page")
    test("extract_og_tags - image", og.get("image"), "https://example.com/image.jpg")

    twitter = extract_twitter_cards(html)
    test("extract_twitter_cards - card", twitter.get("card"), "summary")

    schema = extract_schema_org(html)
    test_not_empty("extract_schema_org", schema)
    test("extract_schema_org - type", schema[0].get("@type") if schema else None, "Product")

    structured = extract_structured_data(html)
    test("extract_structured_data - has canonical", structured["canonical"], "https://example.com/page")
    test_not_empty("extract_structured_data - has og", structured["og"])

    # =========================================================================
    # RESULTS
    # =========================================================================
    print("\n" + "="*60)
    print(f"       TEST RESULTS: {passed} passed, {failed} failed")
    print("="*60)

    if failed == 0:
        print("\n  ALL TESTS PASSED!\n")
        return 0
    else:
        print(f"\n  {failed} TESTS FAILED\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
