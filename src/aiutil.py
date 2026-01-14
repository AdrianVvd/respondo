"""
AI-powered text parsing using LLM APIs.
Supports OpenAI, Anthropic, Grok, Gemini, Mistral, Groq, Cohere, Together, DeepSeek, Perplexity.
No external dependencies - uses urllib only.
"""

import json
import os
import urllib.request
import urllib.error
from typing import Any, Optional


def _get_api_key(provider: str) -> str:
    """Get API key from environment variable."""
    env_vars = {
        "openai": "OPENAI_API_KEY",
        "anthropic": "ANTHROPIC_API_KEY",
        "grok": "GROK_API_KEY",
        "gemini": "GEMINI_API_KEY",
        "mistral": "MISTRAL_API_KEY",
        "groq": "GROQ_API_KEY",
        "cohere": "COHERE_API_KEY",
        "together": "TOGETHER_API_KEY",
        "deepseek": "DEEPSEEK_API_KEY",
        "perplexity": "PERPLEXITY_API_KEY",
    }
    var_name = env_vars.get(provider, "")
    return os.environ.get(var_name, "")


def _http_post(url: str, headers: dict, payload: dict, response_path: list) -> str:
    """Make HTTP POST request and extract response."""
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=120) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            for key in response_path:
                if isinstance(key, int):
                    if isinstance(result, list) and 0 <= key < len(result):
                        result = result[key]
                    else:
                        return ""
                else:
                    if isinstance(result, dict) and key in result:
                        result = result[key]
                    else:
                        return ""
            return str(result) if result else ""
    except Exception:
        return ""


def _call_openai(prompt: str, text: str, api_key: str, model: str, schema: Optional[dict]) -> str:
    """Call OpenAI API."""
    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload: dict = {
        "model": model,
        "messages": [{"role": "user", "content": f"{prompt}\n\n{text}"}],
    }
    if schema:
        payload["response_format"] = {
            "type": "json_schema",
            "json_schema": {"name": "response", "strict": True, "schema": schema}
        }
    return _http_post(url, headers, payload, ["choices", 0, "message", "content"])


def _call_anthropic(prompt: str, text: str, api_key: str, model: str, schema: Optional[dict]) -> str:
    """Call Anthropic API."""
    url = "https://api.anthropic.com/v1/messages"
    headers = {
        "x-api-key": api_key,
        "Content-Type": "application/json",
        "anthropic-version": "2023-06-01",
    }
    content = f"{prompt}\n\n{text}"
    if schema:
        content += f"\n\nRespond with JSON matching this schema:\n{json.dumps(schema)}"
    payload = {
        "model": model,
        "max_tokens": 4096,
        "messages": [{"role": "user", "content": content}],
    }
    return _http_post(url, headers, payload, ["content", 0, "text"])


def _call_grok(prompt: str, text: str, api_key: str, model: str, schema: Optional[dict]) -> str:
    """Call Grok (xAI) API - OpenAI compatible."""
    url = "https://api.x.ai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload: dict = {
        "model": model,
        "messages": [{"role": "user", "content": f"{prompt}\n\n{text}"}],
    }
    if schema:
        payload["response_format"] = {"type": "json_object"}
    return _http_post(url, headers, payload, ["choices", 0, "message", "content"])


def _call_gemini(prompt: str, text: str, api_key: str, model: str, schema: Optional[dict]) -> str:
    """Call Google Gemini API."""
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
    headers = {"Content-Type": "application/json"}
    content = f"{prompt}\n\n{text}"
    if schema:
        content += f"\n\nRespond with JSON matching this schema:\n{json.dumps(schema)}"
    payload: dict = {
        "contents": [{"parts": [{"text": content}]}],
    }
    if schema:
        payload["generationConfig"] = {"responseMimeType": "application/json"}
    return _http_post(url, headers, payload, ["candidates", 0, "content", "parts", 0, "text"])


def _call_mistral(prompt: str, text: str, api_key: str, model: str, schema: Optional[dict]) -> str:
    """Call Mistral API."""
    url = "https://api.mistral.ai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload: dict = {
        "model": model,
        "messages": [{"role": "user", "content": f"{prompt}\n\n{text}"}],
    }
    if schema:
        payload["response_format"] = {"type": "json_object"}
    return _http_post(url, headers, payload, ["choices", 0, "message", "content"])


def _call_groq(prompt: str, text: str, api_key: str, model: str, schema: Optional[dict]) -> str:
    """Call Groq API - OpenAI compatible."""
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload: dict = {
        "model": model,
        "messages": [{"role": "user", "content": f"{prompt}\n\n{text}"}],
    }
    if schema:
        payload["response_format"] = {"type": "json_object"}
    return _http_post(url, headers, payload, ["choices", 0, "message", "content"])


def _call_cohere(prompt: str, text: str, api_key: str, model: str, schema: Optional[dict]) -> str:
    """Call Cohere API."""
    url = "https://api.cohere.com/v2/chat"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    content = f"{prompt}\n\n{text}"
    if schema:
        content += f"\n\nRespond with JSON matching this schema:\n{json.dumps(schema)}"
    payload: dict = {
        "model": model,
        "messages": [{"role": "user", "content": content}],
    }
    if schema:
        payload["response_format"] = {"type": "json_object"}
    return _http_post(url, headers, payload, ["message", "content", 0, "text"])


def _call_together(prompt: str, text: str, api_key: str, model: str, schema: Optional[dict]) -> str:
    """Call Together AI API - OpenAI compatible."""
    url = "https://api.together.xyz/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload: dict = {
        "model": model,
        "messages": [{"role": "user", "content": f"{prompt}\n\n{text}"}],
    }
    if schema:
        payload["response_format"] = {"type": "json_object", "schema": schema}
    return _http_post(url, headers, payload, ["choices", 0, "message", "content"])


def _call_deepseek(prompt: str, text: str, api_key: str, model: str, schema: Optional[dict]) -> str:
    """Call DeepSeek API - OpenAI compatible."""
    url = "https://api.deepseek.com/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload: dict = {
        "model": model,
        "messages": [{"role": "user", "content": f"{prompt}\n\n{text}"}],
    }
    if schema:
        payload["response_format"] = {"type": "json_object"}
    return _http_post(url, headers, payload, ["choices", 0, "message", "content"])


def _call_perplexity(prompt: str, text: str, api_key: str, model: str, schema: Optional[dict]) -> str:
    """Call Perplexity API - OpenAI compatible."""
    url = "https://api.perplexity.ai/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    content = f"{prompt}\n\n{text}"
    if schema:
        content += f"\n\nRespond with JSON matching this schema:\n{json.dumps(schema)}"
    payload: dict = {
        "model": model,
        "messages": [{"role": "user", "content": content}],
    }
    return _http_post(url, headers, payload, ["choices", 0, "message", "content"])


# Provider configurations
PROVIDERS = {
    "openai": {"handler": _call_openai, "default_model": "gpt-4o-mini"},
    "anthropic": {"handler": _call_anthropic, "default_model": "claude-3-5-haiku-latest"},
    "grok": {"handler": _call_grok, "default_model": "grok-2-latest"},
    "gemini": {"handler": _call_gemini, "default_model": "gemini-2.0-flash"},
    "mistral": {"handler": _call_mistral, "default_model": "mistral-small-latest"},
    "groq": {"handler": _call_groq, "default_model": "llama-3.3-70b-versatile"},
    "cohere": {"handler": _call_cohere, "default_model": "command-r"},
    "together": {"handler": _call_together, "default_model": "meta-llama/Llama-3.3-70B-Instruct-Turbo"},
    "deepseek": {"handler": _call_deepseek, "default_model": "deepseek-chat"},
    "perplexity": {"handler": _call_perplexity, "default_model": "sonar"},
}


def parse_ai(
    prompt: str,
    text: str,
    provider: str = "openai",
    model: Optional[str] = None,
    api_key: Optional[str] = None,
) -> str:
    """
    Parse text using an LLM API.

    Args:
        prompt: Instructions for the LLM (e.g., "Extract all email addresses")
        text: The text to parse
        provider: "openai", "anthropic", "grok", "gemini", "mistral", "groq",
                  "cohere", "together", "deepseek", "perplexity"
        model: Model name (defaults to provider's recommended model)
        api_key: API key (defaults to environment variable)

    Returns:
        LLM response as string, or empty string on error.

    Environment variables:
        OPENAI_API_KEY, ANTHROPIC_API_KEY, GROK_API_KEY, GEMINI_API_KEY,
        MISTRAL_API_KEY, GROQ_API_KEY, COHERE_API_KEY, TOGETHER_API_KEY,
        DEEPSEEK_API_KEY, PERPLEXITY_API_KEY

    Example:
        >>> parse_ai("Extract the price", "The item costs $29.99", provider="openai")
        "$29.99"
        >>> parse_ai("Summarize", text, provider="groq", model="llama-3.1-8b-instant")
        "..."
    """
    if not prompt or not text:
        return ""

    key = api_key or _get_api_key(provider)
    if not key:
        return ""

    config = PROVIDERS.get(provider)
    if not config:
        return ""

    model = model or config["default_model"]
    handler = config["handler"]

    return handler(prompt, text, key, model, None)


def parse_ai_json(
    prompt: str,
    text: str,
    provider: str = "openai",
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    schema: Optional[dict] = None,
) -> Any:
    """
    Parse text using an LLM and return JSON.

    Args:
        prompt: Instructions for the LLM
        text: The text to parse
        provider: API provider name
        model: Model name (optional)
        api_key: API key (optional)
        schema: JSON Schema for structured output (optional).
                When provided, uses provider's native structured output feature.

    Returns:
        Parsed JSON (dict/list), or None on error.

    Example:
        >>> parse_ai_json("Extract name and age as JSON", "John is 30 years old")
        {"name": "John", "age": 30}

        >>> schema = {
        ...     "type": "object",
        ...     "properties": {
        ...         "name": {"type": "string"},
        ...         "age": {"type": "integer"}
        ...     },
        ...     "required": ["name", "age"],
        ...     "additionalProperties": False
        ... }
        >>> parse_ai_json("Extract info", "John is 30", schema=schema)
        {"name": "John", "age": 30}
    """
    if not prompt or not text:
        return None

    key = api_key or _get_api_key(provider)
    if not key:
        return None

    config = PROVIDERS.get(provider)
    if not config:
        return None

    model = model or config["default_model"]
    handler = config["handler"]

    # Add JSON instruction to prompt if no schema
    if not schema:
        prompt = f"{prompt}\n\nRespond with valid JSON only, no other text."

    result = handler(prompt, text, key, model, schema)
    if not result:
        return None

    # Clean markdown code blocks
    result = result.strip()
    if result.startswith("```"):
        lines = result.split("\n")
        if len(lines) >= 2:
            result = "\n".join(lines[1:-1] if lines[-1].strip().startswith("```") else lines[1:])
            result = result.strip()

    try:
        return json.loads(result)
    except Exception:
        return None


def list_providers() -> dict:
    """
    List available providers and their default models.

    Returns:
        Dict mapping provider name to default model.

    Example:
        >>> list_providers()
        {"openai": "gpt-4o-mini", "anthropic": "claude-3-5-haiku-latest", ...}
    """
    return {name: config["default_model"] for name, config in PROVIDERS.items()}
