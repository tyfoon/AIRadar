"""
Diagnostic script for Gemini API connectivity from inside the container.

Run from the host:
    git pull
    sudo docker cp tools/gemini_debug.py airadar-app:/tmp/gemini_debug.py
    sudo docker compose exec airadar-app python3 /tmp/gemini_debug.py

Runs three independent tests to isolate where a Gemini call hangs:
  1. Raw urllib POST   — Python stdlib only, tests basic HTTPS
  2. httpx POST        — the HTTP library the SDK uses under the hood
  3. google-genai SDK  — the full stack our app uses
"""
import os
import json
import time


def main():
    key = os.getenv("GEMINI_API_KEY", "")
    print(f"Key length: {len(key)}")
    if not key:
        print("GEMINI_API_KEY not set — aborting")
        return

    url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        "gemini-flash-lite-latest:generateContent?key=" + key
    )
    payload = {"contents": [{"parts": [{"text": "Say hello"}]}]}

    # ------------------------------------------------------------------
    # Test 1: Raw urllib POST (stdlib only)
    # ------------------------------------------------------------------
    print("\n=== Test 1: urllib POST (stdlib) ===")
    t0 = time.time()
    try:
        import urllib.request
        import urllib.error
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as r:
            data = r.read()
        print(f"  OK in {time.time() - t0:.1f}s, {len(data)} bytes")
        print(f"  First 200 chars: {data[:200].decode(errors='replace')}")
    except urllib.error.HTTPError as e:
        print(f"  HTTP {e.code} after {time.time() - t0:.1f}s: {e.read()[:200].decode(errors='replace')}")
    except Exception as exc:
        print(f"  FAILED after {time.time() - t0:.1f}s: {type(exc).__name__}: {exc}")

    # ------------------------------------------------------------------
    # Test 2: httpx POST (library used by google-genai)
    # ------------------------------------------------------------------
    print("\n=== Test 2: httpx POST ===")
    t0 = time.time()
    try:
        import httpx
        print(f"  httpx version: {httpx.__version__}")
        with httpx.Client(timeout=30) as c:
            r = c.post(url, json=payload)
        print(f"  OK in {time.time() - t0:.1f}s, status {r.status_code}")
        print(f"  First 200 chars: {r.text[:200]}")
    except Exception as exc:
        print(f"  FAILED after {time.time() - t0:.1f}s: {type(exc).__name__}: {exc}")

    # ------------------------------------------------------------------
    # Test 3: google-genai SDK (what our app uses)
    # ------------------------------------------------------------------
    print("\n=== Test 3: google-genai SDK ===")
    t0 = time.time()
    try:
        import google.genai as genai_pkg
        print(f"  google-genai version: {getattr(genai_pkg, '__version__', 'unknown')}")
        from google import genai
        client = genai.Client(api_key=key)
        r = client.models.generate_content(
            model="gemini-flash-lite-latest",
            contents="Say hello",
        )
        print(f"  OK in {time.time() - t0:.1f}s")
        print(f"  Response: {r.text[:200]}")
    except Exception as exc:
        print(f"  FAILED after {time.time() - t0:.1f}s: {type(exc).__name__}: {exc}")


if __name__ == "__main__":
    main()
