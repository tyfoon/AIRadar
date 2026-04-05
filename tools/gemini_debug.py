"""
Diagnostic script for Gemini API connectivity from inside the container.

Runs four independent tests so we can pinpoint exactly which layer fails:

  1. urllib POST (stdlib)         — raw HTTPS, no third-party deps
  2. httpx POST (HTTP/1.1 forced) — library the SDK uses, but HTTP/2 off
  3. httpx POST (default / HTTP/2)— default httpx behaviour
  4. google-genai SDK             — the full stack our app uses

Each test has its own timeout + prints progress immediately. If a test
hangs, you can Ctrl+C and the next one still runs.

Host usage:
    cd ~/AIradar && git pull
    sudo docker cp tools/gemini_debug.py airadar-app:/tmp/gemini_debug.py
    sudo docker compose exec airadar-app python3 /tmp/gemini_debug.py
"""
import json
import os
import socket
import sys
import time


# IPv4-only patch — same as api.py. Without this, socket.create_connection
# tries IPv6 first, waits ~63s for the kernel SYN retry timeout, then
# falls back to IPv4. Tests 1-3 complete in 60.5s because of this
# fallback; Test 4 (google-genai SDK) doesn't fall back at all and hangs.
_ORIG_GETADDRINFO = socket.getaddrinfo
def _ipv4_only_getaddrinfo(host, *args, **kwargs):
    results = _ORIG_GETADDRINFO(host, *args, **kwargs)
    filtered = [r for r in results if r[0] == socket.AF_INET]
    return filtered or results
socket.getaddrinfo = _ipv4_only_getaddrinfo
print("[net] IPv4-only getaddrinfo patch active in debug script")

# Flush print immediately so we see progress when a test hangs.
print = lambda *a, **k: __builtins__.print(*a, **{**k, "flush": True}) if hasattr(__builtins__, "print") else None
import builtins
_print = builtins.print
def p(*a, **k):
    _print(*a, flush=True, **k)


MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash-lite")
PAYLOAD = {"contents": [{"parts": [{"text": "Say hello in one word."}]}]}


def main():
    key = os.getenv("GEMINI_API_KEY", "")
    p(f"Script: gemini_debug.py")
    p(f"Model:  {MODEL}")
    p(f"Key set: {bool(key)} (length {len(key)})")
    if not key:
        p("GEMINI_API_KEY not set — aborting")
        return

    url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"{MODEL}:generateContent?key={key}"
    )

    # --- Test 1: urllib stdlib ---
    p("\n=== Test 1: urllib POST (stdlib, timeout 15s) ===")
    _test_urllib(url)

    # --- Test 2: httpx HTTP/1.1 forced ---
    p("\n=== Test 2: httpx POST (HTTP/1.1 forced, timeout 15s) ===")
    _test_httpx(url, http2=False)

    # --- Test 3: httpx default ---
    p("\n=== Test 3: httpx POST (default, timeout 15s) ===")
    _test_httpx(url, http2=None)

    # --- Test 4: google-genai SDK ---
    p("\n=== Test 4: google-genai SDK ===")
    _test_sdk(key)


def _test_urllib(url):
    import urllib.request, urllib.error
    t0 = time.time()
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(PAYLOAD).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            data = r.read()
        p(f"  OK in {time.time()-t0:.1f}s, {len(data)} bytes")
        p(f"  First 200 chars: {data[:200].decode(errors='replace')}")
    except urllib.error.HTTPError as e:
        body = e.read()[:300].decode(errors="replace")
        p(f"  HTTP {e.code} after {time.time()-t0:.1f}s")
        p(f"  Body: {body}")
    except Exception as exc:
        p(f"  FAILED after {time.time()-t0:.1f}s: {type(exc).__name__}: {exc}")


def _test_httpx(url, http2):
    t0 = time.time()
    try:
        import httpx
        p(f"  httpx version: {httpx.__version__}")
        kwargs = {"timeout": 15.0}
        if http2 is not None:
            kwargs["http2"] = http2
        with httpx.Client(**kwargs) as c:
            r = c.post(url, json=PAYLOAD)
        p(f"  OK in {time.time()-t0:.1f}s, status {r.status_code}")
        p(f"  First 200 chars: {r.text[:200]}")
    except Exception as exc:
        p(f"  FAILED after {time.time()-t0:.1f}s: {type(exc).__name__}: {exc}")


def _test_sdk(key):
    t0 = time.time()
    try:
        import google.genai as genai_pkg
        p(f"  google-genai version: {getattr(genai_pkg, '__version__', 'unknown')}")
        from google import genai
        client = genai.Client(api_key=key)
        r = client.models.generate_content(
            model=MODEL,
            contents="Say hello in one word.",
        )
        p(f"  OK in {time.time()-t0:.1f}s")
        p(f"  Response: {r.text[:200]}")
    except Exception as exc:
        p(f"  FAILED after {time.time()-t0:.1f}s: {type(exc).__name__}: {exc}")


if __name__ == "__main__":
    main()
