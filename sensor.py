"""
AI-Radar — Network Sensor (Phase 2).
Sniffs DNS (port 53), TLS Client Hello (TCP 443), and QUIC Initial (UDP 443)
traffic for outbound requests to known AI service domains, then forwards
detection events to the Phase 1 API for storage.

QUIC Initial packets are encrypted with keys derived from the publicly-visible
Destination Connection ID (DCID).  This sensor performs the full RFC 9001
key derivation and AES-128-GCM decryption to recover the TLS Client Hello
embedded inside QUIC CRYPTO frames, then extracts the SNI.

Must be run with root/sudo privileges (scapy requires raw socket access).
"""

from __future__ import annotations

import os
import subprocess
import sys
import socket
import threading
import time
from datetime import datetime, timezone

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from scapy.all import DNS, DNSQR, DNSRR, IP, IPv6, TCP, UDP, Raw, sniff

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

API_URL = "http://localhost:8000/api/ingest"
DEVICE_API_URL = "http://localhost:8000/api/devices"
SENSOR_ID = socket.gethostname()

# ---------------------------------------------------------------------------
# Device fingerprinting — resolve IPs to hostnames and MAC addresses
# ---------------------------------------------------------------------------
# Cache TTL in seconds — re-resolve devices after this period
DEVICE_CACHE_TTL = 300  # 5 minutes

# { ip: (hostname, mac, resolved_at_timestamp) }
_device_cache: dict[str, tuple[str | None, str | None, float]] = {}


def _resolve_hostname(ip: str) -> str | None:
    """Reverse DNS lookup.  Returns the hostname or None on failure."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


def _resolve_mac(ip: str) -> str | None:
    """Look up the MAC address for a local IP via the system ARP table."""
    try:
        result = subprocess.run(
            ["arp", "-n", ip],
            capture_output=True, text=True, timeout=3,
        )
        # macOS format: "? (192.168.1.5) at aa:bb:cc:dd:ee:ff on en0 ..."
        # Linux format: "192.168.1.5  ether aa:bb:cc:dd:ee:ff  C  en0"
        for line in result.stdout.splitlines():
            parts = line.split()
            for i, p in enumerate(parts):
                if p == "at" and i + 1 < len(parts):
                    mac = parts[i + 1]
                    if ":" in mac and mac != "(incomplete)":
                        return mac.lower()
                # Linux: field after "ether"
                if p == "ether" and i + 1 < len(parts):
                    return parts[i + 1].lower()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return None


def resolve_device(ip: str) -> tuple[str | None, str | None]:
    """Resolve an IP to (hostname, mac_address), using an in-memory cache.

    Returns cached results within DEVICE_CACHE_TTL seconds to avoid
    blocking the packet processing loop with slow DNS lookups.
    """
    now = time.time()
    cached = _device_cache.get(ip)
    if cached and (now - cached[2]) < DEVICE_CACHE_TTL:
        return cached[0], cached[1]

    hostname = _resolve_hostname(ip)
    mac = _resolve_mac(ip)
    _device_cache[ip] = (hostname, mac, now)
    return hostname, mac


def register_device_async(ip: str) -> None:
    """Resolve a device and POST it to the API in a background thread,
    so we never block the packet sniffer."""

    def _do_register():
        hostname, mac = resolve_device(ip)
        payload = {"ip": ip}
        if hostname:
            payload["hostname"] = hostname
        if mac:
            payload["mac_address"] = mac
        try:
            requests.post(DEVICE_API_URL, json=payload, timeout=5)
            name = hostname or mac or ip
            print(f"[*] Device registered: {ip} -> {name}")
        except requests.RequestException:
            pass  # API might not be running yet

    threading.Thread(target=_do_register, daemon=True).start()


# Set of IPs we've already kicked off registration for (avoid duplicates)
_registered_ips: set[str] = set()

# Known AI service domains — maps base domain -> service label.
AI_DOMAINS: dict[str, str] = {
    # Google Gemini
    "gemini.google.com":                    "google_gemini",
    "generativelanguage.googleapis.com":    "google_gemini",
    "aistudio.google.com":                  "google_gemini",
    # OpenAI / ChatGPT
    "openai.com":                           "openai",
    "chatgpt.com":                          "openai",
    "oaiusercontent.com":                   "openai",
    # Anthropic / Claude
    "claude.ai":                            "anthropic_claude",
    "anthropic.com":                        "anthropic_claude",
    # Microsoft Copilot
    "copilot.microsoft.com":                "microsoft_copilot",
    "sydney.bing.com":                      "microsoft_copilot",
    # Perplexity
    "perplexity.ai":                        "perplexity",
    # Hugging Face
    "huggingface.co":                       "huggingface",
    # Mistral
    "mistral.ai":                           "mistral",
}

# ---------------------------------------------------------------------------
# Volumetric upload detection
# ---------------------------------------------------------------------------
# Threshold in bytes — if outbound payload to an AI IP exceeds this within
# the tracking window, we flag it as a possible file/data upload.
UPLOAD_THRESHOLD_BYTES = 100_000  # 100 KB

# Maps resolved AI destination IPs → service name (populated from DNS responses)
_ai_ip_map: dict[str, str] = {}

# Tracks cumulative outbound bytes per AI *service* (not per IP, because a
# single service can resolve to many IPs via CDN/load balancing)
_outbound_bytes: dict[str, int] = {}

# Tracks the last source IP that sent traffic to each service
_outbound_src: dict[str, str] = {}

# ---------------------------------------------------------------------------
# QUIC v1 cryptographic constants (RFC 9001 §5)
# ---------------------------------------------------------------------------

# The salt used to derive the Initial Secret from the client's DCID.
# This is a well-known, fixed value defined in RFC 9001 §5.2.
QUIC_V1_SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")

# HKDF labels used by QUIC (RFC 9001 §5.1).  QUIC uses the TLS 1.3 style
# HKDF-Expand-Label which prepends "tls13 " to the label.
#   client_in  → derives the client Initial secret from the Initial secret
#   quic key   → derives the AES key from the client secret
#   quic iv    → derives the IV/nonce from the client secret
#   quic hp    → derives the header-protection key from the client secret
LABEL_CLIENT_IN = b"client in"
LABEL_KEY       = b"quic key"
LABEL_IV        = b"quic iv"
LABEL_HP        = b"quic hp"


# ---------------------------------------------------------------------------
# QUIC crypto helpers
# ---------------------------------------------------------------------------

def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract (RFC 5869 §2.2): derive a pseudo-random key from input
    keying material using HMAC-SHA256."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"",
    )
    # HKDF in the cryptography library combines Extract+Expand.  We need
    # just the Extract step, so we use HMAC directly.
    import hmac as _hmac
    return _hmac.new(salt, ikm, "sha256").digest()


def _hkdf_expand_label(secret: bytes, label: bytes, length: int) -> bytes:
    """TLS 1.3 / QUIC HKDF-Expand-Label (RFC 8446 §7.1, RFC 9001 §5.1).

    Constructs the info parameter as:
      - 2 bytes: output length
      - 1 byte:  label length (including "tls13 " prefix)
      - N bytes: "tls13 " + label
      - 1 byte:  context length (0 — no context for QUIC Initial)
    Then runs HKDF-Expand with SHA-256.
    """
    full_label = b"tls13 " + label
    # Build the HkdfLabel struct
    info = (
        length.to_bytes(2, "big")
        + len(full_label).to_bytes(1, "big")
        + full_label
        + b"\x00"  # empty context
    )
    hkdf = HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info)
    return hkdf.derive(secret)


def derive_quic_client_keys(dcid: bytes) -> tuple[bytes, bytes, bytes]:
    """Derive the client's AES-128-GCM key, IV, and header-protection key
    from the Destination Connection ID found in the QUIC Initial packet.

    Derivation chain (RFC 9001 §5.2):
      1. initial_secret  = HKDF-Extract(salt=QUIC_V1_SALT, IKM=DCID)
      2. client_secret   = HKDF-Expand-Label(initial_secret, "client in", 32)
      3. key (16 bytes)  = HKDF-Expand-Label(client_secret,  "quic key",  16)
      4. iv  (12 bytes)  = HKDF-Expand-Label(client_secret,  "quic iv",   12)
      5. hp  (16 bytes)  = HKDF-Expand-Label(client_secret,  "quic hp",   16)
    """
    # Step 1: Extract the Initial Secret
    initial_secret = _hkdf_extract(QUIC_V1_SALT, dcid)

    # Step 2: Derive the client-side Initial secret
    client_secret = _hkdf_expand_label(initial_secret, LABEL_CLIENT_IN, 32)

    # Steps 3-5: Derive the AES key, IV, and header-protection key
    key = _hkdf_expand_label(client_secret, LABEL_KEY, 16)  # AES-128 key
    iv  = _hkdf_expand_label(client_secret, LABEL_IV,  12)  # 96-bit nonce
    hp  = _hkdf_expand_label(client_secret, LABEL_HP,  16)  # HP key

    return key, iv, hp


def _remove_header_protection(
    data: bytes,
    hp_key: bytes,
    pn_offset: int,
) -> tuple[bytes, int, int]:
    """Remove QUIC header protection to reveal the true first byte and
    packet number (RFC 9001 §5.4).

    QUIC encrypts parts of the header (the packet-number length bits in
    the first byte, and the packet number itself) using AES-ECB of a
    sample taken from the encrypted payload.

    Args:
        data:      the full UDP payload (QUIC packet)
        hp_key:    the 16-byte header-protection key
        pn_offset: byte offset where the packet number starts

    Returns:
        (modified_data, packet_number, pn_length)
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    # The sample is 16 bytes starting 4 bytes after the packet number offset
    sample_offset = pn_offset + 4
    if sample_offset + 16 > len(data):
        raise ValueError("Packet too short for HP sample")
    sample = data[sample_offset:sample_offset + 16]

    # Generate the mask by encrypting the sample with AES-ECB
    cipher = Cipher(algorithms.AES(hp_key), modes.ECB())
    encryptor = cipher.encryptor()
    mask = encryptor.update(sample) + encryptor.finalize()

    # Unmask the first byte — for long headers, only the lower 4 bits
    # (which encode packet number length - 1) are protected
    data = bytearray(data)
    data[0] ^= mask[0] & 0x0f

    # The packet number length is encoded in the lowest 2 bits of the
    # (now unmasked) first byte, plus one
    pn_length = (data[0] & 0x03) + 1

    # Unmask the packet number bytes
    for i in range(pn_length):
        data[pn_offset + i] ^= mask[1 + i]

    # Read the packet number
    pn = int.from_bytes(data[pn_offset:pn_offset + pn_length], "big")

    return bytes(data), pn, pn_length


def _read_var_int(data: bytes, offset: int) -> tuple[int, int]:
    """Read a QUIC variable-length integer (RFC 9000 §16).

    The two most-significant bits of the first byte encode the length:
      00 → 1 byte  (6-bit value)
      01 → 2 bytes (14-bit value)
      10 → 4 bytes (30-bit value)
      11 → 8 bytes (62-bit value)

    Returns (value, new_offset).
    """
    first = data[offset]
    prefix = first >> 6
    if prefix == 0:
        return first & 0x3F, offset + 1
    elif prefix == 1:
        val = int.from_bytes(data[offset:offset + 2], "big") & 0x3FFF
        return val, offset + 2
    elif prefix == 2:
        val = int.from_bytes(data[offset:offset + 4], "big") & 0x3FFFFFFF
        return val, offset + 4
    else:
        val = int.from_bytes(data[offset:offset + 8], "big") & 0x3FFFFFFFFFFFFFFF
        return val, offset + 8


def _extract_crypto_frames(decrypted: bytes) -> list[tuple[int, bytes]]:
    """Walk QUIC frames in the decrypted payload and return a list of
    (stream_offset, data) tuples from CRYPTO frames (type 0x06).

    The stream_offset indicates where each chunk belongs in the TLS
    handshake byte stream — this is critical for reassembling a Client
    Hello that spans multiple QUIC packets.

    CRYPTO frame layout (RFC 9000 §19.6):
      - type:   0x06 (variable-length int, but always 1 byte)
      - offset: variable-length int (byte offset in the crypto stream)
      - length: variable-length int
      - data:   <length> bytes of TLS handshake data
    """
    fragments: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(decrypted):
        frame_type = decrypted[offset]

        # PADDING frames (type 0x00) — skip
        if frame_type == 0x00:
            offset += 1
            continue

        # PING frames (type 0x01) — skip
        if frame_type == 0x01:
            offset += 1
            continue

        # CRYPTO frame (type 0x06) — extract data with its stream offset
        if frame_type == 0x06:
            offset += 1
            crypto_offset, offset = _read_var_int(decrypted, offset)
            crypto_len, offset = _read_var_int(decrypted, offset)
            if offset + crypto_len > len(decrypted):
                break
            fragments.append((crypto_offset, decrypted[offset:offset + crypto_len]))
            offset += crypto_len
            continue

        # ACK frame (type 0x02 or 0x03) — we must parse to skip
        if frame_type in (0x02, 0x03):
            offset += 1
            _largest_ack, offset = _read_var_int(decrypted, offset)
            _ack_delay, offset = _read_var_int(decrypted, offset)
            ack_range_count, offset = _read_var_int(decrypted, offset)
            _first_range, offset = _read_var_int(decrypted, offset)
            for _ in range(ack_range_count):
                _gap, offset = _read_var_int(decrypted, offset)
                _ack_range, offset = _read_var_int(decrypted, offset)
            if frame_type == 0x03:  # ACK with ECN counts
                _ect0, offset = _read_var_int(decrypted, offset)
                _ect1, offset = _read_var_int(decrypted, offset)
                _ecn_ce, offset = _read_var_int(decrypted, offset)
            continue

        # CONNECTION_CLOSE (0x1c, 0x1d) — parse and stop
        if frame_type in (0x1C, 0x1D):
            break

        # Unknown frame — can't safely skip without knowing length, stop
        break

    return fragments


def _extract_sni_from_client_hello(hs_data: bytes) -> str | None:
    """Parse a raw TLS Client Hello handshake message (without the TLS
    record header) and extract the SNI hostname.

    This is the same structure as extract_sni() expects after byte 5,
    but here we receive just the handshake message directly from QUIC
    CRYPTO frames (no 5-byte TLS record wrapper).

    Handshake layout:
      byte  0       : handshake type (0x01 = Client Hello)
      bytes 1-3     : handshake length
      bytes 4-5     : client version (0x0303 for TLS 1.2 compat)
      bytes 6-37    : client random (32 bytes)
      byte  38      : session ID length → skip session ID
      ...           : cipher suites, compression, extensions (same as TLS)
    """
    try:
        if len(hs_data) < 42 or hs_data[0] != 0x01:
            return None

        offset = 38  # session ID length

        # Skip session ID
        session_id_len = hs_data[offset]
        offset += 1 + session_id_len

        # Skip cipher suites
        if offset + 2 > len(hs_data):
            return None
        cs_len = int.from_bytes(hs_data[offset:offset + 2], "big")
        offset += 2 + cs_len

        # Skip compression methods
        if offset + 1 > len(hs_data):
            return None
        comp_len = hs_data[offset]
        offset += 1 + comp_len

        # Extensions
        if offset + 2 > len(hs_data):
            return None
        ext_total = int.from_bytes(hs_data[offset:offset + 2], "big")
        offset += 2
        ext_end = offset + ext_total

        while offset + 4 <= ext_end:
            ext_type = int.from_bytes(hs_data[offset:offset + 2], "big")
            ext_len = int.from_bytes(hs_data[offset + 2:offset + 4], "big")
            offset += 4

            if ext_type == 0x0000:  # SNI
                if offset + 5 > len(hs_data):
                    return None
                sni_type = hs_data[offset + 2]
                name_len = int.from_bytes(hs_data[offset + 3:offset + 5], "big")
                if sni_type == 0 and offset + 5 + name_len <= len(hs_data):
                    return hs_data[offset + 5:offset + 5 + name_len].decode(
                        "ascii", errors="ignore"
                    )
                return None

            offset += ext_len

    except (IndexError, ValueError):
        return None

    return None


# ---------------------------------------------------------------------------
# QUIC CRYPTO stream reassembly buffer
# ---------------------------------------------------------------------------
# The TLS Client Hello can span multiple QUIC Initial packets.  Each packet
# carries CRYPTO frames with a stream offset indicating where the data
# belongs.  We buffer fragments keyed by DCID and reassemble the stream
# once we have contiguous data starting from offset 0.
#
# Buffers are evicted after MAX_CONNECTIONS entries or when the SNI is found.

MAX_CONNECTIONS = 256
_crypto_streams: dict[bytes, bytearray] = {}
_crypto_seen_dcids: list[bytes] = []  # LRU order for eviction


def _reassemble_crypto_stream(dcid: bytes, fragments: list[tuple[int, bytes]]) -> bytes | None:
    """Insert fragments into the per-connection buffer and return the
    contiguous byte stream starting from offset 0, or None if offset 0
    is still missing."""

    # Get or create the stream buffer for this DCID
    if dcid not in _crypto_streams:
        # Evict oldest if at capacity
        if len(_crypto_seen_dcids) >= MAX_CONNECTIONS:
            old = _crypto_seen_dcids.pop(0)
            _crypto_streams.pop(old, None)
        _crypto_streams[dcid] = bytearray()
        _crypto_seen_dcids.append(dcid)

    buf = _crypto_streams[dcid]

    # Insert each fragment at its stream offset, extending the buffer
    # if needed (sparse regions are filled with zeros)
    for crypto_offset, data in fragments:
        end = crypto_offset + len(data)
        if end > len(buf):
            buf.extend(b"\x00" * (end - len(buf)))
        buf[crypto_offset:end] = data

    # Check if we have data starting from offset 0 with a valid
    # Client Hello header (type 0x01)
    if len(buf) < 4 or buf[0] != 0x01:
        return None

    # Read the Client Hello length from bytes 1-3
    ch_len = int.from_bytes(buf[1:4], "big")
    total_needed = 4 + ch_len  # type(1) + length(3) + body

    if len(buf) >= total_needed:
        return bytes(buf[:total_needed])

    # We don't have the full Client Hello yet, but the SNI is near the
    # start — try to parse with what we have so far
    if len(buf) > 100:
        return bytes(buf)

    return None


def _cleanup_crypto_stream(dcid: bytes) -> None:
    """Remove the reassembly buffer for a completed connection."""
    _crypto_streams.pop(dcid, None)
    try:
        _crypto_seen_dcids.remove(dcid)
    except ValueError:
        pass


def decrypt_quic_initial(raw_bytes: bytes) -> str | None:
    """Full QUIC v1 Initial packet decryption to extract the SNI.

    Implements the complete cryptographic pipeline from RFC 9001:
      1. Parse the QUIC long header to extract the DCID
      2. Derive Initial keys from the DCID using HKDF
      3. Remove header protection (AES-ECB mask)
      4. Decrypt the payload with AES-128-GCM
      5. Extract CRYPTO frame fragments with their stream offsets
      6. Reassemble the TLS handshake stream across multiple packets
      7. Extract the SNI extension from the Client Hello

    The Client Hello for modern TLS 1.3 (with large key shares) often
    exceeds a single QUIC packet.  This function buffers CRYPTO fragments
    per DCID and attempts SNI extraction after each new packet.

    Args:
        raw_bytes: raw UDP payload (the QUIC packet)

    Returns:
        The SNI hostname string, or None if decryption/parsing fails
        or the stream is not yet complete enough to extract the SNI.
    """
    try:
        if len(raw_bytes) < 20:
            return None

        first_byte = raw_bytes[0]

        # Must be a long header (bit 7 set)
        if (first_byte & 0x80) == 0:
            return None

        # Check packet type — only process Initial (type bits 5-4 == 00)
        # These bits are NOT header-protected for long headers
        if (first_byte & 0x30) != 0x00:
            return None

        # ---- Parse the long header fields ----

        version = int.from_bytes(raw_bytes[1:5], "big")
        if version not in (0x00000001, 0x6B3343CF):
            return None

        offset = 5

        # DCID
        dcid_len = raw_bytes[offset]
        offset += 1
        if dcid_len > 20 or offset + dcid_len > len(raw_bytes):
            return None
        dcid = raw_bytes[offset:offset + dcid_len]
        offset += dcid_len

        # SCID
        scid_len = raw_bytes[offset]
        offset += 1
        offset += scid_len

        # Token
        token_len, offset = _read_var_int(raw_bytes, offset)
        offset += token_len

        # Payload length
        payload_len, offset = _read_var_int(raw_bytes, offset)
        pn_offset = offset

        # ---- Derive cryptographic keys from the DCID ----
        key, iv, hp_key = derive_quic_client_keys(dcid)

        # ---- Remove header protection ----
        unprotected, pn, pn_length = _remove_header_protection(
            raw_bytes, hp_key, pn_offset
        )

        # ---- Decrypt the payload with AES-128-GCM ----
        encrypted_start = pn_offset + pn_length
        encrypted_len = payload_len - pn_length
        if encrypted_start + encrypted_len > len(unprotected):
            return None

        ciphertext = unprotected[encrypted_start:encrypted_start + encrypted_len]

        pn_bytes = pn.to_bytes(12, "big")
        nonce = bytes(a ^ b for a, b in zip(iv, pn_bytes))
        aad = unprotected[:encrypted_start]

        aesgcm = AESGCM(key)
        try:
            decrypted = aesgcm.decrypt(nonce, ciphertext, aad)
        except Exception:
            return None

        # ---- Extract CRYPTO frame fragments ----
        fragments = _extract_crypto_frames(decrypted)
        if not fragments:
            return None

        # ---- Reassemble the TLS handshake stream ----
        crypto_data = _reassemble_crypto_stream(dcid, fragments)
        if not crypto_data:
            return None

        # ---- Try to extract SNI ----
        sni = _extract_sni_from_client_hello(crypto_data)
        if sni:
            _cleanup_crypto_stream(dcid)  # done with this connection
        return sni

    except (IndexError, ValueError, Exception):
        return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def match_ai_domain(hostname: str) -> tuple[str, str] | None:
    """Return (matched_domain, service_name) if hostname matches a known AI
    domain, otherwise None.  Supports exact and subdomain matches."""
    hostname = hostname.rstrip(".").lower()
    for domain, service in AI_DOMAINS.items():
        if hostname == domain or hostname.endswith("." + domain):
            return domain, service
    return None


def send_event(
    detection_type: str,
    ai_service: str,
    source_ip: str,
    bytes_transferred: int,
    possible_upload: bool = False,
) -> None:
    """POST a detection event to the Phase 1 API."""
    event = {
        "sensor_id": SENSOR_ID,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "detection_type": detection_type,
        "ai_service": ai_service,
        "source_ip": source_ip,
        "bytes_transferred": bytes_transferred,
        "possible_upload": possible_upload,
    }
    try:
        resp = requests.post(API_URL, json=event, timeout=5)
        resp.raise_for_status()
        upload_tag = " [UPLOAD]" if possible_upload else ""
        print(
            f"[+] Event sent to API: {ai_service.upper()} detected "
            f"({detection_type}) from {source_ip}{upload_tag}"
        )
    except requests.RequestException as exc:
        print(f"[!] Failed to send event: {exc}")


# ---------------------------------------------------------------------------
# TLS record SNI parser (for TCP Client Hello packets)
# ---------------------------------------------------------------------------

def extract_sni(raw_bytes: bytes) -> str | None:
    """Parse the SNI hostname from a TLS Client Hello payload.

    TLS record layout (simplified):
      byte  0       : content type (0x16 = handshake)
      bytes 1-2     : TLS version
      bytes 3-4     : record length
      byte  5       : handshake type (0x01 = Client Hello)
      bytes 6-8     : handshake length
      bytes 9-10    : client version
      bytes 11-42   : random (32 bytes)
      byte  43      : session ID length  -> skip session ID
      ...           : cipher suites length (2 bytes) -> skip
      ...           : compression methods length (1 byte) -> skip
      ...           : extensions length (2 bytes)
      ...           : extensions list — look for type 0x0000 (SNI)
    """
    try:
        if len(raw_bytes) < 44 or raw_bytes[0] != 0x16:
            return None
        if raw_bytes[5] != 0x01:
            return None

        offset = 43

        session_id_len = raw_bytes[offset]
        offset += 1 + session_id_len

        if offset + 2 > len(raw_bytes):
            return None
        cipher_suites_len = int.from_bytes(raw_bytes[offset:offset + 2], "big")
        offset += 2 + cipher_suites_len

        if offset + 1 > len(raw_bytes):
            return None
        comp_methods_len = raw_bytes[offset]
        offset += 1 + comp_methods_len

        if offset + 2 > len(raw_bytes):
            return None
        extensions_len = int.from_bytes(raw_bytes[offset:offset + 2], "big")
        offset += 2
        extensions_end = offset + extensions_len

        while offset + 4 <= extensions_end:
            ext_type = int.from_bytes(raw_bytes[offset:offset + 2], "big")
            ext_len = int.from_bytes(raw_bytes[offset + 2:offset + 4], "big")
            offset += 4

            if ext_type == 0x0000:
                if offset + 5 > len(raw_bytes):
                    return None
                sni_type = raw_bytes[offset + 2]
                name_len = int.from_bytes(
                    raw_bytes[offset + 3:offset + 5], "big"
                )
                if sni_type == 0 and offset + 5 + name_len <= len(raw_bytes):
                    return raw_bytes[offset + 5:offset + 5 + name_len].decode(
                        "ascii", errors="ignore"
                    )
                return None

            offset += ext_len

    except (IndexError, ValueError):
        return None

    return None


# ---------------------------------------------------------------------------
# Packet callback
# ---------------------------------------------------------------------------

def _get_src_ip(pkt) -> str | None:
    """Return the source IP from an IPv4 or IPv6 packet."""
    if pkt.haslayer(IP):
        return pkt[IP].src
    if pkt.haslayer(IPv6):
        return pkt[IPv6].src
    return None


def _get_dst_ip(pkt) -> str | None:
    """Return the destination IP from an IPv4 or IPv6 packet."""
    if pkt.haslayer(IP):
        return pkt[IP].dst
    if pkt.haslayer(IPv6):
        return pkt[IPv6].dst
    return None


def _learn_ai_ips_from_dns(pkt) -> None:
    """Extract resolved IPs from DNS responses and map them to AI services.

    When the OS resolves an AI domain (e.g. api.openai.com → 104.18.x.x),
    we record the IP so that subsequent TCP/UDP data packets to that IP
    can be attributed to the correct AI service for upload tracking.
    """
    if not (pkt.haslayer(DNS) and pkt[DNS].ancount and pkt[DNS].ancount > 0):
        return

    # Get the queried name from the question section
    if not pkt.haslayer(DNSQR):
        return
    qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore")
    match = match_ai_domain(qname)
    if not match:
        return
    _, service = match

    # Walk all answer records and map resolved IPs to this service
    for i in range(pkt[DNS].ancount):
        try:
            rr = pkt[DNS].an[i] if pkt[DNS].ancount > 1 else pkt[DNS].an
            if hasattr(rr, "rdata"):
                ip = rr.rdata
                if isinstance(ip, bytes):
                    ip = ip.decode("utf-8", errors="ignore")
                ip = str(ip)
                if ip and ip not in _ai_ip_map:
                    _ai_ip_map[ip] = service
                    print(f"[*] Learned AI IP: {ip} -> {service}")
        except (IndexError, AttributeError):
            break


def _track_outbound_bytes(pkt) -> None:
    """Track outbound TCP/UDP payload bytes to known AI services.

    Bytes are accumulated per service name (not per IP), so that traffic
    spread across multiple CDN/load-balancer IPs for the same service
    is counted together and only triggers one upload event.

    When the accumulated outbound data exceeds UPLOAD_THRESHOLD_BYTES,
    fire a 'volumetric_upload' event and reset the counter.
    """
    dst_ip = _get_dst_ip(pkt)
    if dst_ip is None or dst_ip not in _ai_ip_map:
        return

    # Only count outbound data packets with payload (port 443)
    payload_size = 0
    if pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt[TCP].dport == 443:
        payload_size = len(pkt[Raw].load)
    elif pkt.haslayer(UDP) and pkt.haslayer(Raw) and pkt[UDP].dport == 443:
        payload_size = len(pkt[Raw].load)

    if payload_size == 0:
        return

    service = _ai_ip_map[dst_ip]
    src_ip = _get_src_ip(pkt) or "unknown"
    _outbound_bytes[service] = _outbound_bytes.get(service, 0) + payload_size
    _outbound_src[service] = src_ip

    if _outbound_bytes[service] >= UPLOAD_THRESHOLD_BYTES:
        total = _outbound_bytes[service]
        send_event(
            detection_type="volumetric_upload",
            ai_service=service,
            source_ip=src_ip,
            bytes_transferred=total,
            possible_upload=True,
        )
        _outbound_bytes[service] = 0


def process_packet(pkt) -> None:
    """Callback invoked by scapy for every captured packet."""

    src_ip = _get_src_ip(pkt)
    if src_ip is None:
        return

    # --- Device fingerprinting: register unknown source IPs ---
    if src_ip not in _registered_ips and not src_ip.startswith(("127.", "::1")):
        _registered_ips.add(src_ip)
        register_device_async(src_ip)

    # --- DNS: learn AI IPs from responses + detect AI queries ---
    if pkt.haslayer(DNS):
        _learn_ai_ips_from_dns(pkt)
        if pkt.haslayer(DNSQR):
            qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore")
            match = match_ai_domain(qname)
            if match:
                _, service = match
                send_event(
                    detection_type="dns_query",
                    ai_service=service,
                    source_ip=src_ip,
                    bytes_transferred=len(pkt),
                )
        return

    # --- Track outbound bytes for upload detection ---
    _track_outbound_bytes(pkt)

    # --- TLS Client Hello / SNI detection (TCP 443) ---
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        sni = extract_sni(bytes(pkt[Raw].load))
        if sni:
            match = match_ai_domain(sni)
            if match:
                _, service = match
                # Also learn the destination IP from TLS SNI
                dst_ip = _get_dst_ip(pkt)
                if dst_ip and dst_ip not in _ai_ip_map:
                    _ai_ip_map[dst_ip] = service
                    print(f"[*] Learned AI IP (SNI): {dst_ip} -> {service}")
                send_event(
                    detection_type="sni_hello",
                    ai_service=service,
                    source_ip=src_ip,
                    bytes_transferred=len(pkt),
                )
        return

    # --- QUIC Initial / SNI detection (UDP 443) ---
    if pkt.haslayer(UDP) and pkt.haslayer(Raw):
        if pkt[UDP].dport == 443 or pkt[UDP].sport == 443:
            sni = decrypt_quic_initial(bytes(pkt[Raw].load))
            if sni:
                match = match_ai_domain(sni)
                if match:
                    _, service = match
                    dst_ip = _get_dst_ip(pkt)
                    if dst_ip and dst_ip not in _ai_ip_map:
                        _ai_ip_map[dst_ip] = service
                        print(f"[*] Learned AI IP (QUIC): {dst_ip} -> {service}")
                    send_event(
                        detection_type="quic_sni",
                        ai_service=service,
                        source_ip=src_ip,
                        bytes_transferred=len(pkt),
                    )


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    if os.geteuid() != 0:
        print("[!] This sensor must be run as root (sudo). Exiting.")
        sys.exit(1)

    print(f"[*] AI-Radar sensor starting on host '{SENSOR_ID}'")
    print(f"[*] Reporting to API at {API_URL}")
    print(f"[*] Monitoring {len(AI_DOMAINS)} AI domains")
    print("[*] Sniffing DNS (port 53), TLS (TCP 443) and QUIC (UDP 443) traffic …")
    print("[*] QUIC Initial decryption enabled (RFC 9001 AES-128-GCM)")
    print(f"[*] Upload detection threshold: {UPLOAD_THRESHOLD_BYTES:,} bytes\n")

    sniff(
        filter="port 53 or port 443",
        prn=process_packet,
        store=False,
    )


if __name__ == "__main__":
    main()
