"""
AI-Radar — PydanticAI agent factories.

Wraps the LLM calls used by /api/devices/{mac}/report and
/api/alerts/ai-summary in PydanticAI agents that return typed,
schema-validated outputs.

Why this lives in its own module:
  - Keeps the LLM provider plumbing in one place so we can swap from
    Gemini to Claude/Ollama/OpenAI by changing one function instead of
    chasing google-genai imports through api.py.
  - Lets api.py focus on building the data block — the prompt-shape
    work that's actually domain-specific — and treat the agent as a
    typed function: in goes a markdown context, out comes a validated
    Pydantic object.

Why typed output:
  - The legacy code returns a markdown string and the UI string-matches
    on the section headers ("## Samenvatting" vs "## Summary") to
    detect language. Now we get the markdown plus structured flags
    (vpn_detected, ai_usage_present, ...) that the UI can filter on.
  - PydanticAI auto-retries when the model returns malformed JSON, so
    transient parse failures don't bubble up as 502s.
  - The "slightly longer" latency is the price of (a) the extra output
    tokens for the structured fields and (b) one auto-retry on the
    rare validation failure. In exchange we get reliable structure
    instead of regex over markdown.

Provider:
  Default = google-gla (Google AI Studio, same path as the existing
  google-genai SDK). Override AI_AGENT_PROVIDER + AI_AGENT_MODEL in
  .env to swap. Example for the EOL migration plan:
      AI_AGENT_PROVIDER=anthropic
      AI_AGENT_MODEL=claude-haiku-4-5

Fail-closed:
  If pydantic-ai isn't importable for any reason, the get_*_agent()
  factories raise PydanticAIUnavailable. The api.py call sites catch
  that and fall back to the legacy google-genai path so we never
  break the device report endpoint during a deploy.
"""

from __future__ import annotations

import os
from typing import Literal, Optional

from pydantic import BaseModel, Field


class PydanticAIUnavailable(RuntimeError):
    """Raised when pydantic-ai cannot be imported or configured."""


# ---------------------------------------------------------------------------
# Output schemas
# ---------------------------------------------------------------------------

class RecapFlags(BaseModel):
    """High-signal flags extracted from a device's 24h activity.

    The frontend can filter / badge devices on these without having to
    parse the markdown body. Add fields here as we identify more
    repeatable patterns we want to surface — bumping the schema only
    affects new reports, cached ones are read back from the markdown.
    """

    vpn_detected: bool = Field(
        default=False,
        description="True if any vpn_* service was active in the window.",
    )
    ai_usage_present: bool = Field(
        default=False,
        description="True if openai/anthropic/google_gemini/copilot/etc. were used.",
    )
    ad_tracker_heavy: bool = Field(
        default=False,
        description="True if 5+ ad-tracking services appeared (adform, openx, rtb_house, vidazoo, etc.).",
    )
    unexpected_services: bool = Field(
        default=False,
        description="True if a service appeared that doesn't match the device type "
                    "(e.g. baidu on a Dutch laptop, AI on a child's tablet).",
    )
    upload_anomaly: bool = Field(
        default=False,
        description="True if the device pushed unusually large uploads in the window.",
    )
    activity_level: Literal["idle", "light", "moderate", "active"] = Field(
        default="light",
        description="Overall activity level — must match the ACTIVE/MODERATE/LIGHT/IDLE "
                    "label provided in the data block.",
    )


class DeviceRecap(BaseModel):
    """Structured device activity recap.

    The `markdown` field is the primary product — what the drawer renders.
    The other fields are extracted metadata for future filters and
    dashboards. Keep `markdown` non-empty: the UI relies on it.
    """

    tldr: str = Field(
        description="One sentence (max 25 words) describing what this device is and "
                    "what it's doing right now. No jargon.",
    )
    markdown: str = Field(
        description="Full markdown report following the structure specified in the system "
                    "prompt — section headers, day breakdown, observations. This is what "
                    "the user sees in the drawer, so it MUST be complete and well-formed.",
    )
    flags: RecapFlags = Field(default_factory=RecapFlags)
    services_active: list[str] = Field(
        default_factory=list,
        description="Service names from the ACTIVELY USED bucket only — never include "
                    "services from LIGHT or BACKGROUND. Max 10.",
    )
    observations: list[str] = Field(
        default_factory=list,
        description="2-4 short observation bullets the markdown body references. "
                    "Each bullet is one sentence, no markdown formatting.",
    )


class AlertSummary(BaseModel):
    """Plain-language summary of the active alert inbox."""

    summary: str = Field(
        description="2-3 plain Dutch sentences, no jargon, focused on what the user "
                    "should DO. No bullets, no list, just prose.",
    )
    priority: Literal["low", "medium", "high"] = Field(
        description="Overall urgency. 'high' = needs immediate attention, "
                    "'medium' = should be reviewed today, 'low' = informational.",
    )
    devices_to_check: list[str] = Field(
        default_factory=list,
        description="Device display names that the user should look at first. Max 5.",
    )


# ---------------------------------------------------------------------------
# Agent factories
# ---------------------------------------------------------------------------

# Default model — same as the legacy google-genai code path so behaviour
# is identical until the user overrides it. When 2.5-flash-lite is EOL'd
# in July 2026 we either bump this default or set AI_AGENT_MODEL in .env.
DEFAULT_MODEL = os.getenv("AI_AGENT_MODEL", "gemini-2.5-flash-lite")
DEFAULT_PROVIDER = os.getenv("AI_AGENT_PROVIDER", "google-gla")


def _build_model(model_name: Optional[str] = None, provider_name: Optional[str] = None):
    """Construct a pydantic-ai model object for the requested provider.

    Currently only google-gla is wired up. Adding anthropic / openai is
    a matter of importing the right Provider + Model class — they all
    share the same Agent interface.
    """
    try:
        from pydantic_ai.models.google import GoogleModel
        from pydantic_ai.providers.google import GoogleProvider
    except ImportError as exc:
        raise PydanticAIUnavailable(
            f"pydantic-ai not installed (run `pip install -r requirements.txt`): {exc}"
        ) from exc

    provider_name = provider_name or DEFAULT_PROVIDER
    model_name = model_name or DEFAULT_MODEL

    if provider_name == "google-gla":
        api_key = os.getenv("GEMINI_API_KEY", "").strip()
        if not api_key:
            raise PydanticAIUnavailable(
                "GEMINI_API_KEY not configured — set it in .env to use the "
                "google-gla provider, or set AI_AGENT_PROVIDER to switch."
            )
        return GoogleModel(model_name, provider=GoogleProvider(api_key=api_key))

    raise PydanticAIUnavailable(
        f"Provider '{provider_name}' is not wired up yet. Supported: google-gla. "
        f"Add a new branch in ai_agent._build_model to enable more."
    )


def get_device_recap_agent(system_prompt: str, model_name: Optional[str] = None):
    """Return an Agent that produces a DeviceRecap.

    The system_prompt is the same multi-paragraph instruction block the
    legacy code builds (Dutch or English). PydanticAI will append its
    own schema-instruction notes so the model knows the JSON shape.
    """
    try:
        from pydantic_ai import Agent
    except ImportError as exc:
        raise PydanticAIUnavailable(
            f"pydantic-ai not installed: {exc}"
        ) from exc

    model = _build_model(model_name=model_name)
    return Agent(
        model,
        output_type=DeviceRecap,
        system_prompt=system_prompt,
        retries=2,  # one auto-retry if the model returns malformed JSON
    )


def get_alert_summary_agent(system_prompt: str, model_name: Optional[str] = None):
    """Return an Agent that produces an AlertSummary."""
    try:
        from pydantic_ai import Agent
    except ImportError as exc:
        raise PydanticAIUnavailable(
            f"pydantic-ai not installed: {exc}"
        ) from exc

    model = _build_model(model_name=model_name)
    return Agent(
        model,
        output_type=AlertSummary,
        system_prompt=system_prompt,
        retries=2,
    )
