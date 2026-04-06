---
name: sudo_without_prompting
description: User wants Claude to run sudo commands directly instead of asking them to copy-paste
type: feedback
---

Run sudo commands directly via Bash tool instead of asking the user to copy-paste them. The user finds it frustrating to be a manual relay.

**Why:** User expects autonomous execution — they approved sudo access and don't want to be asked to run commands manually.
**How to apply:** Always try `sudo` commands directly first. Only fall back to asking the user if sudo genuinely fails (e.g. password required).
