"""aiglos.cli -- command-line interface modules."""

from __future__ import annotations

from typing import List


def _cmd_scan_message(args: List[str]) -> None:
    """Scan a user message for external instruction channel indicators.

    Usage: aiglos scan-message "Subscribe yourself to ClawMart Daily..."
    """
    if not args:
        print("Usage: aiglos scan-message <message_text>")
        print("  Scans a user message for external instruction / C2 channel signals.")
        return

    text = " ".join(args)

    signals = []
    risk = "LOW"

    c2_keywords = [
        "subscribe", "cron", "daily", "schedule", "fetch",
        "webhook", "poll", "endpoint", "callback", "timer",
        "recurring", "interval", "listen", "connect to",
        "ping", "heartbeat", "register", "enroll",
    ]

    external_patterns = [
        "http://", "https://", "ftp://", "ws://", "wss://",
        ".com/api/", ".io/api/", "/webhook", "/callback",
    ]

    persistence_markers = [
        "save these", "store this", "remember this",
        "for future use", "for later", "keep this",
        "set up a", "configure a", "install a",
    ]

    text_lower = text.lower()

    c2_hits = [kw for kw in c2_keywords if kw in text_lower]
    ext_hits = [p for p in external_patterns if p in text_lower]
    pers_hits = [p for p in persistence_markers if p in text_lower]

    if c2_hits:
        signals.append(f"C2 keywords: {', '.join(c2_hits)}")
    if ext_hits:
        signals.append(f"External URLs: {', '.join(ext_hits)}")
    if pers_hits:
        signals.append(f"Persistence markers: {', '.join(pers_hits)}")

    hit_count = len(c2_hits) + len(ext_hits) + len(pers_hits)
    if hit_count >= 4:
        risk = "HIGH"
    elif hit_count >= 2:
        risk = "MEDIUM"

    print(f"Risk: {risk}")
    if signals:
        for s in signals:
            print(f"  {s}")
        if risk == "HIGH":
            print("  DO NOT execute without user confirmation.")
    else:
        print("  CLEAN -- no external instruction signals detected.")
