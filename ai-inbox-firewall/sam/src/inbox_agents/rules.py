import re
from typing import Any, Dict


SPAM_KEYWORDS = [
    r"free money",
    r"winner",
    r"claim now",
    r"act now",
    r"bitcoin",
    r"crypto giveaway",
    r"limited time",
    r"100% off",
]

NEWSLETTER_KEYWORDS = [
    r"newsletter",
    r"unsubscribe",
    r"daily digest",
    r"weekly roundup",
    r"your receipt",
]

URGENT_KEYWORDS = [
    r"asap",
    r"urgent",
    r"immediate",
    r"due today",
    r"deadline",
]

LOW_KEYWORDS = [
    r"fyi",
    r"no action required",
    r"for your information",
]


def _text(email: Dict[str, Any]) -> str:
    subject = str(email.get("subject", ""))
    body = str(email.get("body", ""))
    return f"{subject}\n{body}".lower()


def classify_spam(email: Dict[str, Any]) -> Dict[str, str]:
    """Rule-based spam / newsletter / legitimate classifier."""
    t = _text(email)

    if any(re.search(p, t) for p in SPAM_KEYWORDS):
        return {"spam_label": "spam", "reason": "Matched common spam keywords."}

    if any(re.search(p, t) for p in NEWSLETTER_KEYWORDS):
        return {"spam_label": "newsletter", "reason": "Looks like a newsletter/marketing email."}

    return {"spam_label": "legitimate", "reason": "No strong spam/newsletter signals."}


def assign_priority(email: Dict[str, Any]) -> Dict[str, str]:
    """Rule-based urgent / normal / low priority classifier."""
    t = _text(email)

    if any(re.search(p, t) for p in URGENT_KEYWORDS):
        return {"priority": "urgent", "reason": "Contains urgency keywords (asap, urgent, immediate)."}

    # High priority: deadlines
    if re.search(r"\b(today|tomorrow|eod|end of day|deadline)\b", t):
        return {"priority": "high", "reason": "Mentions near-term deadlines."}

    # Low priority
    if any(re.search(p, t) for p in LOW_KEYWORDS):
        return {"priority": "low", "reason": "Marked as FYI or no action required."}

    return {"priority": "medium", "reason": "Standard priority."}
