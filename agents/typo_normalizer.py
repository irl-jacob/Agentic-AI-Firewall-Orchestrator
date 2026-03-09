"""Typo normalizer for AFO.

Handles common typos, casual phrasing, and urgency detection.
"""

import re


class TypoNormalizer:
    """Normalizes typos and casual language in user input."""

    def __init__(self):
        # Common typo mappings
        self.typo_map = {
            # Casual/informal
            "plz": "please",
            "pls": "please",
            "thx": "thanks",
            "ty": "thank you",
            "u": "you",
            "ur": "your",
            "r": "are",

            # Contractions without apostrophes
            "dont": "don't",
            "doesnt": "doesn't",
            "cant": "can't",
            "wont": "won't",
            "isnt": "isn't",
            "arent": "aren't",
            "wasnt": "wasn't",
            "werent": "weren't",
            "hasnt": "hasn't",
            "havent": "haven't",
            "hadnt": "hadn't",
            "shouldnt": "shouldn't",
            "wouldnt": "wouldn't",
            "couldnt": "couldn't",

            # Urgency
            "asap": "immediately",
            "rn": "right now",
            "rtfn": "right now",

            # Common command typos
            "blok": "block",
            "blck": "block",
            "bolck": "block",
            "alow": "allow",
            "alw": "allow",
            "delet": "delete",
            "remov": "remove",
            "stpo": "stop",
            "stp": "stop",

            # Protocol typos
            "shh": "ssh",
            "htpp": "http",
            "htp": "http",
            "httsp": "https",
            "htps": "https",

            # Action typos
            "blcok": "block",
            "bloack": "block",
            "allwo": "allow",
            "alolw": "allow",
        }

        # Urgency keywords (for detection, not replacement)
        self.urgency_keywords = {
            "now",
            "immediately",
            "asap",
            "urgent",
            "emergency",
            "critical",
            "quick",
            "quickly",
            "fast",
            "hurry",
            "attack",
            "attacking",
            "ddos",
            "breach",
            "compromised",
            "hacked",
            "brute force",
            "bruteforce",
        }

    def normalize(self, text: str) -> tuple[str, dict]:
        """
        Normalize typos and casual language.

        Args:
            text: Raw user input

        Returns:
            Tuple of (normalized_text, metadata)
            metadata includes: urgency_detected, all_caps, typos_fixed
        """
        original = text
        normalized = text
        metadata = {
            "urgency_detected": False,
            "all_caps": False,
            "typos_fixed": [],
            "urgency_keywords": [],
        }

        # Detect ALL CAPS (urgency indicator)
        if len(text) > 10 and text.isupper():
            metadata["all_caps"] = True
            metadata["urgency_detected"] = True
            # Convert to normal case for processing
            normalized = text.lower()

        # Fix typos (word-by-word)
        words = normalized.split()
        fixed_words = []
        for word in words:
            # Remove punctuation for matching
            clean_word = word.strip('.,!?;:').lower()
            if clean_word in self.typo_map:
                replacement = self.typo_map[clean_word]
                # Preserve original punctuation
                if word != clean_word:
                    # Has punctuation
                    prefix = word[:len(word) - len(word.lstrip('.,!?;:'))]
                    suffix = word[len(word.rstrip('.,!?;:')):] if word.rstrip('.,!?;:') != word else ''
                    fixed_word = prefix + replacement + suffix
                else:
                    fixed_word = replacement

                fixed_words.append(fixed_word)
                metadata["typos_fixed"].append(f"{word} → {fixed_word}")
            else:
                fixed_words.append(word)

        normalized = " ".join(fixed_words)

        # Detect urgency keywords
        normalized_lower = normalized.lower()
        for keyword in self.urgency_keywords:
            if keyword in normalized_lower:
                metadata["urgency_detected"] = True
                metadata["urgency_keywords"].append(keyword)

        return normalized, metadata

    def is_urgent(self, text: str) -> bool:
        """
        Quick check if text contains urgency indicators.

        Args:
            text: User input

        Returns:
            True if urgent, False otherwise
        """
        text_lower = text.lower()

        # Check ALL CAPS
        if len(text) > 10 and text.isupper():
            return True

        # Check urgency keywords
        for keyword in self.urgency_keywords:
            if keyword in text_lower:
                return True

        return False

    def get_urgency_level(self, text: str) -> str:
        """
        Determine urgency level.

        Args:
            text: User input

        Returns:
            "low", "medium", or "high"
        """
        text_lower = text.lower()

        # High urgency indicators
        high_urgency = ["attack", "attacking", "ddos", "breach", "compromised", "hacked", "emergency", "critical"]
        if any(word in text_lower for word in high_urgency):
            return "high"

        # Medium urgency indicators
        medium_urgency = ["now", "immediately", "asap", "urgent", "quick", "fast", "hurry"]
        if any(word in text_lower for word in medium_urgency):
            return "medium"

        # ALL CAPS
        if len(text) > 10 and text.isupper():
            return "high"

        return "low"


# Global instance
_typo_normalizer: TypoNormalizer | None = None


def get_typo_normalizer() -> TypoNormalizer:
    """Get or create the global typo normalizer."""
    global _typo_normalizer
    if _typo_normalizer is None:
        _typo_normalizer = TypoNormalizer()
    return _typo_normalizer


def normalize_typos(text: str) -> tuple[str, dict]:
    """
    Normalize typos in text.

    Args:
        text: Raw user input

    Returns:
        Tuple of (normalized_text, metadata)
    """
    normalizer = get_typo_normalizer()
    return normalizer.normalize(text)


def is_urgent(text: str) -> bool:
    """Check if text is urgent."""
    normalizer = get_typo_normalizer()
    return normalizer.is_urgent(text)


# Example usage and tests
if __name__ == "__main__":
    test_cases = [
        "plz block that one IP",
        "dont allow port 22 anymore",
        "BLOCK EVERYTHING FROM 1.2.3.4 NOW!!!",
        "Can you maybe alow traffic on 8080?",
        "block 1.2.3.4 asap its attacking us",
        "blok shh from 10.0.0.5",
        "we're under ddos attack block them immediately",
    ]

    normalizer = TypoNormalizer()
    for test in test_cases:
        normalized, metadata = normalizer.normalize(test)
        urgency = normalizer.get_urgency_level(test)

        print(f"Original: {test}")
        print(f"Normalized: {normalized}")
        print(f"Urgency: {urgency}")
        if metadata["typos_fixed"]:
            print(f"Typos fixed: {', '.join(metadata['typos_fixed'])}")
        if metadata["urgency_keywords"]:
            print(f"Urgency keywords: {', '.join(metadata['urgency_keywords'])}")
        print()
