"""Detects network device vendor from raw config text."""

import re
from typing import Optional


def detect_vendor(config_text: str) -> dict:
    """
    Detect vendor from configuration text using fingerprint patterns.
    
    Returns dict with vendor name, confidence score, and matched patterns.
    """
    patterns = {
        "cisco_ios": [
            r"^!\s*$",  # Cisco uses ! for comments
            r"^version \d+\.\d+",
            r"^hostname \S+",
            r"^interface (GigabitEthernet|FastEthernet|Ethernet|Loopback)\S*",
            r"^router (ospf|bgp|eigrp|rip) \d+",
            r"^line (con|vty|aux) \d+",
            r"transport input (telnet|ssh)",
            r"^enable secret \d+",
            r"^service \S+",
        ],
        "juniper_junos": [
            r"^#\s*$",  # Juniper uses # for comments
            r"^set \S+",
            r"^interfaces \{",
            r"^\s+interface \S+ \{",
            r"^system \{",
            r"^routing-options \{",
            r"^security \{",
            r"^\s+host-name \S+;",
            r"^\s+address \d+\.\d+\.\d+\.\d+/\d+;",
        ],
        "paloalto_panos": [
            r"<entry name=",
            r"<config",
            r"<deviceconfig>",
            r"<hostname>",
            r"<ip-address>\d+\.\d+\.\d+\.\d+</ip-address>",
            r"<netmask>/\d+</netmask>",
            r"<vsys>",
            r"<security>",
            r"^\s*\"[^\"]+\"\s*\{",
        ],
    }
    
    scores = {}
    matches = {}
    
    for vendor, regexes in patterns.items():
        score = 0
        matched = []
        for pattern in regexes:
            matches_found = re.findall(pattern, config_text, re.MULTILINE)
            if matches_found:
                score += len(matches_found)
                matched.append((pattern, len(matches_found)))
        scores[vendor] = score
        matches[vendor] = matched
    
    if not any(scores.values()):
        return {
            "vendor": "unknown",
            "confidence": 0.0,
            "scores": scores,
            "recommendation": "manual_review_required"
        }
    
    best_vendor = max(scores, key=scores.get)
    total_matches = sum(scores.values())
    confidence = scores[best_vendor] / total_matches if total_matches > 0 else 0
    
    return {
        "vendor": best_vendor,
        "confidence": round(confidence, 2),
        "scores": scores,
        "matched_patterns": matches[best_vendor][:3],
    }


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python3 vendor_detector.py <config_file>")
        sys.exit(1)
    
    with open(sys.argv[1]) as f:
        config_text = f.read()
    
    result = detect_vendor(config_text)
    print(f"Detected vendor: {result['vendor']}")
    print(f"Confidence: {result['confidence']}")
    print(f"Scores: {result['scores']}")
