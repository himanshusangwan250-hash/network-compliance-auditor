"""Detects Palo Alto PAN-OS configuration export format."""

import re


def detect_paloalto_format(config_text: str) -> str:
    """
    Detect whether a Palo Alto config is XML/API export,
    curly-brace show running-config style, or set-command style.

    Returns one of: 'xml', 'curly_brace', 'set', 'unknown'
    """
    stripped = config_text.strip()

    # XML: starts with <?xml or <config
    if stripped.startswith('<?xml') or stripped.startswith('<config'):
        return 'xml'

    # Curly-brace style: contains brace-delimited blocks like "Rule Name" { ... }
    # and/or top-level sections like security { ... }
    if re.search(r'^\s*"[^"]+"\s*\{', config_text, re.MULTILINE):
        return 'curly_brace'
    if re.search(r'^\s*\w+\s*\{', config_text, re.MULTILINE):
        return 'curly_brace'

    # Set style: lines beginning with "set "
    if re.search(r'^set\s+\S+', config_text, re.MULTILINE):
        return 'set'

    return 'unknown'


def get_format_confidence(config_text: str) -> dict:
    """
    Return confidence scores for each format.
    Useful for debugging and edge cases.
    """
    scores = {
        'xml': 0,
        'curly_brace': 0,
        'set': 0,
    }

    # XML signals
    if config_text.strip().startswith('<?xml'):
        scores['xml'] += 10
    if '<config' in config_text and '</config>' in config_text:
        scores['xml'] += 5
    if '<deviceconfig>' in config_text:
        scores['xml'] += 3

    # Curly-brace signals
    curly_blocks = re.findall(r'^\s*"[^"]+"\s*\{', config_text, re.MULTILINE)
    scores['curly_brace'] += len(curly_blocks) * 2
    if re.search(r'^\s*\w+\s*\{', config_text, re.MULTILINE):
        scores['curly_brace'] += 1
    if 'action allow' in config_text or 'action deny' in config_text:
        scores['curly_brace'] += 2
    if 'terminal yes' in config_text or 'terminal no' in config_text:
        scores['curly_brace'] += 2

    # Set signals
    set_lines = re.findall(r'^set\s+\S+', config_text, re.MULTILINE)
    scores['set'] += len(set_lines)

    total = sum(scores.values())
    if total == 0:
        return {'format': 'unknown', 'confidence': 0.0, 'scores': scores}

    best = max(scores, key=scores.get)
    confidence = scores[best] / total
    return {
        'format': best,
        'confidence': round(confidence, 2),
        'scores': scores,
    }
