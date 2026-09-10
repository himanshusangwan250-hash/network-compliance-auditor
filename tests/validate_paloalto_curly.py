"""Validate Palo Alto curly‑brace parser against a real security‑policy fragment."""

import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from parser.paloalto_curly import parse_paloalto_curly


def main():
    with open('sample_configs/paloalto_curly_real.txt') as f:
        cfg = f.read()
    result = parse_paloalto_curly(cfg)

    rule = result.get('security_rules', [])[0] if result.get('security_rules') else None
    checks = [
        (rule.get('name') if rule else None, 'Outside Web Server', 'rule name'),
        (rule.get('from')[0] if rule and rule.get('from') else None, 'Trust', 'from zone'),
        (rule.get('to')[0] if rule and rule.get('to') else None, 'Untrust', 'to zone'),
        (rule.get('source')[0] if rule and rule.get('source') else None, '10.1.1.0/24', 'source'),
        (rule.get('destination')[0] if rule and rule.get('destination') else None, '200.10.10.10', 'destination'),
        (rule.get('action') if rule else None, 'allow', 'action'),
    ]

    passed = 0
    for actual, expected, desc in checks:
        if actual == expected:
            print(f"PASS {desc}")
            passed += 1
        else:
            print(f"FAIL {desc}: expected {expected}, got {actual}")
    print(f"\n{passed}/{len(checks)} checks passed")
    sys.exit(0 if passed == len(checks) else 1)

if __name__ == '__main__':
    main()
