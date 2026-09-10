#!/usr/bin/env python3
"""
Demonstration script for ML compliance model.
Shows cross-vendor generalization and error analysis.
"""

import sys
import json
from pathlib import Path
from setfit import SetFitModel

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))
from model.infer import load_model, predict


def main():
    """Run demonstration cases."""
    print("=" * 80)
    print("ML COMPLIANCE MODEL DEMONSTRATION")
    print("=" * 80)

    # Load model
    model = load_model()

    print("\n" + "=" * 80)
    print("DEMO CASE 1: Same security intent, different vendor syntax")
    print("=" * 80)

    # Case 1: SSH version 2 across vendors
    cases_1 = [
        {
            "policy": "SSH must use secure protocol version 2",
            "config": "ip ssh version 2",
            "vendor": "cisco",
            "expected": "compliant"
        },
        {
            "policy": "SSH must use secure protocol version 2",
            "config": "set system services ssh protocol-version v2",
            "vendor": "juniper",
            "expected": "compliant"
        },
    ]

    for i, case in enumerate(cases_1, 1):
        result = predict(case["policy"], case["config"], case["vendor"], model)
        status = "[OK]" if result["prediction"] == case["expected"] else "[FAIL]"
        print(f"\n{i}. {status} {case['vendor'].upper()}")
        print(f"   Policy: {case['policy']}")
        print(f"   Config: {case['config']}")
        print(f"   Prediction: {result['prediction']} (confidence: {result['confidence']:.4f})")
        print(f"   Expected: {case['expected']}")

    print("\n" + "=" * 80)
    print("DEMO CASE 2: Same vendor, compliant vs non-compliant")
    print("=" * 80)

    cases_2 = [
        {
            "policy": "Password Encryption Required",
            "config": "username admin privilege 15 secret 5 \$1\$admin123\$hash",
            "vendor": "cisco",
            "expected": "compliant"
        },
        {
            "policy": "Password Encryption Required",
            "config": "username admin privilege 15 password 0 admin123",
            "vendor": "cisco",
            "expected": "non_compliant"
        },
    ]

    for i, case in enumerate(cases_2, 1):
        result = predict(case["policy"], case["config"], case["vendor"], model)
        status = "[OK]" if result["prediction"] == case["expected"] else "[FAIL]"
        print(f"\n{i}. {status} {case['vendor'].upper()}")
        print(f"   Policy: {case['policy']}")
        print(f"   Config: {case['config']}")
        print(f"   Prediction: {result['prediction']} (confidence: {result['confidence']:.4f})")
        print(f"   Expected: {case['expected']}")

    print("\n" + "=" * 80)
    print("DEMO CASE 3: Unknown/ambiguous input")
    print("=" * 80)

    cases_3 = [
        {
            "policy": "Avoid Default Credentials",
            "config": "unknown configuration syntax",
            "vendor": "cisco",
            "expected": "uncertain"
        },
    ]

    for i, case in enumerate(cases_3, 1):
        result = predict(case["policy"], case["config"], case["vendor"], model)
        status = "[OK]" if result["prediction"] == case["expected"] else "[FAIL]"
        print(f"\n{i}. {status}")
        print(f"   Policy: {case['policy']}")
        print(f"   Config: {case['config']}")
        print(f"   Prediction: {result['prediction']} (confidence: {result['confidence']:.4f})")
        print(f"   Expected: {case['expected']}")

    print("\n" + "=" * 80)
    print("DEMO CASE 4: Cross-vendor generalization")
    print("=" * 80)

    # Use examples from cross-vendor test sets
    cases_4 = [
        {
            "policy": "Avoid Default Credentials",
            "config": "username guest privilege 1 secret 5 \$1\$guest123\$hash",
            "vendor": "paloalto",
            "note": "Test on Palo Alto (held-out vendor)"
        },
        {
            "policy": "Syslog Configuration Required",
            "config": "set system syslog host 192.0.2.10 any any",
            "vendor": "juniper",
            "note": "Test on Juniper (held-out vendor)"
        },
    ]

    for i, case in enumerate(cases_4, 1):
        result = predict(case["policy"], case["config"], case["vendor"], model)
        print(f"\n{i}. {case['note']}")
        print(f"   Policy: {case['policy']}")
        print(f"   Config: {case['config']}")
        print(f"   Prediction: {result['prediction']} (confidence: {result['confidence']:.4f})")

    print("\n" + "=" * 80)
    print("DEMONSTRATION COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    main()
