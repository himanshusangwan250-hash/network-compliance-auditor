"""Validate Juniper parser against multiple samples."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from parser.juniper_junos import parse_juniper_junos


def run_checks(sample_name, config_path, checks):
    """Run a set of (path, expected, desc) checks against a config."""
    
    with open(config_path) as f:
        config = f.read()
    
    result = parse_juniper_junos(config)
    
    passed = 0
    failed = 0
    
    print(f"\n=== {sample_name} ===")
    
    for path, expected, desc in checks:
        actual = result
        for key in path:
            if isinstance(key, int):
                if len(actual) > key:
                    actual = actual[key]
                else:
                    actual = None
                    break
            else:
                actual = actual.get(key) if isinstance(actual, dict) else None
        
        if actual == expected:
            print(f"  PASS: {desc}")
            passed += 1
        else:
            print(f"  FAIL: {desc}")
            print(f"        Expected: {expected}")
            print(f"        Actual:   {actual}")
            failed += 1
    
    print(f"\n  Results: {passed} passed, {failed} failed")
    return failed == 0


def validate_sample1():
    """Sample 1 has full config: SSH deny, telnet, HTTP mgmt, NTP, users, zones."""
    
    checks = [
        (['hostname'], 'TEST-SRX-01', 'hostname extracted'),
        (['services', 'ssh_root_login'], 'deny', 'SSH root login deny'),
        (['services', 'ssh_protocol'], 'v2', 'SSH protocol v2'),
        (['services', 'telnet'], True, 'telnet block detected'),
        (['services', 'http_management'], True, 'HTTP management detected'),
        (['users', 0, 'name'], 'admin', 'user admin extracted'),
        (['users', 0, 'class'], 'superuser', 'user class superuser'),
        (['interfaces', 0, 'address'], '203.0.113.1/30', 'interface 0 address'),
        (['interfaces', 1, 'address'], '192.168.1.1/24', 'interface 1 address'),
        (['ntp', 0], '192.168.1.10', 'NTP server 1'),
        (['ntp', 1], '192.168.1.11', 'NTP server 2'),
        (['security', 'zones', 0, 'name'], 'trust', 'zone trust'),
        (['security', 'zones', 1, 'name'], 'untrust', 'zone untrust'),
    ]
    
    return run_checks("Sample 1 (full config)", "sample_configs/juniper_junos_sample.txt", checks)


def validate_sample2():
    """Sample 2 is sparser: no telnet, no HTTP mgmt, no NTP, no SSH settings block.
    Missing fields must return sensible defaults (None/False/empty list)."""
    
    checks = [
        # Fields present in sample 2
        (['hostname'], None, 'hostname defaults to None when host-name statement absent'),
        (['interfaces', 0, 'address'], '10.50.0.1/29', 'interface ge-1/0/0 address'),
        (['interfaces', 1, 'address'], '172.16.0.1/32', 'interface lo0 address'),
        
        # Fields present but must extract correctly
        (['services', 'ssh_root_login'], 'allow', 'SSH root login defaults to allow when block absent'),
        (['services', 'telnet'], False, 'telnet correctly absent (False, not True)'),
        (['services', 'http_management'], False, 'HTTP management correctly absent'),
        
        # Fields that should be empty lists/None when config lacks them
        (['ntp'], [], 'NTP list empty when no NTP block'),
        (['users'], [], 'Users list empty when no user block'),
        (['security', 'zones'], [], 'Zones list empty when no zones block'),
        
        # Static route extraction (sample 2 has one static route)
        (['routes', 0, 'prefix'], '0.0.0.0/0', 'static route prefix extracted'),
        (['routes', 0, 'next_hop'], '10.50.0.6', 'static route next-hop extracted'),
    ]
    
    return run_checks("Sample 2 (sparse config - tests defaults)", "sample_configs/juniper_junos_sample2.txt", checks)


if __name__ == "__main__":
    s1_ok = validate_sample1()
    s2_ok = validate_sample2()
    
    if s1_ok and s2_ok:
        print("\nAll validation checks passed.")
        sys.exit(0)
    else:
        print("\nSome validation checks failed.")
        sys.exit(1)
