"""Validate Cisco parser against sample config."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from parser.cisco_ios import parse_cisco_ios


def validate_sample():
    """Test against the Cisco sample config."""
    
    with open('sample_configs/cisco_ios_sample.txt') as f:
        config = f.read()
    
    result = parse_cisco_ios(config)
    
    checks = [
        # System info
        (['hostname'], 'TEST-RTR-01', 'hostname extracted'),
        (['version'], '15.7', 'version extracted'),
        
        # Interfaces
        (['interfaces', 0, 'name'], 'GigabitEthernet0/0', 'interface 0 name'),
        (['interfaces', 0, 'ip'], '203.0.113.1', 'interface 0 IP'),
        (['interfaces', 0, 'mask'], '255.255.255.252', 'interface 0 mask'),
        (['interfaces', 0, 'shutdown'], False, 'interface 0 no shutdown'),
        (['interfaces', 1, 'name'], 'GigabitEthernet0/1', 'interface 1 name'),
        (['interfaces', 1, 'ip'], '192.168.1.1', 'interface 1 IP'),
        
        # Users
        (['users', 0, 'name'], 'admin', 'user admin extracted'),
        (['users', 0, 'privilege'], 15, 'user admin privilege 15'),
        (['users', 0, 'encrypted'], True, 'user admin secret encrypted'),
        (['users', 1, 'name'], 'netadmin', 'user netadmin extracted'),
        (['users', 1, 'encrypted'], False, 'user netadmin password plain'),
        
        # NTP
        (['ntp', 0], '192.168.1.10', 'NTP server 1'),
        (['ntp', 1], '192.168.1.11', 'NTP server 2'),
        
        # Logging
        (['logging', 0, 'host'], '192.168.1.50', 'logging host extracted'),
        
        # SNMP
        (['snmp', 0, 'community'], 'public', 'SNMP community public'),
        (['snmp', 0, 'permission'], 'RO', 'SNMP community permission RO'),
        (['snmp', 1, 'community'], 'private', 'SNMP community private'),
        (['snmp', 1, 'permission'], 'RW', 'SNMP community permission RW'),
    ]
    
    passed = 0
    failed = 0
    
    print("\n=== Cisco Sample ===")
    
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


if __name__ == "__main__":
    success = validate_sample()
    sys.exit(0 if success else 1)
