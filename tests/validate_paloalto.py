"""Validate Palo Alto parser against sample config."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from parser.paloalto_panos import parse_paloalto_panos


def validate_sample1():
    """Test against the full Palo Alto sample."""
    
    with open('sample_configs/paloalto_panos_sample.txt') as f:
        config = f.read()
    
    result = parse_paloalto_panos(config)
    
    checks = [
        # System info
        (['hostname'], 'TEST-PAFW-01', 'hostname extracted'),
        (['domain'], 'example.com', 'domain extracted'),
        (['ip_address'], '192.168.1.1', 'IP address extracted'),
        (['netmask'], '255.255.255.0', 'netmask extracted'),
        (['default_gateway'], '192.168.1.254', 'gateway extracted'),
        (['dns_servers', 0], '8.8.8.8', 'DNS primary'),
        (['dns_servers', 1], '8.8.4.4', 'DNS secondary'),
        (['ntp_servers', 'primary'], '192.168.1.10', 'NTP primary'),
        (['ntp_servers', 'secondary'], '192.168.1.11', 'NTP secondary'),
        
        # Interfaces
        (['interfaces', 0, 'name'], 'ethernet1/1', 'interface ethernet1/1 name'),
        (['interfaces', 0, 'ip'], '192.168.1.1/24', 'interface ethernet1/1 IP'),
        (['interfaces', 1, 'name'], 'ethernet1/2', 'interface ethernet1/2 name'),
        (['interfaces', 1, 'ip'], '203.0.113.1/30', 'interface ethernet1/2 IP'),
        
        # Addresses
        (['addresses', 0, 'name'], 'internal-net', 'address internal-net'),
        (['addresses', 0, 'cidr'], '192.168.1.0/24', 'address internal-net CIDR'),
        (['addresses', 1, 'name'], 'dmz-net', 'address dmz-net'),
        (['addresses', 1, 'cidr'], '10.0.0.0/24', 'address dmz-net CIDR'),
        
        # Services
        (['services', 0, 'name'], 'tcp-8080', 'service tcp-8080'),
        (['services', 0, 'port'], '8080', 'service port'),
        
        # Security rules
        (['security_rules', 0, 'name'], 'allow-internal-outbound', 'rule name'),
        (['security_rules', 0, 'action'], 'allow', 'rule action allow'),
        (['security_rules', 1, 'action'], 'deny', 'rule action deny'),
        
        # Zones
        (['zones', 0, 'name'], 'trust', 'zone trust'),
        (['zones', 1, 'name'], 'untrust', 'zone untrust'),
        (['zones', 2, 'name'], 'dmz', 'zone dmz'),
        
        # SNMP
        (['snmp_communities', 0, 'name'], 'public', 'SNMP community public'),
        (['snmp_communities', 1, 'name'], 'private', 'SNMP community private'),
    ]
    
    passed = 0
    failed = 0
    
    print("\n=== Palo Alto Sample 1 ===")
    
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
    success = validate_sample1()
    sys.exit(0 if success else 1)
