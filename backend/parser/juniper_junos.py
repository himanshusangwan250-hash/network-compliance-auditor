"""Juniper Junos configuration parser using pyparsing."""

import re
import json
from typing import Dict, Any


def parse_juniper_junos(config_text: str) -> Dict[str, Any]:
    """
    Parse Juniper Junos configuration (hierarchical brace syntax) into JSON.
    
    Returns dict with sections: hostname, interfaces, users, services, etc.
    """
    result = {
        "vendor": "juniper_junos",
        "hostname": None,
        "domain": None,
        "users": [],
        "services": {
            "ssh_root_login": "allow",
            "ssh_protocol": "v1",
            "telnet": False,
            "http_management": False,
        },
        "interfaces": [],
        "ntp": [],
        "syslog": [],
        "snmp": {"communities": []},
        "security": {"zones": []},
        "routes": [],
    }
    
    lines = config_text.split('\n')
    
    # Hostname and domain
    for line in lines:
        stripped = line.strip()
        
        if 'host-name' in stripped and ';' in stripped:
            match = re.search(r'host-name\s+(\S+);', stripped)
            if match:
                result["hostname"] = match.group(1)
        
        if 'domain-name' in stripped and ';' in stripped:
            match = re.search(r'domain-name\s+(\S+);', stripped)
            if match:
                result["domain"] = match.group(1)
    
    # SSH root login
    if 'root-login deny' in config_text:
        result["services"]["ssh_root_login"] = "deny"
    
    # SSH protocol
    if 'protocol-version v2' in config_text:
        result["services"]["ssh_protocol"] = "v2"
    
    # Telnet
    if re.search(r'telnet\s*\{', config_text):
        result["services"]["telnet"] = True
    
    # HTTP management
    if re.search(r'web-management\s*\{[^}]*http;', config_text, re.DOTALL):
        result["services"]["http_management"] = True
    
    # Users
    user_blocks = re.findall(
        r'user\s+(\S+)\s*\{[^}]*uid\s+(\d+);[^}]*class\s+(\S+);[^}]*encrypted-password\s+"([^"]+)";',
        config_text, re.DOTALL
    )
    for username, uid, class_name, password in user_blocks:
        result["users"].append({
            "name": username,
            "uid": int(uid),
            "class": class_name,
            "encrypted": True,
        })
    
    # Interfaces
    interface_blocks = re.findall(
        r'(ge|xe|et|ae|lo)-\S+\s*\{[^}]*unit\s+(\d+)\s*\{[^}]*address\s+(\S+);',
        config_text, re.DOTALL
    )
    for intf_match in re.finditer(
        r'(\S+)\s*\{\s*(?:description\s+"([^"]+)";\s*)?unit\s+(\d+)\s*\{[^}]*address\s+(\S+);',
        config_text, re.DOTALL
    ):
        result["interfaces"].append({
            "name": intf_match.group(1),
            "description": intf_match.group(2),
            "unit": intf_match.group(3),
            "address": intf_match.group(4),
        })
    
    # NTP
    for match in re.finditer(r'server\s+(\d+\.\d+\.\d+\.\d+);', config_text):
        result["ntp"].append(match.group(1))
    
    # Syslog
    syslog_hosts = re.findall(
        r'host\s+(\d+\.\d+\.\d+\.\d+)\s*\{[^}]*any\s+any;',
        config_text, re.DOTALL
    )
    for host in syslog_hosts:
        result["syslog"].append({"host": host, "level": "any"})
    
    # SNMP communities
    snmp_comms = re.findall(
        r'community\s+(\S+)\s*\{\s*authorization\s+(read-only|read-write);',
        config_text
    )
    for comm, perm in snmp_comms:
        result["snmp"]["communities"].append({
            "name": comm,
            "permission": perm,
        })
    
    # Security zones
    zone_blocks = re.findall(
        r'security-zone\s+(\S+)\s*\{[^}]*interfaces\s*\{([^}]*)\}',
        config_text, re.DOTALL
    )
    for zone_name, interfaces in zone_blocks:
        result["security"]["zones"].append({
            "name": zone_name,
            "interfaces": [i.strip() for i in interfaces.split(';') if i.strip()],
        })
    
    # Static routes
    route_matches = re.findall(
        r'route\s+(\S+)\s+next-hop\s+(\S+);',
        config_text
    )
    for prefix, next_hop in route_matches:
        result["routes"].append({
            "prefix": prefix,
            "next_hop": next_hop,
        })
    
    return result


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python3 juniper_junos.py <config_file>")
        sys.exit(1)
    
    with open(sys.argv[1]) as f:
        config_text = f.read()
    
    parsed = parse_juniper_junos(config_text)
    print(json.dumps(parsed, indent=2))
