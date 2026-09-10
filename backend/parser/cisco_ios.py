"""Cisco IOS configuration parser using pyparsing."""

from pyparsing import (
    Suppress, Word, alphas, alphanums, nums, 
    Regex, Optional, Group, SkipTo, lineStart, lineEnd
)
import json
from typing import Dict, Any


def parse_cisco_ios(config_text: str) -> Dict[str, Any]:
    """
    Parse Cisco IOS configuration into structured JSON.
    
    Returns dict with sections: hostname, interfaces, users, services, etc.
    """
    result = {
        "hostname": None,
        "version": None,
        "services": {},
        "interfaces": [],
        "users": [],
        "lines": [],
        "logging": [],
        "ntp": [],
        "snmp": [],
        "banners": {},
        "aaa": {},
    }
    
    lines = config_text.split('\n')
    current_section = None
    
    for line in lines:
        line = line.rstrip()
        if not line or line.startswith('!'):
            continue
        
        # Version
        if line.startswith('version '):
            result["version"] = line.split()[1]
            continue
        
        # Hostname
        if line.startswith('hostname '):
            result["hostname"] = line.split(maxsplit=1)[1]
            continue
        
        # Service commands
        if line.startswith('service '):
            parts = line.split()
            if len(parts) >= 2:
                result["services"][parts[1]] = True
            continue
        
        # Interface block
        if line.startswith('interface '):
            current_section = "interface"
            result["interfaces"].append({
                "name": line.split(maxsplit=1)[1],
                "ip": None,
                "mask": None,
                "shutdown": True,
            })
            continue
        
        # Interface sub-commands
        if current_section == "interface" and line.startswith(' ') and result["interfaces"]:
            if line.strip().startswith('ip address '):
                parts = line.strip().split()
                if len(parts) >= 4:
                    result["interfaces"][-1]["ip"] = parts[2]
                    result["interfaces"][-1]["mask"] = parts[3]
            elif line.strip() == 'no shutdown':
                result["interfaces"][-1]["shutdown"] = False
            continue
        
        # User accounts
        if line.startswith('username '):
            parts = line.split()
            user = {"name": parts[1] if len(parts) > 1 else None}
            if 'privilege' in parts:
                idx = parts.index('privilege')
                user["privilege"] = int(parts[idx + 1]) if idx + 1 < len(parts) else 0
            if 'secret' in parts:
                user["encrypted"] = True
            elif 'password' in parts:
                user["encrypted"] = False
            result["users"].append(user)
            continue
        
        # Line vty/con
        if line.startswith('line '):
            current_section = "line"
            result["lines"].append({
                "type": parts[1] if (parts := line.split()) and len(parts) > 1 else None,
                "range": " ".join(parts[2:]) if len(parts) > 2 else None,
                "transport_input": None,
                "exec_timeout": None,
            })
            continue
        
        # NTP
        if line.startswith('ntp server '):
            result["ntp"].append(line.split()[2])
            continue
        
        # Logging
        if line.startswith('logging host '):
            result["logging"].append({"host": line.split()[2]})
            continue
        
        # SNMP
        if line.startswith('snmp-server community '):
            parts = line.split()
            if len(parts) >= 4:
                result["snmp"].append({
                    "community": parts[2],
                    "permission": parts[3],
                })
            continue
        
        # Banner
        if line.startswith('banner '):
            parts = line.split(' ', 2)
            if len(parts) >= 3:
                result["banners"][parts[1]] = parts[2]
            continue # Reset section on unindented top-level command
        if not line.startswith(' ') and not line.startswith('!'):
            current_section = None
    
    return result


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python3 cisco_ios.py <config_file>")
        sys.exit(1)
    
    with open(sys.argv[1]) as f:
        config_text = f.read()
    
    parsed = parse_cisco_ios(config_text)
    print(json.dumps(parsed, indent=2))
