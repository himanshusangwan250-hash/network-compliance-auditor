"""Palo Alto PAN-OS curly-brace configuration parser (show running-config style)."""

import re
import json
from typing import Dict, Any, List, Union


def _tokenize(text: str) -> List[str]:
    """Tokenize curly-brace config into meaningful tokens."""
    tokens = []
    i = 0
    length = len(text)

    while i < length:
        if text[i].isspace():
            i += 1
            continue

        if text[i] == '#':
            while i < length and text[i] != '\n':
                i += 1
            continue

        if text[i] == '"':
            j = i + 1
            while j < length and text[j] != '"':
                j += 1
            tokens.append(text[i:j + 1])
            i = j + 1
            continue

        if text[i] == '[':
            tokens.append('[')
            i += 1
            continue
        if text[i] == ']':
            tokens.append(']')
            i += 1
            continue
        if text[i] == '{':
            tokens.append('{')
            i += 1
            continue
        if text[i] == '}':
            tokens.append('}')
            i += 1
            continue
        if text[i] == ';':
            tokens.append(';')
            i += 1
            continue

        if text[i].isalnum() or text[i] in '-_./':
            j = i
            while j < length and (text[j].isalnum() or text[j] in '-_./'):
                j += 1
            tokens.append(text[i:j])
            i = j
            continue

        i += 1

    return tokens


def _parse_value(tokens: List[str], pos: int) -> tuple[Any, int]:
    """Parse a value from tokens. Returns (value, new_pos)."""
    if pos >= len(tokens):
        return None, pos

    token = tokens[pos]

    if token == '[':
        pos += 1
        items = []
        while pos < len(tokens) and tokens[pos] != ']':
            if tokens[pos] == ';':
                pos += 1
                continue
            val, pos = _parse_value(tokens, pos)
            if val is not None:
                items.append(val)
        if pos < len(tokens) and tokens[pos] == ']':
            pos += 1
        return items, pos

    if token.startswith('"'):
        return token[1:-1], pos + 1

    if token.isdigit():
        return int(token), pos + 1

    if token.lower() in ('yes', 'true', 'on'):
        return True, pos + 1
    if token.lower() in ('no', 'false', 'off'):
        return False, pos + 1

    return token, pos + 1


def _parse_block(tokens: List[str], pos: int) -> tuple[Dict[str, Any], int]:
    """Parse a block starting at current position. Returns (block_dict, new_pos)."""
    block: Dict[str, Any] = {}
    current_key = None

    while pos < len(tokens):
        token = tokens[pos]

        if token == '}':
            return block, pos + 1

        if token == ';':
            pos += 1
            current_key = None
            continue

        if token == '{':
            if current_key is not None:
                nested, pos = _parse_block(tokens, pos + 1)
                if current_key in block:
                    existing = block[current_key]
                    if isinstance(existing, list):
                        existing.append(nested)
                    else:
                        block[current_key] = [existing, nested]
                else:
                    block[current_key] = nested
                current_key = None
            pos += 1
            continue

        if token == '[':
            if current_key is not None:
                val, pos = _parse_value(tokens, pos)
                block[current_key] = val
                current_key = None
            pos += 1
            continue

        if token.startswith('"'):
            if current_key is None:
                current_key = token[1:-1]
            else:
                current_key = token[1:-1]
            pos += 1
            continue

        # Plain word token
        if current_key is None:
            if pos + 2 < len(tokens) and tokens[pos + 1] != '{' and tokens[pos + 1] != ';' and tokens[pos + 2] == '{':
                current_key = f"{token} {tokens[pos + 1]}"
                pos += 2
            else:
                current_key = token
                pos += 1
        else:
            if pos + 1 < len(tokens) and tokens[pos + 1] == '{':
                current_key = f"{current_key} {token}"
                pos += 1
            else:
                val, pos = _parse_value(tokens, pos)
                block[current_key] = val
                current_key = None
                continue

    return block, pos


def _ensure_list(value: Any) -> List[Any]:
    """Ensure a value is a list."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _extract_system(deviceconfig: Dict[str, Any], result: Dict[str, Any]) -> None:
    """Extract system information from deviceconfig block."""
    if not isinstance(deviceconfig, dict):
        return

    system = deviceconfig.get('system')
    if not isinstance(system, dict):
        return

    result['hostname'] = system.get('hostname')
    result['domain'] = system.get('domain')
    result['ip_address'] = system.get('ip-address')
    result['netmask'] = system.get('netmask')
    result['default_gateway'] = system.get('default-gateway')

    dns = system.get('dns-setting')
    if isinstance(dns, dict):
        servers = dns.get('servers')
        if isinstance(servers, list):
            result['dns_servers'] = servers

    # Also handle primary/secondary ntp if present in system
    primary = system.get('primary')
    secondary = system.get('secondary')
    ntp = system.get('ntp-servers')
    if isinstance(ntp, dict):
        primary = ntp.get('primary') or primary
        secondary = ntp.get('secondary') or secondary

    if primary:
        result['ntp_servers']['primary'] = primary
    if secondary:
        result['ntp_servers']['secondary'] = secondary


def _extract_interfaces(network: Dict[str, Any], result: Dict[str, Any]) -> None:
    """Extract interfaces from network block."""
    if not isinstance(network, dict):
        return

    interface = network.get('interface')
    if not isinstance(interface, dict):
        return

    for name, data in interface.items():
        if not isinstance(data, dict):
            continue

        for eth_key, eth_val in data.items():
            if isinstance(eth_val, dict):
                result['interfaces'].append({
                    'name': eth_val.get('name', eth_key),
                    'ip': eth_val.get('ip'),
                    'zone': eth_val.get('zone'),
                })
            elif eth_key == 'ip':
                result['interfaces'].append({
                    'name': name,
                    'ip': eth_val,
                    'zone': data.get('zone'),
                })


def _extract_zones(vsys: Dict[str, Any], result: Dict[str, Any]) -> None:
    """Extract zones from vsys block."""
    if not isinstance(vsys, dict):
        return

    for vsys_name, vsys_data in vsys.items():
        if not isinstance(vsys_data, dict):
            continue

        zone = vsys_data.get('zone')
        if not isinstance(zone, dict):
            continue

        for zone_name, zone_data in zone.items():
            if not isinstance(zone_data, dict):
                continue

            net = zone_data.get('network')
            if isinstance(net, list):
                result['zones'].append({
                    'name': zone_name,
                    'interfaces': net,
                })
            elif isinstance(net, str):
                result['zones'].append({
                    'name': zone_name,
                    'interfaces': [net],
                })


def _extract_addresses(vsys: Dict[str, Any], result: Dict[str, Any]) -> None:
    """Extract addresses from vsys block."""
    if not isinstance(vsys, dict):
        return

    for vsys_name, vsys_data in vsys.items():
        if not isinstance(vsys_data, dict):
            continue

        address = vsys_data.get('address')
        if not isinstance(address, dict):
            continue

        for addr_name, addr_data in address.items():
            if not isinstance(addr_data, dict):
                continue

            result['addresses'].append({
                'name': addr_name,
                'cidr': addr_data.get('ip-netmask') or addr_data.get('ip-range'),
            })

    # Also check top-level address
    top_addr = vsys.get('address')
    if isinstance(top_addr, dict):
        for addr_name, addr_data in top_addr.items():
            if isinstance(addr_data, dict):
                result['addresses'].append({
                    'name': addr_name,
                    'cidr': addr_data.get('ip-netmask') or addr_data.get('ip-range'),
                })


def _extract_services(vsys: Dict[str, Any], result: Dict[str, Any]) -> None:
    """Extract services from vsys block."""
    if not isinstance(vsys, dict):
        return

    for vsys_name, vsys_data in vsys.items():
        if not isinstance(vsys_data, dict):
            continue

        service = vsys_data.get('service')
        if not isinstance(service, dict):
            continue

        for svc_name, svc_data in service.items():
            if not isinstance(svc_data, dict):
                continue

            result['services'].append({
                'name': svc_name,
                'protocol': svc_data.get('protocol'),
                'port': svc_data.get('port'),
            })

    # Also check top-level service
    top_svc = vsys.get('service')
    if isinstance(top_svc, dict):
        for svc_name, svc_data in top_svc.items():
            if isinstance(svc_data, dict):
                result['services'].append({
                    'name': svc_name,
                    'protocol': svc_data.get('protocol'),
                    'port': svc_data.get('port'),
                })


def _extract_security_rules(vsys: Dict[str, Any], result: Dict[str, Any]) -> None:
    """Extract security rules from vsys block."""
    if not isinstance(vsys, dict):
        return

    for vsys_name, vsys_data in vsys.items():
        if not isinstance(vsys_data, dict):
            continue

        security = vsys_data.get('security')
        if not isinstance(security, dict):
            continue

        rules = security.get('rules')
        if not isinstance(rules, dict):
            continue

        for rule_name, rule_data in rules.items():
            if not isinstance(rule_data, dict):
                continue

            result['security_rules'].append({
                'name': rule_name,
                'from': _ensure_list(rule_data.get('from')),
                'to': _ensure_list(rule_data.get('to')),
                'source': _ensure_list(rule_data.get('source')),
                'destination': _ensure_list(rule_data.get('destination')),
                'service': _ensure_list(rule_data.get('service')),
                'action': rule_data.get('action'),
                'application': rule_data.get('application/service'),
            })


def _extract_snmp(raw: Dict[str, Any], result: Dict[str, Any]) -> None:
    """Extract SNMP communities from raw parsed blocks."""
    snmp = raw.get('snmp')
    if not isinstance(snmp, dict):
        return

    community = snmp.get('community')
    if not isinstance(community, dict):
        return

    for comm_name, comm_data in community.items():
        if not isinstance(comm_data, dict):
            continue

        result['snmp_communities'].append({
            'name': comm_name,
            'version': comm_data.get('version'),
        })


def parse_paloalto_curly(config_text: str) -> Dict[str, Any]:
    """
    Parse Palo Alto curly-brace configuration format.

    Returns normalized dict similar to XML parser output.
    """
    tokens = _tokenize(config_text)
    raw, _ = _parse_block(tokens, 0)

    result = {
        "vendor": "paloalto_panos",
        "format": "curly_brace",
        "hostname": None,
        "domain": None,
        "ip_address": None,
        "netmask": None,
        "default_gateway": None,
        "dns_servers": [],
        "ntp_servers": {"primary": None, "secondary": None},
        "interfaces": [],
        "addresses": [],
        "services": [],
        "security_rules": [],
        "zones": [],
        "snmp_communities": [],
        "raw_blocks": raw,
    }

    # Extract deviceconfig
    deviceconfig = raw.get('deviceconfig')
    if isinstance(deviceconfig, dict):
        _extract_system(deviceconfig, result)

    # Extract network/interfaces
    network = raw.get('network')
    if isinstance(network, dict):
        _extract_interfaces(network, result)

    # Extract vsys content
    vsys = raw.get('vsys')
    if isinstance(vsys, dict):
        _extract_zones(vsys, result)
        _extract_addresses(vsys, result)
        _extract_services(vsys, result)
        _extract_security_rules(vsys, result)
    # Also extract any top‑level rule‑like blocks (e.g., a rule defined without vsys wrapper)
    for top_key, top_val in raw.items():
        if (isinstance(top_val, dict) and top_val.get('action') and (top_val.get('from') or top_val.get('to') or top_val.get('source') or top_val.get('destination'))):
            result['security_rules'].append({
                'name': top_key,
                'from': _ensure_list(top_val.get('from')),
                'to': _ensure_list(top_val.get('to')),
                'source': _ensure_list(top_val.get('source')),
                'destination': _ensure_list(top_val.get('destination')),
                'service': _ensure_list(top_val.get('service')),
                'action': top_val.get('action'),
                'application': top_val.get('application/service'),
            })

    # Extract SNMP
    _extract_snmp(raw, result)

    return result


if __name__ == '__main__':
    import sys

    if len(sys.argv) != 2:
        print("Usage: python3 paloalto_curly.py <config_file>")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        config_text = f.read()

    parsed = parse_paloalto_curly(config_text)
    print(json.dumps(parsed, indent=2))
