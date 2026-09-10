"""Palo Alto PAN-OS unified parser supporting XML, curly-brace, and set formats."""

import xml.etree.ElementTree as ET
import json
import re
from typing import Dict, Any, List

from .paloalto_format_detector import detect_paloalto_format
from .paloalto_curly import parse_paloalto_curly


def parse_paloalto_panos(config_text: str) -> Dict[str, Any]:
    """
    Parse Palo Alto PAN-OS configuration into structured JSON.
    Auto-detects format: XML, curly-brace, or set commands.

    Returns normalized dict with sections: hostname, interfaces, addresses,
    security rules, zones, etc.
    """
    fmt = detect_paloalto_format(config_text)

    if fmt == 'xml':
        return _parse_xml(config_text)
    elif fmt == 'curly_brace':
        return parse_paloalto_curly(config_text)
    elif fmt == 'set':
        return _parse_set(config_text)
    else:
        return {
            "vendor": "paloalto_panos",
            "format": "unknown",
            "error": "Unable to detect configuration format",
            "hostname": None,
            "security_rules": [],
            "zones": [],
            "interfaces": [],
            "addresses": [],
            "services": [],
        }


def _parse_xml(config_text: str) -> Dict[str, Any]:
    """Parse XML/API export format."""
    result = {
        "vendor": "paloalto_panos",
        "format": "xml",
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
        "users": [],
        "logging_hosts": [],
    }

    if config_text.startswith('<?xml'):
        config_text = re.sub(r'<\?xml[^?]*\?>', '', config_text, count=1).strip()

    try:
        root = ET.fromstring(config_text)
    except ET.ParseError:
        return _parse_xml_fallback(config_text, result)

    # Device config / system
    deviceconfig = root.find('.//deviceconfig')
    if deviceconfig is not None:
        system = deviceconfig.find('.//system')
        if system is not None:
            hostname = system.find('hostname')
            if hostname is not None:
                result["hostname"] = hostname.text

            domain = system.find('domain')
            if domain is not None:
                result["domain"] = domain.text

            ip = system.find('ip-address')
            if ip is not None:
                result["ip_address"] = ip.text

            mask = system.find('netmask')
            if mask is not None:
                result["netmask"] = mask.text

            gw = system.find('default-gateway')
            if gw is not None:
                result["default_gateway"] = gw.text

            dns_setting = system.find('.//dns-setting/servers')
            if dns_setting is not None:
                result["dns_servers"] = [m.text for m in dns_setting.findall('member') if m.text]

            ntp = system.find('.//ntp-servers')
            if ntp is not None:
                primary = ntp.find('primary')
                if primary is not None:
                    result["ntp_servers"]["primary"] = primary.text
                secondary = ntp.find('secondary')
                if secondary is not None:
                    result["ntp_servers"]["secondary"] = secondary.text

    # Interfaces
    for eth_entry in root.findall('.//network/interface/ethernet/entry'):
        name = eth_entry.get('name')
        ip_entry = eth_entry.find('.//ip/entry')
        ip_addr = ip_entry.find('ip').text if ip_entry is not None and ip_entry.find('ip') is not None else None

        result["interfaces"].append({
            "name": name,
            "ip": ip_addr,
        })

    # Addresses
    for addr_entry in root.findall('.//vsys/entry/address/entry'):
        name = addr_entry.get('name')
        ip_netmask = addr_entry.find('ip-netmask')
        ip_value = ip_netmask.text if ip_netmask is not None else None

        result["addresses"].append({
            "name": name,
            "cidr": ip_value,
        })

    # Services
    for svc_entry in root.findall('.//vsys/entry/service/entry'):
        name = svc_entry.get('name')
        proto = svc_entry.find('protocol')
        port = svc_entry.find('port')

        result["services"].append({
            "name": name,
            "protocol": proto.text if proto is not None else None,
            "port": port.text if port is not None else None,
        })

    # Security rules
    for rule in root.findall('.//vsys/entry/security/rules/entry'):
        name = rule.get('name')

        def get_members(parent_tag):
            parent = rule.find(parent_tag)
            if parent is not None:
                return [m.text for m in parent.findall('member') if m.text]
            return []

        action = rule.find('action')

        result["security_rules"].append({
            "name": name,
            "from": get_members('from'),
            "to": get_members('to'),
            "source": get_members('source'),
            "destination": get_members('destination'),
            "service": get_members('service'),
            "action": action.text if action is not None else None,
        })

    # Zones
    for zone in root.findall('.//vsys/entry/zone/entry'):
        name = zone.get('name')
        network = zone.find('network')
        interfaces = [m.text for m in network.findall('member')] if network is not None else []

        result["zones"].append({
            "name": name,
            "interfaces": interfaces,
        })

    # SNMP communities
    for comm in root.findall('.//snmp/community/entry'):
        name = comm.get('name')
        version = comm.find('version')
        result["snmp_communities"].append({
            "name": name,
            "version": version.text if version is not None else None,
        })

    # USERS (mgt-config > users > entry)
    for user_entry in root.findall('.//mgt-config/users/entry'):
        username = user_entry.get('name')
        if username is None:
            continue
        # PAN-OS stores hashed passwords via <phash>; plaintext via <password>.
        # Read what's actually there instead of assuming the secure case.
        phash = user_entry.find('phash')
        password = user_entry.find('password')
        if phash is not None and phash.text:
            encrypted = True
        elif password is not None and password.text:
            encrypted = False
        else:
            encrypted = None  # unknown — neither hash nor plaintext found (e.g. external auth). Don't assume secure.
        result["users"].append({
            "name": username,
            "encrypted": encrypted,
            "privilege_or_class": None,  # not extracted in this version
        })

    # LOGGING HOSTS (log-settings > syslog > server > entry)
    # Structure: log-settings/syslog/<entry-name>/server/<entry-name>/<ip-address|hostname>
    # The outer <server> is a container holding multiple <entry> children, so we
    # must iterate the entries, not the container itself.
    for server_entry in root.findall('.//log-settings/syslog/*/server/entry'):
        # Each server entry has either <ip-address> or <hostname>
        ip_addr = server_entry.find('ip-address')
        hostname = server_entry.find('hostname')
        server_value = None
        if ip_addr is not None and ip_addr.text:
            server_value = ip_addr.text
        elif hostname is not None and hostname.text:
            server_value = hostname.text

        if server_value:
            result["logging_hosts"].append(server_value)

    return result


def _parse_xml_fallback(config_text: str, result: Dict[str, Any]) -> Dict[str, Any]:
    """Regex-based fallback when XML is malformed."""
    match = re.search(r'<hostname>(\S+)</hostname>', config_text)
    if match:
        result["hostname"] = match.group(1)

    match = re.search(r'<ip-address>(\S+)</ip-address>', config_text)
    if match:
        result["ip_address"] = match.group(1)

    match = re.search(r'<netmask>(\S+)</netmask>', config_text)
    if match:
        result["netmask"] = match.group(1)

    dns_match = re.search(r'<servers>(.*?)</servers>', config_text, re.DOTALL)
    if dns_match:
        result["dns_servers"] = re.findall(r'<member>([^<]+)</member>', dns_match.group(1))

    return result


def _parse_set(config_text: str) -> Dict[str, Any]:
    """Parse set-command CLI format. Stretch goal - basic implementation."""
    result = {
        "vendor": "paloalto_panos",
        "format": "set",
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
    }

    for line in config_text.split('\n'):
        line = line.strip()
        if not line.startswith('set '):
            continue

        parts = line.split()
        # parts[0] = 'set'
        # parts[1] = first keyword (e.g., 'deviceconfig')
        # parts[2:] = rest

        if len(parts) < 3:
            continue

        # set deviceconfig system hostname FW01
        if parts[1] == 'deviceconfig' and parts[2] == 'system':
            if len(parts) >= 4:
                if parts[3] == 'hostname':
                    result["hostname"] = parts[4] if len(parts) > 4 else None
                elif parts[3] == 'ip-address':
                    result["ip_address"] = parts[4] if len(parts) > 4 else None
                elif parts[3] == 'netmask':
                    result["netmask"] = parts[4] if len(parts) > 4 else None
                elif parts[3] == 'default-gateway':
                    result["default_gateway"] = parts[4] if len(parts) > 4 else None
                elif parts[3] == 'domain':
                    result["domain"] = parts[4] if len(parts) > 4 else None

    return result


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python3 paloalto_panos.py <config_file>")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        config_text = f.read()

    parsed = parse_paloalto_panos(config_text)
    print(json.dumps(parsed, indent=2))
