"""
Normalization layer for the Network Configuration Compliance Auditor.

Purpose
-------
Provide a stable, vendor-agnostic view over the outputs of the existing
vendor-specific parsers (backend/parser/*) so that the future compliance
engine does not need to know about each vendor's raw dict shape.

This module contains NO compliance logic. It only:
  - defines the normalized data structures
  - translates existing parser output into those structures
  - preserves the original parser output for evidence/drill-down

Design notes:
  - `raw` always holds the untouched, original dict returned by the parser
    for the vendor in question. It is never mutated.
  - Fields that a given vendor's parser output does not support are left as
    None (scalars) or an empty list (collections), with a companion entry
    in `unsupported_fields` explaining that this vendor's parser does not
    extract this data at all -- as opposed to a field that was extracted
    and legitimately found empty/absent in the actual config text.
  - Absence of a field must never be silently treated as a compliance
    failure by this layer -- that judgement belongs to the (future)
    compliance engine, and only after consulting `unsupported_fields`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Common sub-structures
# ---------------------------------------------------------------------------

@dataclass
class NormalizedInterface:
    name: Optional[str]
    address: Optional[str] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None
    raw_ref: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NormalizedUser:
    name: Optional[str]
    privilege_or_class: Optional[str] = None
    encrypted: Optional[bool] = None
    raw_ref: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NormalizedSnmpCommunity:
    name: Optional[str]
    permission: Optional[str] = None
    raw_ref: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NormalizedZone:
    name: Optional[str]
    interfaces: List[str] = field(default_factory=list)
    raw_ref: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NormalizedSecurityRule:
    name: Optional[str]
    from_zones: List[str] = field(default_factory=list)
    to_zones: List[str] = field(default_factory=list)
    source: List[str] = field(default_factory=list)
    destination: List[str] = field(default_factory=list)
    service: List[str] = field(default_factory=list)
    action: Optional[str] = None
    raw_ref: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Top-level normalized config
# ---------------------------------------------------------------------------

@dataclass
class NormalizedConfig:
    vendor: str
    format: Optional[str]

    hostname: Optional[str] = None
    domain: Optional[str] = None

    interfaces: List[NormalizedInterface] = field(default_factory=list)
    users: List[NormalizedUser] = field(default_factory=list)
    logging_hosts: List[str] = field(default_factory=list)
    ntp_servers: List[str] = field(default_factory=list)
    snmp_communities: List[NormalizedSnmpCommunity] = field(default_factory=list)
    zones: List[NormalizedZone] = field(default_factory=list)
    security_rules: List[NormalizedSecurityRule] = field(default_factory=list)
    routes: List[Dict[str, Any]] = field(default_factory=list)

    unsupported_fields: List[str] = field(default_factory=list)

    raw: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Vendor-specific adapters
# ---------------------------------------------------------------------------

def normalize_cisco(parsed: Dict[str, Any]) -> NormalizedConfig:
    """Adapt parse_cisco_ios() output into NormalizedConfig.

    Known cisco_ios parser output keys (verified against
    backend/parser/cisco_ios.py and sample_configs/cisco_ios_sample.txt):
        hostname, version, services (dict), interfaces (list), users (list),
        lines (list), logging (list of {"host"}), ntp (list of str),
        snmp (list of {"community","permission"}), banners (dict),
        aaa (dict, always empty in the current parser).

    Fields NOT produced by this parser at all: domain, zones, security_rules, routes.
    """
    interfaces = [
        NormalizedInterface(
            name=i.get("name"),
            address=_combine_ip_mask(i.get("ip"), i.get("mask")),
            description=None,
            enabled=(not i.get("shutdown")) if i.get("shutdown") is not None else None,
            raw_ref=i,
        )
        for i in parsed.get("interfaces", [])
    ]

    users = [
        NormalizedUser(
            name=u.get("name"),
            privilege_or_class=str(u.get("privilege")) if u.get("privilege") is not None else None,
            encrypted=u.get("encrypted"),
            raw_ref=u,
        )
        for u in parsed.get("users", [])
    ]

    logging_hosts = [entry.get("host") for entry in parsed.get("logging", []) if entry.get("host")]

    snmp_communities = [
        NormalizedSnmpCommunity(
            name=s.get("community"),
            permission=s.get("permission"),
            raw_ref=s,
        )
        for s in parsed.get("snmp", [])
    ]

    return NormalizedConfig(
        vendor="cisco_ios",
        format=None,
        hostname=parsed.get("hostname"),
        domain=None,
        interfaces=interfaces,
        users=users,
        logging_hosts=logging_hosts,
        ntp_servers=list(parsed.get("ntp", [])),
        snmp_communities=snmp_communities,
        zones=[],
        security_rules=[],
        routes=[],
        unsupported_fields=["domain", "zones", "security_rules", "routes"],
        raw=parsed,
    )


def normalize_juniper(parsed: Dict[str, Any]) -> NormalizedConfig:
    """Adapt parse_juniper_junos() output into NormalizedConfig.

    Known juniper_junos parser output keys (verified against
    backend/parser/juniper_junos.py and sample_configs/juniper_junos_sample*.txt):
        vendor, hostname, domain, users (list), services (dict),
        interfaces (list of {"name","description","unit","address"}),
        ntp (list of str), syslog (list of {"host","level"}),
        snmp (dict with "communities" list), security (dict with "zones" list),
        routes (list of {"prefix","next_hop"}).

    Fields NOT produced by this parser: security_rules (juniper has zones but
    no discrete security-rule list in the current parser output).
    """
    interfaces = [
        NormalizedInterface(
            name=i.get("name"),
            address=i.get("address"),
            description=i.get("description"),
            enabled=None,
            raw_ref=i,
        )
        for i in parsed.get("interfaces", [])
    ]

    users = [
        NormalizedUser(
            name=u.get("name"),
            privilege_or_class=u.get("class"),
            encrypted=u.get("encrypted"),
            raw_ref=u,
        )
        for u in parsed.get("users", [])
    ]

    logging_hosts = [entry.get("host") for entry in parsed.get("syslog", []) if entry.get("host")]

    snmp_communities = [
        NormalizedSnmpCommunity(
            name=c.get("name"),
            permission=c.get("permission"),
            raw_ref=c,
        )
        for c in parsed.get("snmp", {}).get("communities", [])
    ]

    zones = [
        NormalizedZone(
            name=z.get("name"),
            interfaces=list(z.get("interfaces", [])),
            raw_ref=z,
        )
        for z in parsed.get("security", {}).get("zones", [])
    ]

    return NormalizedConfig(
        vendor="juniper_junos",
        format=None,
        hostname=parsed.get("hostname"),
        domain=parsed.get("domain"),
        interfaces=interfaces,
        users=users,
        logging_hosts=logging_hosts,
        ntp_servers=list(parsed.get("ntp", [])),
        snmp_communities=snmp_communities,
        zones=zones,
        security_rules=[],
        routes=list(parsed.get("routes", [])),
        unsupported_fields=["security_rules"],
        raw=parsed,
    )


def normalize_paloalto(parsed: Dict[str, Any]) -> NormalizedConfig:
    """Adapt parse_paloalto_panos() / parse_paloalto_curly() output into NormalizedConfig.

    Known paloalto_panos / paloalto_curly parser output keys (verified against
    backend/parser/paloalto_panos.py, backend/parser/paloalto_curly.py, and
    sample_configs/paloalto_panos_sample.txt, paloalto_panos_curly.txt,
    paloalto_curly_real.txt):
        vendor, format, hostname, domain, ip_address, netmask, default_gateway,
        dns_servers (list), ntp_servers (dict with "primary"/"secondary"),
        interfaces (list of {"name","ip"}), addresses (list of {"name","cidr"}),
        services (list of {"name","protocol","port"}),
        security_rules (list of {"name","from","to","source","destination","service","action"}),
        zones (list of {"name","interfaces"}), snmp_communities (list of {"name","version"}),
        raw_blocks (dict, curly-brace format only -- full pre-extraction AST).

    Fields NOT produced by this parser: routes.
    (users and logging_hosts are now extracted from deviceconfig/mgt-config
    and log-settings/syslog respectively.)

    KNOWN LIMITATION (documented here, not fixed by this adapter): for some
    curly-brace inputs (e.g. sample_configs/paloalto_panos_curly.txt),
    parse_paloalto_panos()'s extraction helpers return empty interfaces/
    addresses/services/security_rules/zones/snmp_communities lists even
    though the equivalent data IS present in raw_blocks. This adapter does
    not attempt to re-extract from raw_blocks -- doing so would duplicate
    parser logic outside the parser layer. Consumers needing that data for
    such inputs must currently read `raw`/`raw["raw_blocks"]` directly.
    """
    interfaces = [
        NormalizedInterface(
            name=i.get("name"),
            address=i.get("ip"),
            description=None,
            enabled=None,
            raw_ref=i,
        )
        for i in parsed.get("interfaces", [])
    ]

    zones = [
        NormalizedZone(
            name=z.get("name"),
            interfaces=list(z.get("interfaces", [])),
            raw_ref=z,
        )
        for z in parsed.get("zones", [])
    ]

    security_rules = [
        NormalizedSecurityRule(
            name=r.get("name"),
            from_zones=list(r.get("from", [])),
            to_zones=list(r.get("to", [])),
            source=list(r.get("source", [])),
            destination=list(r.get("destination", [])),
            service=list(r.get("service", [])),
            action=r.get("action"),
            raw_ref=r,
        )
        for r in parsed.get("security_rules", [])
    ]

    snmp_communities = [
        NormalizedSnmpCommunity(
            name=c.get("name"),
            permission=c.get("version"),
            raw_ref=c,
        )
        for c in parsed.get("snmp_communities", [])
    ]

    ntp = parsed.get("ntp_servers", {}) or {}
    ntp_list = [v for v in (ntp.get("primary"), ntp.get("secondary")) if v]

    # Extract users from parser output (mgt-config/users/entry)
    users = [
        NormalizedUser(
            name=u.get("name"),
            privilege_or_class=None,
            encrypted=u.get("encrypted"),
            raw_ref=u,
        )
        for u in parsed.get("users", [])
    ]

    # Extract logging hosts from parser output (log-settings/syslog)
    logging_hosts = list(parsed.get("logging_hosts", []))

    # Determine unsupported fields based on format
    base_unsupported = ["routes"]
    if parsed.get("format") == "curly_brace":
        base_unsupported += ["users", "logging_hosts"]

    return NormalizedConfig(
        vendor=parsed.get("vendor", "paloalto_panos"),
        format=parsed.get("format"),
        hostname=parsed.get("hostname"),
        domain=parsed.get("domain"),
        interfaces=interfaces,
        users=users,
        logging_hosts=logging_hosts,
        ntp_servers=ntp_list,
        snmp_communities=snmp_communities,
        zones=zones,
        security_rules=security_rules,
        routes=[],
        unsupported_fields=base_unsupported,
        raw=parsed,
    )


# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------

_VENDOR_ADAPTERS = {
    "cisco_ios": normalize_cisco,
    "juniper_junos": normalize_juniper,
    "paloalto_panos": normalize_paloalto,
}


def normalize(vendor: str, parsed: Dict[str, Any]) -> NormalizedConfig:
    """Top-level normalization entry point.

    `vendor` should be one of the strings returned by
    backend.parser.detect_vendor(): "cisco_ios", "juniper_junos", "paloalto_panos".

    `parsed` must be the dict already returned by the matching backend.parser
    parse_* function for that vendor. This function does not call the parsers
    itself and does not perform vendor/format detection -- that remains the
    caller's / future API layer's responsibility.
    """
    adapter = _VENDOR_ADAPTERS.get(vendor)
    if adapter is None:
        raise ValueError(
            f"No normalization adapter for vendor '{vendor}'. "
            f"Known vendors: {sorted(_VENDOR_ADAPTERS)}"
        )
    return adapter(parsed)


def _combine_ip_mask(ip: Optional[str], mask: Optional[str]) -> Optional[str]:
    """Combine a bare IP + dotted-decimal mask (cisco style) into a single
    display string. Does not compute a CIDR prefix length -- that would
    require interpreting the mask numerically, which the cisco_ios parser
    itself does not do, so this adapter does not invent that computation
    either."""
    if ip is None:
        return None
    if mask is None:
        return ip
    return f"{ip} {mask}"