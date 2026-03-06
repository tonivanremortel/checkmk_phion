#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-

from cmk.agent_based.v2 import (
    SNMPTree,
    SimpleSNMPSection,
    CheckPlugin,
    Service,
    Result,
    State,
    Metric,
    exists,
)

VPN_STATE_TEXT = {
    -1: "down",
    0: "down-disabled",
    1: "active",
}


def is_site_to_site_tunnel(name: str) -> bool:
    if name.startswith("FW2FW-"):
        return True
    if name.startswith("IPSEC-"):
        return True
    return False


def base_tunnel_name(name: str) -> str:
    """
    FW2FW tunnels have transport suffixes like :0, :8, :9 and must be bundled.
    IPSEC tunnels in your walk do not, so keep them as-is.
    """
    if name.startswith("FW2FW-") and ":" in name:
        return name.rsplit(":", 1)[0]
    return name


def transport_name(name: str) -> str:
    """
    Return transport suffix for FW2FW, otherwise 'default' for single-entry IPSEC tunnels.
    """
    if name.startswith("FW2FW-") and ":" in name:
        return name.rsplit(":", 1)[1]
    return "default"


def parse_phion_vpntunnels(string_table):
    """
    Rows: [vpnName, vpnState]

    Group transports by base tunnel name.
    """
    grouped = {}  # base_name -> {"states": {transport: state}}
    for row in string_table:
        if len(row) < 2:
            continue

        name = row[0]
        if not is_site_to_site_tunnel(name):
            continue

        try:
            st = int(row[1])
        except (TypeError, ValueError):
            st = -99

        base_name = base_tunnel_name(name)
        transport = transport_name(name)

        if base_name not in grouped:
            grouped[base_name] = {"states": {}}

        grouped[base_name]["states"][transport] = st

    return grouped


def discovery_phion_vpntunnels(section):
    for tunnel_name in sorted(section.keys()):
        yield Service(item=tunnel_name)


def check_phion_vpntunnels(item, params, section):
    if item not in section:
        return

    states = section[item]["states"]

    active = []
    warnish = []
    down = []
    unknown = []

    for transport, st in sorted(states.items(), key=lambda x: x[0]):
        if st == 1:
            active.append(transport)
        elif st == 0:
            warnish.append(transport)
        elif st == -1:
            down.append(transport)
        else:
            unknown.append((transport, st))

    total = len(states)
    active_count = len(active)
    warn_count = len(warnish)
    down_count = len(down)
    unknown_count = len(unknown)

    yield Metric("vpn_transport_active", active_count)
    yield Metric("vpn_transport_total", total)
    yield Metric("vpn_transport_down", warn_count + down_count)

    details = []
    if active:
        details.append("active: " + ", ".join(active))
    if warnish:
        details.append("down-disabled: " + ", ".join(warnish))
    if down:
        details.append("down: " + ", ".join(down))
    if unknown:
        details.append(
            "unknown: " + ", ".join(f"{transport}({st})" for transport, st in unknown)
        )

    details_text = "; ".join(details)

    if active_count == total and total > 0:
        yield Result(
            state=State.OK,
            summary=f"{item}: all {total} transport(s) active",
            details=details_text,
        )
    elif active_count > 0:
        yield Result(
            state=State.WARN,
            summary=(
                f"{item}: {active_count}/{total} transport(s) active, "
                f"{warn_count + down_count} down"
            ),
            details=details_text,
        )
    elif (warn_count + down_count) > 0:
        yield Result(
            state=State.CRIT,
            summary=f"{item}: all {total} transport(s) down",
            details=details_text,
        )
    else:
        yield Result(
            state=State.UNKNOWN,
            summary=f"{item}: unable to determine tunnel state",
            details=details_text,
        )


check_plugin_phion_vpntunnels = CheckPlugin(
    name="phion_vpntunnels",
    service_name="VPN Tunnel %s",
    discovery_function=discovery_phion_vpntunnels,
    check_function=check_phion_vpntunnels,
    check_default_parameters={},
)


snmp_section_phion_vpntunnels = SimpleSNMPSection(
    name="phion_vpntunnels",
    detect=exists(".1.3.6.1.4.1.10704.1.6.1.*"),
    fetch=SNMPTree(
        base=".1.3.6.1.4.1.10704.1.6.1",
        oids=[
            "1",  # vpnName
            "2",  # vpnState
        ],
    ),
    parse_function=parse_phion_vpntunnels,
)
