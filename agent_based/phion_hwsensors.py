#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-

from cmk.agent_based.v2 import (
    SNMPTree,
    CheckPlugin,
    SimpleSNMPSection,
    exists,
    Service,
    Result,
    State,
    check_levels,
    Metric,
)

# PHION-MIB::hwSensors
# base: .1.3.6.1.4.1.10704.1.4
# entry:
#   .1 hwSensorName   (OctetString / DisplayString)
#   .2 hwSensorType   (SensorType enum)
#   .3 hwSensorValue  (Integer32)

# Observed / typical SensorType mapping:
#   -1 unknown, 0 voltage, 1 fan, 2 temperature, 3 psu-status
SENSOR_TYPE = {
    -1: "unknown",
    0: "voltage",
    1: "fan",
    2: "temperature",
    3: "psu-status",
}

# No documentation found. Status 1 & 3 are from a live box.
PSU_STATUS_MAP = {
    0: (State.UNKNOWN, "Unknown"),
    1: (State.OK, "OK"),
    2: (State.WARN, "Warning"),
    3: (State.CRIT, "Power fail"),
}

def parse_phion_hwsensors(string_table):
    """
    string_table rows look like:
      [<name>, <type_int>, <value_int>]
    """
    parsed = {}
    for row in string_table:
        if len(row) < 3:
            continue
        name = row[0]
        try:
            stype = int(row[1])
        except (TypeError, ValueError):
            stype = -1
        try:
            value = int(row[2])
        except (TypeError, ValueError):
            value = 0

        parsed[name] = {"type": stype, "value": value}
    return parsed


snmp_section_phion_hwsensors = SimpleSNMPSection(
    name="phion_hwsensors",
    detect=exists(".1.3.6.1.4.1.10704.1.4.1.*"),
    fetch=SNMPTree(
        base=".1.3.6.1.4.1.10704.1.4.1",
        oids=[
            "1",  # hwSensorName
            "2",  # hwSensorType
            "3",  # hwSensorValue
        ],
    ),
    parse_function=parse_phion_hwsensors,
)


def discovery_phion_hwsensors(section):
    for sensor_name in section.keys():
        yield Service(item=sensor_name)


def check_phion_hwsensors(item, params, section):
    if item not in section:
        return

    stype = section[item]["type"]
    value = section[item]["value"]
    stype_name = SENSOR_TYPE.get(stype, f"unknown({stype})")

    if stype == 2:
        temp_c = value / 1000.0
        yield from check_levels(
            temp_c,
            levels_upper=params.get("temp"),
            metric_name="temp",
            label=f"{item}",
            render_func=lambda v: f"{v:.1f} °C",
        )
        return

    if stype == 1:
        rpm = value
        yield from check_levels(
            rpm,
            levels_lower=params.get("fan"),
            metric_name="fan_rpm",
            label=f"{item}",
            render_func=lambda v: f"{int(v)} rpm",
        )
        return

    if stype == 3:
        state, text = PSU_STATUS_MAP.get(value, (State.CRIT, "crit"))
        yield Metric("psu_state", int(value))
        yield Result(state=state, summary=f"{item}: {text} ({value})")
        return

    if stype == 0:
        yield Result(state=State.OK, summary=f"{item}: {value} (raw voltage)")
        return

    yield Result(state=State.OK, summary=f"{item}: {value} (type {stype_name})")


check_plugin_phion_hwsensors = CheckPlugin(
    name="phion_hwsensors",
    service_name="HW Sensor %s",
    discovery_function=discovery_phion_hwsensors,
    check_function=check_phion_hwsensors,
    check_ruleset_name="phion_hwsensors",
    check_default_parameters={},
)

