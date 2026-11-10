"""Additive, host-bound S7 profiles; legacy six-profile manifests remain valid."""
import ipaddress
import re

BASE = {'dc01', 'dc02', 'ca', 'telemetry_dc01', 'telemetry_dc02', 'telemetry_ca'}
OPTIONAL = {'telemetry_windows_pilot', 'telemetry_linux_pilot', 'observability_gateway'}
SUPPORTED = BASE | OPTIONAL


def profile_names(manifest):
    names = set(manifest['certificate_profiles'])
    if not BASE <= names <= SUPPORTED:
        raise ValueError('invalid certificate profile set')
    if ('observability_gateway' in names) != ('telemetry_collector' in manifest):
        raise ValueError('gateway qualification required')
    if 'telemetry_collector' in manifest:
        host = manifest['telemetry_collector']
        valid = (set(host) == {'fqdn', 'address', 'mac', 'kind', 'machine_id', 'scope'}
                 and host['scope'] == 'samba-ad-observability-only'
                 and host['kind'] in ('qemu', 'lxc')
                 and re.fullmatch('[0-9a-f]{32}', host['machine_id'])
                 and re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', host['mac'])
                 and host['fqdn'] not in {r['fqdn'] for r in manifest['resources'].values()})
        if not valid:
            raise ValueError('invalid dedicated collector identity')
        ipaddress.IPv4Address(host['address'])
    return names


def resource(manifest, profile):
    if profile == 'observability_gateway':
        return manifest['telemetry_collector']
    return manifest['resources'][profile.removeprefix('telemetry_')]
