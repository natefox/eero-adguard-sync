#!/usr/bin/env python3
import json
import os
import asyncio
import logging

from adguardhome import AdGuardHome, AdGuardHomeError
import eero

EERO_COOKIE_FILE = 'session.cookie'
ADGUARD_IP = os.getenv('ADGUARD_IP')
ADGUARD_PORT = int(os.getenv('ADGUARD_PORT', 80))
ADGUARD_LOGIN = os.getenv('ADGUARD_LOGIN', 'admin')
ADGUARD_PASSWORD = os.getenv('ADGUARD_PASSWORD')
SLEEP_TIME = int(os.getenv('SLEEP_TIME', 3600))
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()

logging.basicConfig(level=LOG_LEVEL, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CookieStore(eero.SessionStorage):
    def __init__(self, cookie_file):
        from os import path
        self.cookie_file = path.abspath(cookie_file)

        try:
            with open(self.cookie_file, 'r') as f:
                self.__cookie = f.read()
        except IOError:
            self.__cookie = None

    @property
    def cookie(self):
        return self.__cookie

    @cookie.setter
    def cookie(self, cookie):
        self.__cookie = cookie
        with open(self.cookie_file, 'w+') as f:
            f.write(self.__cookie)

def get_eero_devices():
    logger.debug("Fetching Eero devices")
    session = CookieStore(EERO_COOKIE_FILE)
    eero_client = eero.Eero(session)
    account = eero_client.account()
    all_devices = []
    for network in account['networks']['data']:
        if os.environ.get('EERO_NETWORK_NAMES'):
            allowed_names = [name.strip() for name in os.environ['EERO_NETWORK_NAMES'].split(',')]
            if network['name'] not in allowed_names:
                logger.debug(f"Skipping network {network['name']} due to EERO_NETWORK_NAMES filter")
                continue
        devices = eero_client.devices(network['url'])
        all_devices.extend(devices)

    logger.debug(f"Eero devices: {json.dumps(all_devices, indent=4)}")
    return all_devices

def ensure_unique_device_name(device, eero_devices):
    device_name = device.get('display_name')
    if not device_name:
        return None
    devices_with_device_name = [d for d in eero_devices if d.get('display_name') == device_name]
    if len(devices_with_device_name) > 1:
        device_name = f"{device_name} ({device['mac'][-8:]})"
        logger.debug(f"Device name not unique, appending MAC: {device_name}")
    return device_name

def get_device_tags(device):
    if not device.get('display_name'):
        return []
    name_lower = device['display_name'].lower()
    device_tags = set()

    TAG_RULES = [
        ('iphone',      ['device_phone', 'os_ios']),
        ('android',     ['device_phone', 'os_android']),
        ('phone',       ['device_phone']),
        ('kindle',      ['device_tablet']),
        ('ipad',        ['device_tablet']),
        ('fire hd',     ['device_tablet', 'os_android']),
        ('macbook',     ['device_laptop', 'os_macos']),
        ('nintendo',    ['device_gameconsole']),
        ('nvidia',      ['device_gameconsole']),
        ('xbox',        ['device_gameconsole']),
        ('playstation', ['device_gameconsole']),
        ('ps5',         ['device_gameconsole']),
        ('sonos',       ['device_audio']),
        ('bose',        ['device_audio']),
        ('tcl',         ['device_tv']),
        ('linux',       ['os_linux']),
    ]

    for keyword, tags in TAG_RULES:
        if keyword in name_lower:
            device_tags.update(tags)

    return sorted(device_tags)

def apply_client_renames(device_name):
    client_renames = os.getenv('CLIENT_RENAMES', '')
    if client_renames:
        client_renames_dict = {old_name: new_name for old_name, new_name in [item.split('|') for item in client_renames.split(',')]}
        if device_name in client_renames_dict:
            logger.info(f"Renaming device {device_name} to {client_renames_dict[device_name]}")
            device_name = client_renames_dict[device_name]
    return device_name


DEFAULT_CLIENT = {
    "tags": [],
    "use_global_settings": True,
    "filtering_enabled": False,
    "safebrowsing_enabled": False,
    "parental_enabled": False,
    "ignore_querylog": False,
    "ignore_statistics": False,
    "blocked_services": [],
    "safe_search": {
        "enabled": False,
        "bing": True,
        "duckduckgo": True,
        "ecosia": True,
        "google": True,
        "pixabay": True,
        "yandex": True,
        "youtube": True
    },
    "upstreams": [],
    "upstreams_cache_enabled": False,
    "upstreams_cache_size": 0,
    "use_global_blocked_services": True,
    "blocked_services_schedule": {"time_zone": "Local"},
}


async def add_device_to_adguard(adguard, device_name, device_ip, device_tags=None):
    logger.debug(f"Adding device to AdGuard: {device_name} at {device_ip} with tags {device_tags}")
    payload = {**DEFAULT_CLIENT, "ids": [device_ip], "name": device_name}
    if device_tags:
        payload['tags'] = device_tags
    await adguard.request(uri="clients/add", method="POST", json_data=payload)


async def update_device_ip(adguard, device_name, device_ip, device_tags=None):
    logger.debug(f"Updating device IP in AdGuard: {device_name} to {device_ip} with tags {device_tags}")
    data = {**DEFAULT_CLIENT, "ids": [device_ip], "name": device_name}
    if device_tags:
        data['tags'] = device_tags
    payload = {"name": device_name, "data": data}
    await adguard.request(uri="clients/update", method="POST", json_data=payload)


async def delete_device_from_adguard(adguard, device_name):
    logger.debug(f"Deleting device from AdGuard: {device_name}")
    await adguard.request(uri="clients/delete", method="POST", json_data={"name": device_name})


async def update_adguard_clients():
    logger.info("Starting AdGuard clients update")
    eero_devices = get_eero_devices()
    logger.debug(f"Retrieved {len(eero_devices)} Eero devices")
    async with AdGuardHome(
        host=ADGUARD_IP,
        port=ADGUARD_PORT,
        username=ADGUARD_LOGIN,
        password=ADGUARD_PASSWORD
    ) as adguard:
        adguard_clients_obj = await adguard.request('clients')
        adguard_clients = adguard_clients_obj['clients']
        adguard_name_ips = {a['name']: a.get('ids', []) for a in adguard_clients}
        adguard_name_tags = {a['name']: a.get('tags', []) for a in adguard_clients}
        # Build reverse map: IP -> client name for conflict resolution
        adguard_ip_name = {}
        for a in adguard_clients:
            for ip in a.get('ids', []):
                adguard_ip_name[ip] = a['name']
        logger.debug(f"Retrieved {len(adguard_clients)} AdGuard clients")

        for eero_device in eero_devices:
            try:
                device_display_name = ensure_unique_device_name(eero_device, eero_devices)
                device_display_name = apply_client_renames(device_display_name)
                if not device_display_name:
                    continue
                device_ip = eero_device.get('ipv4')
                device_tags = get_device_tags(eero_device)

                logger.info(f"Processing device: {device_display_name}/{device_ip}/{sorted(adguard_name_tags.get(device_display_name, []))}->{device_tags}")

                if device_display_name in adguard_name_ips and not device_ip:
                    logger.info(f"Deleting device {device_display_name} from AdGuard Home (no IP)")
                    await delete_device_from_adguard(adguard, device_display_name)

                elif device_display_name not in adguard_name_ips and device_ip:
                    # Check if the IP is already claimed by another client
                    existing_owner = adguard_ip_name.get(device_ip)
                    if existing_owner and existing_owner != device_display_name:
                        logger.info(f"IP {device_ip} is owned by '{existing_owner}', deleting old client before adding '{device_display_name}'")
                        await delete_device_from_adguard(adguard, existing_owner)
                        del adguard_name_ips[existing_owner]
                        adguard_ip_name[device_ip] = device_display_name
                    logger.info(f"Adding device {device_display_name}/{device_ip}/{device_tags}")
                    await add_device_to_adguard(adguard, device_display_name, device_ip, device_tags)
                    adguard_name_ips[device_display_name] = [device_ip]

                elif device_display_name in adguard_name_ips and device_ip and device_ip not in adguard_name_ips[device_display_name]:
                    logger.info(f"Updating device {device_display_name}/{device_ip}/{device_tags}")
                    await update_device_ip(adguard, device_display_name, device_ip, device_tags)
                    adguard_name_ips[device_display_name] = [device_ip]

                # Update tags if they changed
                if device_ip and sorted(adguard_name_tags.get(device_display_name, [])) != device_tags:
                    logger.info(f"Updating device tags on {device_display_name}: {sorted(adguard_name_tags.get(device_display_name, []))}->{device_tags}")
                    await update_device_ip(adguard, device_display_name, device_ip, device_tags)
                    adguard_name_tags[device_display_name] = device_tags

            except AdGuardHomeError as e:
                logger.error(f"Error processing device {device_display_name}: {e}")
                continue

            await asyncio.sleep(0.4)

        logger.info("AdGuard Home devices updated successfully")

async def main():
    logger.info("Starting main loop")
    while True:
        await update_adguard_clients()
        logger.info(f"Sleeping for {SLEEP_TIME} seconds")
        await asyncio.sleep(SLEEP_TIME)

if __name__ == '__main__':
    logger.info("Starting Eero to AdGuard Home sync script")
    asyncio.run(main())


"""
For reference

Eero device object:
    {
        "url": "/2.2/networks/yyyyyy/devices/xxxxxxxxxxx",
        "mac": "74:4c:a1:12:12:12",
        "eui64": "744ca1fffe121212",
        "manufacturer": "Liteon Technology Corporation",
        "ip": null,
        "ips": [],
        "ipv6_addresses": [
            {
                "address": "fe80:0:0:0:e93:cccc:bbbb:aaaa/64",
                "scope": "link",
                "interface": "br_lan"
            }
        ],
        "nickname": null,
        "hostname": "0be8ca7cd8b201a1930a4e68dfffffff",
        "connected": false,
        "wireless": true,
        "connection_type": "wireless",
        "source": {
            "location": "Kitchen",
            "is_gateway": false,
            "model": "eero 6+",
            "display_name": "Kitchen eero",
            "serial_number": "GGC1UC0KAAAAAAAAA",
            "is_proxied_node": false,
            "url": "/2.2/eeros/NNNNNNN"
        },
        "last_active": "2025-12-22T03:20:47.523Z",
        "first_active": "2025-12-22T02:05:19.956Z",
        "connectivity": {
            "rx_bitrate": "866.7 MBit/s",
            "signal": "-57 dBm",
            "signal_avg": null,
            "score": 1,
            "score_bars": 5,
            "frequency": 5580,
            "rx_rate_info": {
                "rate_bps": 866700000,
                "mcs": 9,
                "nss": 2,
                "guard_interval": "GI_400NS",
                "channel_width": "WIDTH_80MHz",
                "phy_type": "VHT"
            },
            "tx_rate_info": {
                "rate_bps": 866700000,
                "mcs": 9,
                "nss": 2,
                "guard_interval": "GI_400NS",
                "channel_width": "WIDTH_80MHz",
                "phy_type": "VHT"
            },
            "ethernet_status": null
        },
        "interface": {
            "frequency": "5",
            "frequency_unit": "GHz"
        },
        "usage": null,
        "profile": null,
        "device_type": "generic",
        "blacklisted": null,
        "dropped": null,
        "homekit": {
            "registered": false,
            "protection_mode": "UNKNOWN"
        },
        "is_guest": false,
        "paused": false,
        "channel": 116,
        "auth": "wpa2",
        "is_private": false,
        "secondary_wan_deny_access": false,
        "ring_lte": {
            "is_not_pausable": false,
            "ring_managed": false,
            "lte_enabled": false
        },
        "ipv4": null,
        "is_proxied_node": false,
        "manufacturer_device_type_id": null,
        "amazon_devices_detail": null,
        "ssid": "mywifi",
        "subnet_kind": "main",
        "vlan_id": null,
        "vlan_name": "",
        "display_name": "0be8ca7cd8b201a1930a4e68dfffffff",
        "model_name": null
    },


Adguard entire clients object:
{
    "clients": [
        {
            "safe_search": {
                "enabled": false,
                "bing": true,
                "duckduckgo": true,
                "ecosia": true,
                "google": true,
                "pixabay": true,
                "yandex": true,
                "youtube": true
            },
            "blocked_services_schedule": {
                "time_zone": "America/Los_Angeles"
            },
            "name": "0be8ca7cd8b201a1930a4e68dfffffff",
            "blocked_services": [],
            "ids": [
                "192.168.1.84"
            ],
            "tags": ["device_other"],
            "upstreams": [],
            "filtering_enabled": false,
            "parental_enabled": false,
            "safebrowsing_enabled": false,
            "safesearch_enabled": false,
            "use_global_blocked_services": true,
            "use_global_settings": true,
            "ignore_querylog": false,
            "ignore_statistics": false,
            "upstreams_cache_size": 0,
            "upstreams_cache_enabled": false
        },
        ....
    ],
    "auto_clients": [
        {
            "whois_info": {},
            "ip": "192.168.1.145",
            "name": "",
            "source": "ARP"
        },
        {
            "whois_info": {},
            "ip": "192.168.1.187",
            "name": "",
            "source": "ARP"
        },
        ...
    ],
    "supported_tags": [
        "device_audio",
        "device_camera",
        "device_gameconsole",
        "device_laptop",
        "device_nas",
        "device_other",
        "device_pc",
        "device_phone",
        "device_printer",
        "device_securityalarm",
        "device_tablet",
        "device_tv",
        "os_android",
        "os_ios",
        "os_linux",
        "os_macos",
        "os_other",
        "os_windows",
        "user_admin",
        "user_child",
        "user_regular"
    ]
}
"""