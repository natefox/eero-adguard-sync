#!/usr/bin/env python3
import json
import os
import asyncio
import logging

from adguardhome import AdGuardHome, AdGuardHomeError
import eero

EERO_COOKIE_FILE = 'session.cookie'
ADGUARD_IP = os.getenv('ADGUARD_IP')
ADGUARD_PORT = os.getenv('ADGUARD_PORT', 80)
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
    # Replace 'your_eero_access_token' with your actual Eero access token
    session = CookieStore(EERO_COOKIE_FILE)
    eero_client = eero.Eero(session)
    account = eero_client.account()
    for network in account['networks']['data']:
        devices = eero_client.devices(network['url'])

    logger.debug(f"Eero devices: {json.dumps(devices, indent=4)}")
    return devices

async def ensure_unique_device_name(device, eero_devices):
    logger.debug(f"Ensuring unique name for device: {device['display_name']}")
    # look through the eero devices and ensure device's name is unique
    # if not, append the last 3 blocks of the mac address to the device_name to make it unique
    # such as "MyDevice (12:34:56)"
    # first see if the device's display_name is unique
    device_name = device['display_name']
    devices_with_device_name = [d for d in eero_devices if d['display_name'] == device_name]
    if len(devices_with_device_name) > 1:
        device_name = f"{device_name} ({device['mac'][-8:]})"
        logger.debug(f"Device name not unique, appending MAC: {device_name}")
    return device_name

async def add_device_to_adguard(device_name, device_ip, device_tags=None):
    logger.debug(f"Adding device to AdGuard: {device_name} at {device_ip} with tags {device_tags}")
    async with AdGuardHome(
        host=ADGUARD_IP,
        port=int(ADGUARD_PORT),
        username=ADGUARD_LOGIN,
        password=ADGUARD_PASSWORD
    ) as adguard:
        payload = {"ids":[device_ip],"name":device_name,"tags":[],"use_global_settings":True,"filtering_enabled":False,"safebrowsing_enabled":False,"parental_enabled":False,"ignore_querylog":False,"ignore_statistics":False,"blocked_services":[],"safe_search":{"enabled":False,"bing":True,"duckduckgo":True,"ecosia":True,"google":True,"pixabay":True,"yandex":True,"youtube":True},"upstreams":[],"upstreams_cache_enabled":False,"upstreams_cache_size":0,"use_global_blocked_services":True,"blocked_services_schedule":{"time_zone":"Local"}}
        if device_tags:
            payload['tags'] = device_tags
        await adguard.request(uri="clients/add", method="POST", json_data=payload)


async def update_device_ip(device_name, device_ip, device_tags=None):
    logger.debug(f"Updating device IP in AdGuard: {device_name} to {device_ip} with tags {device_tags}")
    async with AdGuardHome(
        host=ADGUARD_IP,
        port=ADGUARD_PORT,
        username=ADGUARD_LOGIN,
        password=ADGUARD_PASSWORD
    ) as adguard:
        payload = {"name":device_name,"data":{"ids":[device_ip],"name":device_name,"tags":[],"use_global_settings":True,"filtering_enabled":False,"safebrowsing_enabled":False,"parental_enabled":False,"ignore_querylog":False,"ignore_statistics":False,"blocked_services":[],"safe_search":{"enabled":False,"bing":True,"duckduckgo":True,"ecosia":True,"google":True,"pixabay":True,"yandex":True,"youtube":True},"upstreams":[],"upstreams_cache_enabled":False,"upstreams_cache_size":0,"use_global_blocked_services":True,"blocked_services_schedule":{"time_zone":"America/Los_Angeles"},"safesearch_enabled":False}}
        if device_tags:
            payload['data']['tags'] = device_tags
        await adguard.request(uri="clients/update", method="POST", json_data=payload)


async def delete_device_from_adguard(device_name):
    logger.debug(f"Deleting device from AdGuard: {device_name}")
    async with AdGuardHome(
        host=ADGUARD_IP,
        port=ADGUARD_PORT,
        username=ADGUARD_LOGIN,
        password=ADGUARD_PASSWORD
    ) as adguard:
        await adguard.request(uri="clients/delete", method="POST", json_data={"name": device_name})


async def get_device_tags(device, allowed_tags=None):
    if not device.get('display_name'):
        logger.debug(f"Device has no display name, returning empty tags")
        return []
    logger.debug(f"Getting tags for device: {device['display_name']}")
    ## not entirely sure how I want to handle this going forward
    ## for now we'll look at mac address or name and kinda hardcode things?
    device_tags = set()
    if 'phone' in device['display_name'].lower():
        device_tags.add('device_phone')
    if 'iphone' in device['display_name'].lower():
        device_tags.add('device_phone')
        device_tags.add('os_ios')
    if 'android' in device['display_name'].lower():
        device_tags.add('os_android')
        device_tags.add('device_phone')
    if 'kindle' in device['display_name'].lower():
        device_tags.add('device_tablet')
    if 'ipad' in device['display_name'].lower():
        device_tags.add('device_tablet')
    if 'macbook' in device['display_name'].lower():
        device_tags.add('os_macos')
        device_tags.add('device_laptop')
    if 'fire hd' in device['display_name'].lower():
        device_tags.add('os_android')
        device_tags.add('device_tablet')
    if 'nintendo' in device['display_name'].lower():
        device_tags.add('device_gameconsole')
    if 'nvidia' in device['display_name'].lower():
        device_tags.add('device_gameconsole')
    if 'xbox' in device['display_name'].lower():
        device_tags.add('device_gameconsole')
    if 'playstation' in device['display_name'].lower():
        device_tags.add('device_gameconsole')
    if 'ps5' in device['display_name'].lower():
        device_tags.add('device_gameconsole')
    if 'sonos' in device['display_name'].lower():
        device_tags.add('device_audio')
    if 'bose' in device['display_name'].lower():
        device_tags.add('device_audio')
    if 'tcl' in device['display_name'].lower():
        device_tags.add('device_tv')
    if 'linux' in device['display_name'].lower():
        device_tags.add('os_linux')

    return sorted(list(device_tags))

async def apply_client_renames(device_name):
    logger.debug(f"Applying client renames for device: {device_name}")
    # create a dictionary of client renames from the env var CLIENT_RENAMES
    # CLIENT_RENAMES looks like this: "old_name|new_name,old_name2|new_name2"

    client_renames = os.getenv('CLIENT_RENAMES', '')
    if client_renames:
        client_renames_dict = {old_name: new_name for old_name, new_name in [item.split('|') for item in client_renames.split(',')]}
        if device_name in client_renames_dict:
            logger.info(f"Renaming device {device_name} to {client_renames_dict[device_name]}")
            device_name = client_renames_dict[device_name]

    return device_name


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
        adguard_allowed_tags = adguard_clients_obj['supported_tags']
        adguard_name_ips = {a['name']: a.get('ids', []) for a in adguard_clients}
        adguard_name_tags = {a['name']: a.get('tags', []) for a in adguard_clients}
        logger.debug(f"Retrieved {len(adguard_clients)} AdGuard clients")

        for eero_device in eero_devices:
            try:
                device_display_name = await ensure_unique_device_name(eero_device, eero_devices)
                device_display_name = await apply_client_renames(device_display_name)
                if not device_display_name:
                    logger.debug(f"Skipping device with no display name: {eero_device}")
                    continue
                device_tags = await get_device_tags(eero_device, adguard_allowed_tags)

                logger.info(f"Processing device: {device_display_name}/{eero_device['ipv4']}/{sorted(adguard_name_tags.get(device_display_name, []))}->{device_tags}")

                if device_display_name in adguard_name_ips and not eero_device.get('ipv4'):
                    logger.info(f"Deleting device {device_display_name} from AdGuard Home")
                    await delete_device_from_adguard(device_display_name)

                elif device_display_name not in adguard_name_ips and eero_device.get('ipv4'):
                    # Add the device to AdGuard Home
                    logger.info(f"Adding device {device_display_name}/{eero_device['ipv4']}/{device_tags}")
                    await add_device_to_adguard(device_display_name, eero_device['ipv4'], device_tags)

                elif device_display_name in adguard_name_ips and eero_device['ipv4'] not in adguard_name_ips[device_display_name]:
                    logger.info(f"Updating device {device_display_name}/{eero_device['ipv4']}/{device_tags}")
                    await update_device_ip(device_display_name, eero_device['ipv4'], device_tags)

                if eero_device.get('ipv4') and sorted(adguard_name_tags.get(device_display_name, [])) != sorted(device_tags):
                    logger.info(f"Updating device tags on {device_display_name}: {sorted(adguard_name_tags.get(device_display_name, []))}->{device_tags}")
                    await update_device_ip(device_display_name, eero_device['ipv4'], device_tags)
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