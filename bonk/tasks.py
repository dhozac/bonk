import requests
import subprocess
import logging
import urlparse
from celery import shared_task
from django.conf import settings

logger = logging.getLogger("bonk.tasks")

@shared_task
def trigger_dns_dhcp_rebuild(obj):
    if hasattr(settings, 'BONK_TRIGGER_REBUILD'):
        if settings.BONK_TRIGGER_REBUILD['type'] == 'requests':
            response = getattr(requests, settings.BONK_TRIGGER_REBUILD.get('method', 'get'))( 
                settings.BONK_TRIGGER_REBUILD['uri']
            )
            if response.status_code not in (200, 201, 204):
                logger.error("failed to trigger rebuild: status = %d, text = %r", response.status_code, response.text)
        elif settings.BONK_TRIGGER_REBUILD['type'] == 'subprocess':
            p = subprocess.Popen(settings.BONK_TRIGGER_REBUILD['command'],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = p.communicate()
            logger.info("Triggered rebuild")
            for line in stdout.splitlines():
                logger.info(line)
            for line in stderr.splitlines():
                logger.warning(line)
            if p.returncode != 0:
                raise Exception("failed to trigger rebuild: %d", p.returncode)

def socrates_request(method, url, **kwargs):
    return getattr(requests, method.lower())(
        url,
        auth=settings.BONK_SOCRATES_AUTH,
        **kwargs)

@shared_task
def trigger_prefix_create(prefix, block):
    url = urlparse.urlparse(block['announced_by'])
    if url.scheme == 'socrates' and prefix['state'] == 'allocated':
        domain = url.path.strip('/')
        response = socrates_request("get", "https://%s/asset/" % url.netloc,
            params={
                'network__device': domain
            }
        )
        if response.status_code != 200:
            raise Exception("unable to find firewall %s in Socrates" % domain)
        firewalls = response.json()
        switch_domains = set()
        for firewall in firewalls:
            for nic in firewall.get('nics', []):
                if 'remote' in nic and 'domain' in nic:
                    switch_domains.add(nic['remote']['domain'])
        data = dict(urlparse.parse_qsl(url.query))
        domains = dict(
            [(domain, {'name': prefix['name'], 'vlan_id': 0, 'data': data})] +
            [(switch_domain, {'name': prefix['name'], 'vlan_id': 0})
                for switch_domain in switch_domains]
        )
        response = socrates_request("post", "https://%s/network/" % url.netloc,
            json={
                'vrf': prefix['vrf'],
                'network': prefix['network'],
                'length': prefix['length'],
                'permissions': prefix.get('permissions', {}),
                'domains': domains,
            }
        )
        if response.status_code != 201:
            raise Exception("unable to create network in Socrates %d: %r" %
                            (response.status_code, response.content))

@shared_task
def trigger_prefix_delete(prefix, block):
    url = urlparse.urlparse(block['announced_by'])
    if url.scheme == 'socrates' and prefix['state'] == 'allocated':
        response = socrates_request("delete", "https://%s/network/%d/%s/%d/" %
            (url.netloc, prefix['vrf'], prefix['network'], prefix['length']))
        if response.status_code not in (204, 404):
            raise Exception("unable to delete network from Socrates %d: %r" %
                            (response.status_code, response.content))
