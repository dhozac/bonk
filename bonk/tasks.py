import requests
import subprocess
import logging
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
