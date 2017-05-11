import requests
import logging
from celery import shared_task
from django.conf import settings

logger = logging.getLogger("bonk.tasks")

@shared_task
def trigger_dns_dhcp_rebuild(obj):
    if hasattr(settings.BONK_TRIGGER_REBUILD):
        response = getattr(requests, settings.BONK_TRIGGER_REBUILD.get('method', 'get'))( 
            settings.BONK_TRIGGER_REBUILD['uri']
        )
        if response.status_code not in (200, 201, 204):
            logger.error("failed to trigger rebuild: status = %d, text = %r", response.status_code, response.text)
