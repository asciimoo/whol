from django.template import Library
from django.conf import settings

register = Library()

@register.simple_tag
def root_url():
    return settings.ROOT_URL

@register.simple_tag
def media_url():
    return settings.MEDIA_URL

