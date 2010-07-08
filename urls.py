from django.conf.urls.defaults import *
from django.conf import settings
import views

urlpatterns = patterns('',
    (r'^$', views.index),
)

if settings.DEV_SERVER:
    urlpatterns += patterns('',
        (r'^site_media/(?P<path>.*)$', 'django.views.static.serve', {'document_root': settings.MEDIA_PATH}),
    )
