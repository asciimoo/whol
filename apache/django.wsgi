import os, sys

apache_configuration= os.path.dirname(__file__)
project = os.path.dirname(apache_configuration)
workspace = os.path.dirname(project)
sys.path.append(workspace) 

os.environ['DJANGO_SETTINGS_MODULE'] = 'whol.settings'
import django.core.handlers.wsgi
application = django.core.handlers.wsgi.WSGIHandler()

# Apache sites-enabled config:
#
# WSGIScriptAlias /whol_url "/path/to/your/whol/apache/django.wsgi"
# Alias /whol_url/media "/path/to/your/whol/media"
# <Directory "/path/to/your/whol">
#     Options FollowSymLinks
#     AllowOverride All
# </Directory>
