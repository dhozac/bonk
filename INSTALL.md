# Bonk Installation
## Dependencies
* Forked [RethinkDB](https://github.com/dhozac/rethinkdb/tree/ip-address-v2.3.x) branch: ip-address-v2.3.x
** Check [packaging instructions](https://github.com/dhozac/rethinkdb/tree/ip-address-v2.3.x/mk#packaging) for deb, osx, rpm or [build](https://github.com/dhozac/rethinkdb/tree/ip-address-v2.3.x/mk#the-rethinkdb-build-system) for other preferred systems
* django version < 2, (py3 compatibility pending)
* gevent
* gunicorn
## Steps
Setup a RethinkDB instance, please note that this is only using the default rethink setup, you probably want to look over the settings
```
cp /etc/rethinkdb/default.conf.sample /etc/rethinkdb/instances.d/bonk.conf
service rethinkdb start
```
Install Bonk and it's dependencies through pip
```
pip install "django<2"
pip install gevent
pip install gunicorn
pip install bonk
```
Create a dir for bonk and init the django project
```
cd /srv
django-admin startproject da_bonk
```
Edit /srv/da_bonk/da_bonk/settings.py, add django_rethink and bonk to INSTALLED_APPS
```
# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django_rethink',
    'bonk'
]

```
Add rethinkdb specifics at the bottom of settings.py
```
RETHINK_DB_HOST = 'localhost'
RETHINK_DB_PORT = 28015
RETHINK_DB_DB = 'bonk'
```
replace da_bonk/urls.py with
```
from django.conf.urls import include, url

urlpatterns = [
    url(r'', include('django_rethink.urls', namespace='django_rethink')),
    url(r'', include('bonk.urls', namespace='bonk')),
]
```

### Configure gunicorn
Create gunicorn dirs and user
```
mkdir {/var/log,/run,/etc}/gunicorn
chmod 700 /var/log/gunicorn
useradd -s /sbin/nologin --system -d /etc/gunicorn/ -M gunicorn
chown gunicorn:gunicorn {/var/log,/run}/gunicorn
```
create /etc/gunicorn/bonk.conf.py and add
```
import multiprocessing

bind = "127.0.0.1:8000"
workers = multiprocessing.cpu_count() * 2 + 1
max_requests = 1000
max_requests_jitter = 10
loglevel = 'info'
worker_class = 'gevent'
syslog = True
syslog_addr = 'unix:///dev/log#dgram'
graceful_timeout = 40
timeout = 40
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(L)s'
```
gunicorn should be started through systemd or similar, here's an example /etc/systemd/system/gunicorn.service
```
[Unit]
Description=gunicorn daemon
Requires=gunicorn.socket
After=network.target

[Service]
PIDFile=/run/gunicorn/pid
User=gunicorn
Group=gunicorn
WorkingDirectory=/srv/da_bonk
ExecStart=/usr/bin/gunicorn --pid /run/gunicorn/pid --config=/etc/gunicorn/bonk.conf.py da_bonk.wsgi:application
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s TERM $MAINPID
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```
An example /etc/systemd/system/gunicorn.socket
```
[Unit]
Description=gunicorn socket

[Socket]
ListenStream=/run/gunicorn/socket
ListenStream=127.0.0.1:8000

[Install]
WantedBy=sockets.target
```
Add gunicorn to /etc/tmpfiles.d/gunicorn.conf. 
```echo "d /run/gunicorn 0755 gunicorn gunicorn -" > /etc/tmpfiles.d/gunicorn.conf```
Reload systemd and start gunicorn
```
systemctl daemon-reload
systemctl start gunicorn.service
```
### Django time
Migrate django, sync to rethink and create the superuser
```
cd /srv/da_bonk
python manage.py migrate
python manage.py sync rethinkdb
python manage createsuperuser
```
Bonk should be accessible via localhost
```
 curl -u $RECENTLYCREATEDSUPERUSER http://127.0.0.1:8000/address
```
