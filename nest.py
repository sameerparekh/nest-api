__author__ = 'sameer'

import requests
from dateutil import parser
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager
import ssl
from pprint import pprint
import time

class MyAdapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(num_pools=connections,
                                       maxsize=maxsize,
                                       block=block,
                                       ssl_version=ssl.PROTOCOL_TLSv1)

class Nest(object):
    user_agent = 'Nest/2.1.3 CFNetwork/548.0.4'
    protocol_version = 1
    login_url = 'https://home.nest.com/user/login'
    days_map = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']

    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.mount("https://", MyAdapter())
        self._status = None

    @property
    def headers(self):
        return {'X-nl-protocol-version': self.protocol_version,
                'User-Agent': self.user_agent}

    @property
    def auth_headers(self):
        return {'X-nl-user-id': self.userid,
                'Authorization': 'Basic %s' % self.access_token}

    def login(self):
        r = self.session.post(self.login_url, headers=self.headers,
                          data={'username': self.username,
                                                  'password': self.password})
        json = r.json()
        self.transport_url = json['urls']['transport_url']
        self.access_token = json['access_token']
        self.userid = json['userid']
        self.user = json['user']
        self.cookies = r.cookies
        self.cache_expiration = parser.parse(json['expires_in'])

    def request(self, url, method=None, **kwargs):
        headers = self.headers.copy()
        headers.update(self.auth_headers)

        if 'headers' in kwargs:
            headers.update(kwargs['headers'])
            del kwargs['headers']

        if method is None:
            method = self.session.get

        r = method(url, headers=headers, cookies=self.cookies, **kwargs)
        return r

    def get_status(self):
        r = self.request(self.transport_url + '/v3/mobile/' + self.user)
        return r.json()

    def get_weather(self, postal_code):
        r = self.request("https://home.nest.com/api/0.1/weather/forecast/%s" % postal_code)
        return r.json()

    def update_status(self):
        self._status = self.get_status()
        self._status_time = time.time()

    @property
    def status(self):
        if self._status is None or time.time() - self._status_time > 300:
            self.update_status()
        return self._status

    def get_device_weather(self, device_id=None):
        if device_id is None:
            device_id = self.status['device'].keys()[0]
        postal_code = self.status['device'][device_id]['postal_code']
        weather = self.get_weather(postal_code)
        return weather

    def get_device_summary(self, device_id=None):
        if device_id is None:
            device_id = self.status['device'].keys()[0]
        weather = self.get_device_weather(device_id)
        return {
        'temperature': {'target': self.status['shared'][device_id]['target_temperature'],
                       'current': self.status['shared'][device_id]['current_temperature'],
                       'outside': weather['now']['current_temperature'] }
        }


if __name__ == "__main__":
    nest = Nest('nest.com@spam.creativedestruction.com', 'phom5vysh9phop')
    nest.login()
    pprint(nest.get_device_summary())


