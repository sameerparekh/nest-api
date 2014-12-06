__author__ = 'sameer'

import requests
from dateutil import parser

class Nest(object):
    user_agent = 'Nest/2.1.3 CFNetwork/548.0.4'
    protocol_version = 1
    login_url = 'https://home.nest.com/user/login'
    days_map = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']

    def __init__(self, username, password):
        self.username = username
        self.password = password

    @property
    def headers(self):
        return {'X-nl-protocol-version': self.protocol_version,
                'User-Agent': self.user_agent}

    @property
    def auth_headers(self):
        return {'X-nl-user-id': self.userid,
                'Authorization': 'Basic %s' % self.access_token}

    def login(self):
        r = requests.post(self.login_url, headers=self.headers,
                          data={'username': self.username,
                                                  'password': self.password})
        json = r.json()
        self.transport_url = json['urls']['transport_url']
        self.access_token = json['access_token']
        self.userid = json['userid']
        self.user = json['user']
        self.cache_expiration = parser.parse(json['expires_in'])

    def request(self, url, method=requests.get, **kwargs):
        print url
        headers = self.headers.copy()
        headers.update(self.auth_headers)

        if 'headers' in kwargs:
            headers.update(kwargs['headers'])
            del kwargs['headers']

        r = method(url, headers=headers, **kwargs)
        return r

    def get_status(self):
        r = self.request(self.transport_url + '/v3/mobile/' + self.user)
        pass


if __name__ == "__main__":
    nest = Nest('nest.com@spam.creativedestruction.com', 'phom5vysh9phop')
    nest.login()
    nest.get_status()


