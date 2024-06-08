# -*- coding: utf-8 -*-
#
"""
Python library for the Withings API
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Withings Body metrics Services API
<http://www.withings.com/en/api/wbsapiv2>

Uses Oauth 1.0 to authentify. You need to obtain a consumer key
and consumer secret from Withings by creating an application
here: <https://oauth.withings.com/partner/add>

Usage:

auth = WithingsAuth(CONSUMER_KEY, CONSUMER_SECRET)
authorize_url = auth.get_authorize_url()
print "Go to %s allow the app and copy your oauth_verifier" % authorize_url
oauth_verifier = raw_input('Please enter your oauth_verifier: ')
creds = auth.get_credentials(oauth_verifier)

client = WithingsApi(creds)
measures = client.get_measures(limit=1)
print "Your last measured weight: %skg" % measures[0].weight

"""

from __future__ import unicode_literals

__title__ = 'withings'
__version__ = '0.1'
__author__ = 'Maxime Bouroumeau-Fuseau'
__license__ = 'MIT'
__copyright__ = 'Copyright 2012 Maxime Bouroumeau-Fuseau'

__all__ = [str('WithingsCredentials'), str('WithingsAuth'), str('WithingsApi'),
           str('WithingsMeasures'), str('WithingsMeasureGroup')]

# import requests
# from requests_oauthlib import OAuth1, OAuth1Session
import json
import datetime
import arrow

from arrow.parser import ParserError
from requests_oauthlib import OAuth2Session
from oauthlib.oauth2 import WebApplicationClient


class WithingsCredentials(object):
    # def __init__(self, access_token=None, access_token_secret=None,
    #              consumer_key=None, consumer_secret=None, user_id=None):
    #     self.access_token = access_token
    #     self.access_token_secret = access_token_secret
    #     self.consumer_key = consumer_key
    #     self.consumer_secret = consumer_secret
    #     self.user_id = user_id

    # NOKIA
    def __init__(self, access_token=None, token_expiry=None, token_type=None,
            refresh_token=None, user_id=None,
            client_id=None, consumer_secret=None):
        self.access_token = access_token
        self.token_expiry = token_expiry
        self.token_type = token_type
        self.refresh_token = refresh_token
        self.user_id = user_id
        self.client_id = client_id
        self.consumer_secret = consumer_secret


class WithingsError(Exception):
    STATUS_CODES = {
        # Response status codes as defined in documentation
        # http://oauth.withings.com/api/doc
        0: u"Operation was successful",
        247: u"The userid provided is absent, or incorrect",
        250: u"The provided userid and/or Oauth credentials do not match",
        286: u"No such subscription was found",
        293: u"The callback URL is either absent or incorrect",
        294: u"No such subscription could be deleted",
        304: u"The comment is either absent or incorrect",
        305: u"Too many notifications are already set",
        342: u"The signature (using Oauth) is invalid",
        343: u"Wrong Notification Callback Url don't exist",
        601: u"Too Many Request",
        2554: u"Wrong action or wrong webservice",
        2555: u"An unknown error occurred",
        2556: u"Service is not defined",
    }

    def __init__(self, status):
        super(WithingsError, self).__init__(u'{}: {}'.format(status, WithingsError.STATUS_CODES[status]))
        self.status = status


class WithingsAuth(object):
    # URL = 'https://oauth.withings.com/account'
    auth_URL = 'https://account.withings.com'
    request_URL = 'https://wbsapi.withings.net/v2'
    # request_URL = 'https://developer.withings.com'
    # request_URL = 'https://oauth.withings.com/account'


    def __init__(self, consumer_key, consumer_secret, callback_uri=None, scope='user.metrics'):
        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret
        self.oauth_token = None
        self.oauth_secret = None
        self.callback_uri=callback_uri
        self.scope = scope
        
    def _oauth(self):
        # NOKIA input
        return OAuth2Session(self.consumer_key,
                             redirect_uri=self.callback_uri,
                             scope=self.scope)

    def get_authorize_url(self):
        # NOKIA input
        return self._oauth().authorization_url(
            '%s/oauth2_user/authorize2'%self.auth_URL
        )[0]
    
    # def get_authorize_url(self):
    #     oauth = OAuth1Session(self.consumer_key,
    #                           client_secret=self.consumer_secret,
    #                           callback_uri=self.callback_uri)

    #     # curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([ 
    #     #     'action' => 'requesttoken',
    #     #     'grant_type' => 'authorization_code',
    #     #     'client_id' => '7573fd4a4c421ddd102dac406dc6e0e0e22f683c4a5e81ff0a5caf8b65abed67',
    #     #     'client_secret' => 'd9286311451fc6ed71b372a075c58c5058be158f56a77865e43ab3783255424f',
    #     #     'code' => 'mtwsikawoqleuroqcluggflrqilrnqbgqvqeuhhh',
    #     #     'redirect_uri' => 'https://www.withings.com'
    #     # ]));

    #     # https://developer.withings.com/api-reference/#tag/oauth2
    #     # https://account.withings.com/oauth2_user/authorize2?response_type=code&client_id=YOUR_CLIENT_ID&scope=user.info,user.metrics,user.activity&redirect_uri=YOUR_REDIRECT_URI&state=YOUR_STATE

    #     tokens = oauth.fetch_request_token('%s/request_token' % self.URL)
    #     self.oauth_token = tokens['oauth_token']
    #     self.oauth_secret = tokens['oauth_token_secret']

    #     return oauth.authorization_url('%s/authorize' % self.URL)

    def get_credentials(self, oauth_verifier):
        tokens = self._oauth().fetch_token(
            '%s/oauth2' % self.request_URL,
            code=oauth_verifier, # code or client id?
            client_secret=self.consumer_secret,
            include_client_id=True)
        
        # tokens = self._oauth().fetch_token(
        #     '%s/access_token' % self.URL,
        #     code=oauth_verifier, # code or client id?
        #     client_secret=self.consumer_secret,
        #     include_client_id=True)

        return WithingsCredentials(
            access_token=tokens['access_token'],
            token_expiry=str(ts()+int(tokens['expires_in'])),
            token_type=tokens['token_type'],
            refresh_token=tokens['refresh_token'],
            user_id=tokens['userid'],
            client_id=self.client_id,
            consumer_secret=self.consumer_secret,
        )

    # def get_credentials(self, oauth_verifier):
    #     oauth = OAuth1Session(self.consumer_key,
    #                           client_secret=self.consumer_secret,
    #                           resource_owner_key=self.oauth_token,
    #                           resource_owner_secret=self.oauth_secret,
    #                           verifier=oauth_verifier)
    #     tokens = oauth.fetch_access_token('%s/access_token' % self.URL)
    #     return WithingsCredentials(access_token=tokens['oauth_token'],
    #                                access_token_secret=tokens['oauth_token_secret'],
    #                                consumer_key=self.consumer_key,
    #                                consumer_secret=self.consumer_secret,
    #                                user_id=tokens['userid'])

    def migrate_from_oauth1(self, access_token, access_token_secret):
        session = OAuth2Session(self.client_id, auto_refresh_kwargs={
            'client_id': self.client_id,
            'client_secret': self.consumer_secret,
        })
        return session.refresh_token(
            '{}/oauth2/token'.format(self.request_URL),
            refresh_token='{}:{}'.format(access_token, access_token_secret)
        )

def is_date(key):
    return 'date' in key


def is_date_class(val):
    return isinstance(val, (datetime.date, datetime.datetime, arrow.Arrow, ))

# Calculate seconds since 1970-01-01 (timestamp) in a way that works in
# Python 2 and Python3
# https://docs.python.org/3/library/datetime.html#datetime.datetime.timestamp
def ts():
    return int((
        datetime.datetime.utcnow() - datetime.datetime(1970, 1, 1)
    ).total_seconds())



class WithingsApi(object):
    """
    While python-nokia takes care of automatically refreshing the OAuth2 token
    so you can seamlessly continue making API calls, it is important that you
    persist the updated tokens somewhere associated with the user, such as a
    database table. That way when your application restarts it will have the
    updated tokens to start with. Pass a ``refresh_cb`` function to the API
    constructor and we will call it with the updated token when it gets
    refreshed. The token contains ``access_token``, ``refresh_token``,
    ``token_type`` and ``expires_in``. We recommend making the refresh callback
    a method on your user database model class, so you can easily save the
    updates to the user record, like so:

    class NokiaUser(dbModel):
        def refresh_cb(self, token):
            self.access_token = token['access_token']
            self.refresh_token = token['refresh_token']
            self.token_type = token['token_type']
            self.expires_in = token['expires_in']
            self.save()

    Then when you create the api for your user, just pass the callback:

    user = ...
    creds = ...
    api = NokiaApi(creds, refresh_cb=user.refresh_cb)

    Now the updated token will be automatically saved to the DB for later use.
    """
    URL = 'https://wbsapi.withings.net'
    # URL = 'http://wbsapi.withings.net'

    # def __init__(self, credentials):
    #     self.credentials = credentials
    #     self.oauth = OAuth1(credentials.consumer_key,
    #                         credentials.consumer_secret,
    #                         credentials.access_token,
    #                         credentials.access_token_secret,
    #                         signature_type='query')
    #     self.client = requests.Session()
    #     self.client.auth = self.oauth
    #     self.client.params.update({'userid': credentials.user_id})

    def __init__(self, credentials, refresh_cb=None):
        self.credentials = credentials
        self.refresh_cb = refresh_cb
        self.token = {
            'access_token': credentials.access_token,
            'refresh_token': credentials.refresh_token,
            'token_type': credentials.token_type,
            'expires_in': str(int(credentials.token_expiry) - ts()),
        }
        oauth_client = WebApplicationClient(credentials.client_id,
            token=self.token, default_token_placement='query')
        self.client = OAuth2Session(
            credentials.client_id,
            token=self.token,
            client=oauth_client,
            auto_refresh_url='{}/oauth2/token'.format(WithingsAuth.URL),
            auto_refresh_kwargs={
                'client_id': credentials.client_id,
                'client_secret': credentials.consumer_secret,
            },
            token_updater=self.set_token
        )

    def get_credentials(self):
        return self.credentials

    def set_token(self, token):
        self.token = token
        self.credentials.token_expiry = str(
            ts() + int(self.token['expires_in'])
        )
        self.credentials.access_token = self.token['access_token']
        self.credentials.refresh_token = self.token['refresh_token']
        if self.refresh_cb:
            self.refresh_cb(token)


    # def request(self, service, action, params=None, method='GET'):
    #     if params is None:
    #         params = {}
    #     params['action'] = action
    #     r = self.client.request(method, '%s/%s' % (self.URL, service), params=params)
    #     response = json.loads(r.content.decode())
    #     if response['status'] != 0:
    #         raise WithingsError(response['status'])
    #     return response.get('body', None)

    def request(self, service, action, params=None, method='GET',
                version=None):
        params = params or {}
        params['userid'] = self.credentials.user_id
        params['action'] = action
        for key, val in params.items():
            if is_date(key) and is_date_class(val):
                params[key] = arrow.get(val).timestamp
        url_parts = filter(None, [self.URL, version, service])
        r = self.client.request(method, '/'.join(url_parts), params=params)
        response = json.loads(r.content.decode())
        if response['status'] != 0:
            raise Exception("Error code %s" % response['status'])
        return response.get('body', None)


    def get_user(self):
        return self.request('user', 'getbyuserid')

    def get_activities(self, **kwargs):
        r = self.request('measure', 'getactivity', params=kwargs, version='v2')
        activities = r['activities'] if 'activities' in r else [r]
        return [WithingsActivity(act) for act in activities]

    def get_measures(self, **kwargs):
        r = self.request('measure', 'getmeas', kwargs)
        return WithingsMeasures(r)

    def get_sleep(self, **kwargs):
        r = self.request('sleep', 'get', params=kwargs, version='v2')
        return WithingsSleep(r)

    def get_sleep_summary(self, **kwargs):
        r = self.request('sleep', 'getsummary', params=kwargs, version='v2')
        return WithingsSleepSummary(r)
    


    def subscribe(self, callback_url, comment, **kwargs):
        params = {'callbackurl': callback_url, 'comment': comment}
        params.update(kwargs)
        self.request('notify', 'subscribe', params)

    def unsubscribe(self, callback_url, **kwargs):
        params = {'callbackurl': callback_url}
        params.update(kwargs)
        self.request('notify', 'revoke', params)

    def is_subscribed(self, callback_url, appli=1):
        params = {'callbackurl': callback_url, 'appli': appli}
        try:
            self.request('notify', 'get', params)
            return True
        except:
            return False

    def list_subscriptions(self, appli=1):
        r = self.request('notify', 'list', {'appli': appli})
        return r['profiles']



    # def subscribe(self, callback_url, comment, appli=1):
    #     params = {'callbackurl': callback_url,
    #               'comment': comment,
    #               'appli': appli}
    #     self.request('notify', 'subscribe', params)

    # def unsubscribe(self, callback_url, appli=1):
    #     params = {'callbackurl': callback_url, 'appli': appli}
    #     self.request('notify', 'revoke', params)

    # def is_subscribed(self, callback_url, appli=1):
    #     params = {'callbackurl': callback_url, 'appli': appli}
    #     try:
    #         self.request('notify', 'get', params)
    #         return True
    #     except:
    #         return False

    # def list_subscriptions(self, appli=1):
    #     r = self.request('notify', 'list', {'appli': appli})
    #     return r['profiles']


class WithingsObject(object):
    def __init__(self, data):
        self.set_attributes(data)

    def set_attributes(self, data):
        self.data = data
        for key, val in data.items():
            try:
                setattr(self, key, arrow.get(val) if is_date(key) else val)
            except ParserError:
                setattr(self, key, val)

class WithingsActivity(WithingsObject):
    pass

class WithingsMeasures(list):
    def __init__(self, data):
        super(WithingsMeasures, self).__init__([WithingsMeasureGroup(g) for g in data['measuregrps']])
        self.updatetime = datetime.datetime.fromtimestamp(data['updatetime'])


class WithingsMeasureGroup(object):
    MEASURE_TYPES = (
        ('weight', 1), 
        ('height', 4), 
        ('fat_free_mass', 5),
        ('fat_ratio', 6), 
        ('fat_mass_weight', 8),
        ('diastolic_blood_pressure', 9), 
        ('systolic_blood_pressure', 10),
        ('heart_pulse', 11),
        ('temperature', 12),
        ('spo2', 54),
        ('body_temperature', 71),
        # ('skin_temperature', 72),
        ('skin_temperature', 73),
        ('muscle_mass', 76),
        ('hydration', 77),
        ('bone_mass', 88),
        ('pulse_wave_velocity', 91),
        ('vo2max', 123),
        ('fibrillation_result', 130),
        ('qrs_interval', 135),
        ('pr_interval', 136),
        ('qt_interval', 137),
        ('corrected_qt_interval', 138),
        ('ppg_atrial_fibrilation', 139),
        ('vascular_age', 155),
        ('nerve_health', 167),
        ('extracellular_water', 168),
        ('intracellular_water', 169),
        ('visceral_fat', 170), 
        ('fat_mass', 174),
        ('muscle_mass', 175),
        ('electrodermal_activity', 196),
        )

    # def __init__(self, data):
    #     self.data = data
    #     self.grpid = data['grpid']
    #     self.attrib = data['attrib']
    #     self.category = data['category']
    #     self.date = datetime.datetime.fromtimestamp(data['date'])
    #     self.measures = data['measures']
    #     for n, t in self.MEASURE_TYPES:
    #         self.__setattr__(n, self.get_measure(t))

    def __init__(self, data):
        super(WithingsMeasureGroup, self).__init__(data)
        for n, t in self.MEASURE_TYPES:
            self.__setattr__(n, self.get_measure(t))    

    def is_ambiguous(self):
        return self.attrib == 1 or self.attrib == 4

    def is_measure(self):
        return self.category == 1

    def is_target(self):
        return self.category == 2

    def get_measure(self, measure_type):
        for m in self.measures:
            if m['type'] == measure_type:
                return m['value'] * pow(10, m['unit'])
        return None
    

class WithingsSleepSeries(WithingsObject):
    def __init__(self, data):
        super(WithingsSleepSeries, self).__init__(data)
        self.timedelta = self.enddate - self.startdate


class WithingsSleep(WithingsObject):
    def __init__(self, data):
        super(WithingsSleep, self).__init__(data)
        self.series = [WithingsSleepSeries(series) for series in self.series]


class WithingsSleepSummarySeries(WithingsObject):
    def __init__(self, data):
        _data = data
        _data.update(_data.pop('data'))
        super(WithingsSleepSummarySeries, self).__init__(_data)
        self.timedelta = self.enddate - self.startdate


class WithingsSleepSummary(WithingsObject):
    def __init__(self, data):
        super(WithingsSleepSummary, self).__init__(data)
        self.series = [WithingsSleepSummarySeries(series) for series in self.series]