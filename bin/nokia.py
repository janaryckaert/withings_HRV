#!/usr/bin/env python
from optparse import OptionParser
import sys
import os
import socket
import threading
import webbrowser

import cherrypy
import nokia

try:
    import configparser
    from urllib.parse import urlparse
except ImportError:  # Python 2.x fallback
    import ConfigParser as configparser
    from urlparse import urlparse


class NokiaOAuth2Server:
    def __init__(self, client_id, consumer_secret, callback_uri):
        """ Initialize the NokiaAuth client """
        self.success_html = """
            <h1>You are now authorized to access the Nokia API!</h1>
            <br/><h3>You can close this window</h3>"""
        self.failure_html = """
            <h1>ERROR: %s</h1><br/><h3>You can close this window</h3>%s"""

        self.auth = nokia.NokiaAuth(
            client_id,
            consumer_secret,
            callback_uri=callback_uri,
            scope='user.info,user.metrics,user.activity'
        )
        parsed_url = urlparse(callback_uri)
        self.cherrypy_config = {
            'server.socket_host': socket.gethostbyname(parsed_url.hostname),
            'server.socket_port': parsed_url.port or 80,
        }

    def browser_authorize(self):
        """
        Open a browser to the authorization url and spool up a CherryPy
        server to accept the response
        """
        url = self.auth.get_authorize_url()
        print(
            'NOTE: We are going to try to open a browser to the URL below. If '
            'a browser tab/window does not open, please navigate there manually'
        )
        print(url)
        # Open the web browser in a new thread for command-line browser support
        threading.Timer(1, webbrowser.open, args=(url,)).start()
        cherrypy.config.update(self.cherrypy_config)
        cherrypy.quickstart(self)

    @cherrypy.expose
    def index(self, state, code=None, error=None):
        """
        Receive a Nokia response containing a code. Use the code to fetch the
        credentials.
        """
        error = None
        if code:
            self.creds = self.auth.get_credentials(code)
        else:
            error = self._fmt_failure('Unknown error while authenticating')
        # Use a thread to shutdown cherrypy so we can return HTML first
        self._shutdown_cherrypy()
        return error if error else self.success_html

    def _fmt_failure(self, message):
        tb = traceback.format_tb(sys.exc_info()[2])
        tb_html = '<pre>%s</pre>' % ('\n'.join(tb)) if tb else ''
        return self.failure_html % (message, tb_html)

    def _shutdown_cherrypy(self):
        """ Shutdown cherrypy in one second, if it's running """
        if cherrypy.engine.state == cherrypy.engine.states.STARTED:
            threading.Timer(1, cherrypy.engine.exit).start()


if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option('-i', '--client-id', dest='client_id', help="Client ID")
    parser.add_option('-s', '--consumer-secret', dest='consumer_secret', help="Consumer Secret")
    parser.add_option('-b', '--callback-uri', dest='callback_uri', help="Callback URI")
    parser.add_option('-u', '--userid', dest='user_id', help="User ID")
    parser.add_option('-c', '--config', dest='config', help="Config file")

    (options, args) = parser.parse_args()

    if len(args) == 0:
        print("Missing command!")
        sys.exit(1)
    command = args.pop(0)

    req_auth_attrs = ['client_id', 'consumer_secret']
    req_creds_attrs = [
        'access_token',
        'token_expiry',
        'token_type',
        'refresh_token',
        'user_id'
    ] + req_auth_attrs
    # Save the OAuth2 secret in case we are migrating from OAuth1
    oauth2_consumer_secret = options.consumer_secret
    if not options.config is None and os.path.exists(options.config):
        config = configparser.ConfigParser(vars(options))
        config.read(options.config)
        nokiacfg = config['nokia']
        for attr in req_creds_attrs:
            setattr(options, attr, nokiacfg.get(attr, None))
        options.callback_uri = nokiacfg.get('callback_uri', None)
        if command == 'migrateconfig':
            options.consumer_key = nokiacfg.get('consumer_key')
            options.access_token_secret = nokiacfg.get('access_token_secret')

    req_auth_args = [getattr(options, a, 0) for a in req_auth_attrs]
    if not all(req_auth_args):
        print("You must provide a client id and consumer secret")
        print("Create an Oauth 2 application here: "
              "https://account.withings.com/partner/add_oauth2")
        sys.exit(1)

    if command == 'migrateconfig':
        auth = nokia.NokiaAuth(options.client_id, oauth2_consumer_secret)
        token = auth.migrate_from_oauth1(
            options.access_token, options.access_token_secret)
        cfg_split = options.config.split('.')
        options.config = '.'.join(cfg_split[0:-1] + ['oauth2', cfg_split[-1]])
        options.consumer_secret = oauth2_consumer_secret
        options.access_token = token['access_token']
        options.token_expiry = str(int(token['expires_at']))
        options.token_type = token['token_type']
        options.refresh_token = token['refresh_token']

    req_creds_args = {a: getattr(options, a, 0) for a in req_creds_attrs}
    if not all(req_creds_args.values()):
        print("Missing authentification information!")
        print("Starting authentification process...")
        server = NokiaOAuth2Server(*(req_auth_args + [options.callback_uri]))
        server.browser_authorize()

        creds = server.creds
        print("")
    else:
        creds = nokia.NokiaCredentials(**req_creds_args)

    client = nokia.NokiaApi(creds)

    if command == 'saveconfig' or command == 'migrateconfig':
        if options.config is None:
            print("Missing config filename")
            sys.exit(1)
        config = configparser.ConfigParser()
        config.add_section('nokia')
        for attr in req_creds_attrs:
            config.set('nokia', attr, getattr(creds, attr))
        with open(options.config, 'w') as f:
            config.write(f)
        print("Config file saved to %s" % options.config)
        sys.exit(0)

    if command == 'userinfo':
        print(client.get_user())
        sys.exit(0)

    if command == 'last':
        m = client.get_measures(limit=1)[0]
        if len(args) == 1:
            for n, t in nokia.NokiaMeasureGroup.MEASURE_TYPES:
                if n == args[0]:
                    print(m.get_measure(t))
        else:
            for n, t in nokia.NokiaMeasureGroup.MEASURE_TYPES:
                print("%s: %s" % (n.replace('_', ' ').capitalize(), m.get_measure(t)))
        sys.exit(0)

    if command == 'subscribe':
        client.subscribe(args[0], args[1])
        print("Subscribed %s" % args[0])
        sys.exit(0)

    if command == 'unsubscribe':
        client.unsubscribe(args[0])
        print("Unsubscribed %s" % args[0])
        sys.exit(0)

    if command == 'list_subscriptions':
        l = client.list_subscriptions()
        if len(l) > 0:
            for s in l:
                print(" - %s " % s['comment'])
        else:
            print("No subscriptions")
        sys.exit(0)

    print("Unknown command")
    print("Available commands: saveconfig, userinfo, last, subscribe, unsubscribe, list_subscriptions")
    sys.exit(1)