# withings_main.py

import os
from withings import WithingsAuth, WithingsApi
from dotenv import load_dotenv

# Load the .env file
load_dotenv()
# Grab the API token from the .env file
CONSUMER_KEY = os.getenv('SOCIAL_AUTH_WITHINGS_KEY')
CONSUMER_SECRET = os.getenv('SOCIAL_AUTH_WITHINGS_SECRET')

# Authorization of the withings app
# Source: https://github.com/search?q=repo%3Amaximebf%2Fpython-withings+settings+&type=code
auth = WithingsAuth(consumer_key=CONSUMER_KEY, 
                    consumer_secret=CONSUMER_SECRET, 
                    callback_uri='https://www.withings.com')
authorize_url = auth.get_authorize_url()

print("Go to %s allow the app and copy your oauth_verifier" % authorize_url)

oauth_verifier = input('Please enter your oauth_verifier: ')
creds = auth.get_credentials(oauth_verifier)
client = WithingsApi(creds)
measures = client.get_measures(limit=1)
print("Your last measured weight: %skg" % measures[0].weight)