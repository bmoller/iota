import urllib.parse

API_ENDPOINT = '/webapi/v1/user/'
API_SERVER = 'https://b2vapi.bmwgroup.us'
AUTHENTICATION_ENDPOINT = '/webapi/oauth/token/'

API_BASE_URL = urllib.parse.urljoin(API_SERVER, API_ENDPOINT)
AUTHENTICATION_URL = urllib.parse.urljoin(API_SERVER, AUTHENTICATION_ENDPOINT)
