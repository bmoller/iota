import base64
import collections
import http
import json
import urllib.error
import urllib.parse
import urllib.request

import iota.exception
from iota import vehicle

__API_ENDPOINT = '/webapi/v1/user/'
__API_SERVER_EUROPE = 'https://b2vapi.bmwgroup.com'
__API_SERVER_US = 'https://b2vapi.bmwgroup.us'
__AUTHENTICATION_ENDPOINT = '/webapi/oauth/token/'

__VALID_REGIONS = [
    'CHINA',
    'EUROPE',
    'US',
]
__Regions = collections.namedtuple('__Regions', __VALID_REGIONS)
regions = __Regions._make(__VALID_REGIONS)


class BMWiApiClient(object):
    """Main class for interacting with the BMW i API.

    This client derives from reverse-engineering efforts of the BMW i API; no
    official documentation or support exists. As such, absolutely no warranty
    is provided in regards to its accuracy or functionality. In case it's still
    not clear, don't be upset if and when it breaks.

    BMW does not issue API keys, so you'll have to derive one on your own. The
    mobile apps are a good place to start.

    Attributes:
        access_token: An OAuth token provided by the API authentication system.
        api_key: A BMW API key.
        api_secret: The matching secret for the API key.
        region: A valid region for the BMW API.
        user_email: A ConnectedDrive user name, usually an e-mail address.
        user_password: The password of the ConnectedDrive user.
    """

    access_token = str
    api_key = str
    api_secret = str
    region = str
    user_email = str
    user_password = str

    def __init__(
            self, user_email: str, user_password: str, api_key: str,
            api_secret: str, region: str='US'
    ):

        self.user_email = user_email
        self.user_password = user_password
        self.api_key = api_key
        self.api_secret = api_secret

        try:
            self.__API_BASE_URL = urllib.parse.urljoin(
                globals()['__API_SERVER_{region}'.format(region=region)],
                globals()['__API_ENDPOINT']
            )
            self.__AUTHENTICATION_URL = urllib.parse.urljoin(
                globals()['__API_SERVER_{region}'.format(region=region)],
                globals()['__AUTHENTICATION_ENDPOINT']
            )
        except KeyError:
            raise KeyError(
                '{bad_region} is not a valid region; valid regions are {valid_regions}'.format(
                    bad_region=region,
                    valid_regions=', '.join(globals()['__VALID_REGIONS'])
                ))

        self.access_token = self.get_access_token()

    def get_access_token(self) -> str:
        """Authenticate against the BMW i API and get a new OAuth token.

        Returns:
            A new OAuth authorization token. This must be sent in a header with
            each and every API request in this format:

            Authorization: Bearer <OAuth authorization token>

        Raises:
            InvalidCredentialsException: Authentication against the API failed.
        """

        authentication_string = '{key}:{secret}'.format(key=self.api_key,
                                                        secret=self.api_secret)
        authentication_string_bytes = authentication_string.encode()
        base64_auth = base64.b64encode(authentication_string_bytes)
        base64_auth_token = str(base64_auth, encoding='utf8')
        request_data = urllib.parse.urlencode({
            'grant_type': 'password',
            'password': self.user_password,
            'scope': 'remote_services vehicle_data',
            'username': self.user_email,
        }).encode()
        request_headers = {
            'Authorization': 'Basic {token}'.format(token=base64_auth_token),
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        authentication_request = urllib.request.Request(
            self.__AUTHENTICATION_URL, data=request_data, headers=request_headers)

        try:
            with urllib.request.urlopen(authentication_request) as http_response:
                api_response = json.loads(
                    str(http_response.read(), encoding='utf8'))
        except urllib.error.HTTPError as http_error:
            api_response = json.loads(str(http_error.read(), encoding='utf8'))
            if http_error.code == http.HTTPStatus.BAD_REQUEST and api_response['error'] == 'invalid_grant':
                raise iota.exception.InvalidCredentialsException(
                    'OAuth authentication failed; check user_email, user_password, api_key, and api_secret.')
            else:
                raise

        return api_response['access_token']

    def call_endpoint(
        self, api_endpoint: str, data: bytes=None, method: str='GET',
        parse_as_json: bool=True
    ) -> dict:
        """Call an API endpoint, optionally with data and the specified method.

        If data is passed, the method will be set to POST regardless of the
        method parameter. Data should be in URL-encoded form format.

        Args:
            api_endpoint: A path to the endpoint to call.
            data: Bytes to POST in the API call.
            method: The HTTP method to use for the request (eg GET or POST).
            parse_as_json: Most API methods return a text response in JSON
                           format; this method can parse those to Python
                           objects. However, a few return binary data and this
                           parameter enables access to the raw bytes.

        Returns:
            The response from the BMW API. If `parse_as_json` is `True` this
            will be a Python `dict`. Otherwise, the raw `bytes` are returned.

        Raises:
            HTTPError: The error response returned by the API endpoint.
        """

        if data:
            method = 'POST'
        if self.access_token is None:
            self.access_token = self.get_access_token()

        request_headers = {
            'Authorization': 'Bearer {token}'.format(token=self.access_token),
            'Content-Type': 'application/x-www-form-urlencode',
        }
        api_request = urllib.request.Request(
            urllib.parse.urljoin(self.__API_BASE_URL, api_endpoint), data=data,
            headers=request_headers, method=method)

        try:
            with urllib.request.urlopen(api_request) as http_response:
                api_response = http_response.read()
        except urllib.error.HTTPError:
            raise

        if parse_as_json:
            return json.loads(str(api_response, encoding='utf8'))

        return api_response

    def get_vehicle(self, vin: str) -> vehicle.Vehicle:
        """Retrieve a specific vehicle by its VIN.

        Args:
            vin: A VIN to query and return as a Vehicle object. In order to
                 succeed the corresponding vehicle must be registered in the
                 ConnectedDrive portal.

        Returns:
            A new Vehicle representing the requested vehicle.

        Raises:
            KeyError: No vehicle with a matching VIN is listed in this account.
        """

        api_response = self.call_endpoint('vehicles')
        vehicle_data = None
        for vehicle_record in api_response['vehicles']:
            if vehicle_record['vin'] == vin:
                vehicle_data = vehicle_record
                break
        else:
            raise KeyError(
                'No vehicle with VIN {vin} is registered'.format(vin=vin))

        api_response = self.call_endpoint(
            'vehicles/{vin}/status'.format(vin=vin))

        return vehicle.Vehicle(
            self, vehicle_data, api_response['vehicleStatus']
        )
