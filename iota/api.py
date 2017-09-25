import base64
import collections
import http
import json
import urllib.error
import urllib.parse
import urllib.request

import iota.exception
from iota import vehicle


@property
def regions() -> collections.namedtuple:
    valid_regions = [
        'CHINA',
        'EUROPE',
        'US',
    ]
    regions_tuple = collections.namedtuple('regions_tuple', valid_regions)

    return regions_tuple._make(valid_regions)


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
        refresh_token: An OAuth token that can be used to re-authenticate
            without a user name and password.
        region: A valid region for the BMW API.
    """

    access_token = str
    api_key = str
    api_secret = str
    region = str
    user_email = str
    user_password = str

    _API_ENDPOINT = '/webapi/v1/user/'
    _API_SERVER_CHINA = 'https://b2vapi.bmwgroup.cn:8592'
    _API_SERVER_EUROPE = 'https://b2vapi.bmwgroup.com'
    _API_SERVER_US = 'https://b2vapi.bmwgroup.us'
    _AUTHENTICATION_ENDPOINT = '/webapi/oauth/token/'

    def __init__(
        self, api_key: str, api_secret: str, username: str=None,
        password: str=None, refresh_token: str=None, region: str='US'
    ):
        """Create a new instance.

        Args:
            api_key: API key for the ConnectedDrive service.
            api_secret: API secret for the ConnectedDrive service.
            username: A ConnectedDrive username, generally the user's
                registered e-mail address.
            password: Password of the ConnectedDrive account.
            refresh_token: An OAuth refresh token that can be used to
                authenticate without username and password. If this is
                provided a username and password are not required; a refresh
                token is the preferred authentication method.
            region: A region to connect to for the ConnectedDrive service.

        Raises:
            RuntimeError: Occurs when the constructor does not receive required
                authentication information. Either an OAuth refresh token or
                both a user email address and user password must be provided in
                order to successfully authenticate.
        """

        if (
            (username is None or password is None) and refresh_token is None
        ):
            raise RuntimeError(
                'Either refresh_token or both user_email and user_password '
                'must not be None'
            )

        self.api_key = api_key
        self.api_secret = api_secret
        self._vehicles = {}

        try:
            self._API_URL = urllib.parse.urljoin(
                getattr(self, '_API_SERVER_{region}'.format(region=region)),
                self._API_ENDPOINT
            )
            self._AUTHENTICATION_URL = urllib.parse.urljoin(
                getattr(self, '_API_SERVER_{region}'.format(region=region)),
                self._AUTHENTICATION_ENDPOINT
            )
        except KeyError:
            raise KeyError(
                '{bad_region} is not a valid region; valid regions are '
                '{valid_regions}'.format(
                    bad_region=region,
                    valid_regions=', '.join(globals()['regions'])
                )
            )

        self.access_token, self.refresh_token = self.get_access_token(
            username=username, password=password, refresh_token=refresh_token)

    def get_access_token(
        self, username: str=None, password: str=None, refresh_token: str=None
    ) -> tuple:
        """Authenticate against the BMW i API and get a new OAuth token.

        Args:
            username: A ConnectedDrive user account e-mail address.
            password: The password for the ConnectedDrive account.
            refresh_token: A OAuth refresh token returned by a previous
                authentication request. If this parameter is supplied any
                username and password also supplied are ignored.

        Returns:
            A tuple with both a new OAuth authorization token and a new OAuth
            refresh token. The authorization token must be sent in a header
            with each and every API request in this format:

            Authorization: Bearer <OAuth authorization token>

        Raises:
            InvalidCredentialsException: Authentication against the API failed.
        """

        authentication_string = '{key}:{secret}'.format(
            key=self.api_key, secret=self.api_secret
        )
        authentication_string_bytes = authentication_string.encode()
        base64_auth = base64.b64encode(authentication_string_bytes)
        base64_auth_token = str(base64_auth, encoding='utf8')
        form_data = {
            'scope': 'remote_services vehicle_data',
        }
        if refresh_token:
            form_data.update({
                'grant_type': 'refresh_token',
                'refresh_token': refresh_token,
            })
        else:
            form_data.update({
                'grant_type': 'password',
                'password': password,
                'username': username,
            })
        post_data = urllib.parse.urlencode(form_data).encode()
        request_headers = {
            'Authorization': 'Basic {token}'.format(token=base64_auth_token),
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        authentication_request = urllib.request.Request(
            self._AUTHENTICATION_URL, data=post_data, headers=request_headers)

        try:
            with urllib.request.urlopen(authentication_request) as http_response:
                api_response = json.loads(
                    str(http_response.read(), encoding='utf8'))
        except urllib.error.HTTPError as http_error:
            api_response = json.loads(str(http_error.read(), encoding='utf8'))
            if (
                http_error.code == http.HTTPStatus.BAD_REQUEST
                and api_response['error'] == 'invalid_grant'
            ):
                raise iota.exception.InvalidCredentialsException(
                    'OAuth authentication failed; check user_email, '
                    'user_password, api_key, and api_secret.'
                )
            else:
                raise

        return api_response['access_token'], api_response['refresh_token']

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

        # URL join method requires this not begin with a forward slash
        while api_endpoint[0] == '/':
            api_endpoint = api_endpoint[1:]
        if data:
            method = 'POST'
        if self.access_token is None:
            self.access_token = self.get_access_token()

        request_headers = {
            'Authorization': 'Bearer {token}'.format(token=self.access_token),
            'Content-Type': 'application/x-www-form-urlencode',
        }
        api_request = urllib.request.Request(
            urllib.parse.urljoin(self._API_URL, api_endpoint), data=data,
            headers=request_headers, method=method)

        try:
            with urllib.request.urlopen(api_request) as http_response:
                api_response = http_response.read()
        except urllib.error.HTTPError:
            raise

        if parse_as_json:
            api_response = json.loads(str(api_response, encoding='utf8'))

        return api_response

    def _get_vehicles(self):
        """Refresh the cached vehicle list.
        """

        self._vehicles = {}
        api_response = self.call_endpoint('vehicles')
        for vehicle_record in api_response['vehicles']:
            self._vehicles[vehicle_record['vin']] = vehicle_record

    def vehicles(self, refresh: bool=False) -> list:
        """Get a list of all vehicles registered with the current account.

        Args:
            refresh: Discard any cached data and make an API request for the
                     current list.

        Returns:
            List of VIN's of the registered vehicles.
        """

        if not self._vehicles or refresh:
            self._get_vehicles()

        return list(self._vehicles.keys())

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

        # Do the logical thing and try refreshing the list once before failing
        if not self._vehicles or vin not in self._vehicles:
            self._get_vehicles()
        if vin not in self._vehicles:
            raise KeyError(
                'No vehicle with VIN {vin} is registered'.format(vin=vin)
            )

        api_response = self.call_endpoint(
            'vehicles/{vin}/status'.format(vin=vin))

        return vehicle.Vehicle(
            self, self._vehicles[vin], api_response['vehicleStatus']
        )
