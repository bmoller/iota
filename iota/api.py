import base64
import json
import urllib.error
import urllib.parse
import urllib.request
from http import HTTPStatus

from . import API_BASE_URL, AUTHENTICATION_URL
from .car import Car
from .exception import InvalidCredentialsException


class BMWiApiClient(object):

    def __init__(
            self, user_email: str, user_password: str, api_key: str,
            api_secret: str
    ):

        self.user_email = user_email
        self.user_password = user_password
        self.api_key = api_key
        self.api_secret = api_secret

        self.access_token = self.get_access_token(
            user_email, user_password, api_key=api_key, api_secret=api_secret)

    def get_access_token(
            self, user_email: str=None, user_password: str=None,
            api_key: str=None, api_secret: str=None
    ) -> str:
        """Authenticate against the BMW i API and get a new OAuth token.

        All calls to the BMW i API must have an authorization header; the
        format is:

        Authorization: Bearer <OAuth authorization token>

        :param user_email: BMW ConnectedDrive account email address
        :param user_password: BMW ConnectedDrive account password
        :param api_key: Functioning API key for the BMW i API
        :param api_secret: Functioning API secret for the BMW i API

        :return: The new authorization token
        """

        if not user_email:
            user_email = self.user_email
        if not user_password:
            user_password = self.user_password
        if not api_key:
            api_key = self.api_key
        if not api_secret:
            api_secret = self.api_secret

        authentication_string = '{key}:{secret}'.format(key=api_key,
                                                        secret=api_secret)
        authentication_string_bytes = authentication_string.encode()
        base64_auth = base64.b64encode(authentication_string_bytes)
        base64_auth_token = str(base64_auth, encoding='utf8')
        request_data = urllib.parse.urlencode({
            'grant_type': 'password',
            'password': user_password,
            'scope': 'remote_services vehicle_data',
            'username': user_email,
        }).encode()
        request_headers = {
            'Authorization': 'Basic {token}'.format(token=base64_auth_token),
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        authentication_request = urllib.request.Request(
            AUTHENTICATION_URL, data=request_data, headers=request_headers)

        try:
            with urllib.request.urlopen(authentication_request) as http_response:
                api_response = json.loads(
                    str(http_response.read(), encoding='utf8'))
        except urllib.error.HTTPError as http_error:
            api_response = json.loads(str(http_error.read(), encoding='utf8'))
            if http_error.code == HTTPStatus.BAD_REQUEST and api_response['error'] == 'invalid_grant':
                raise InvalidCredentialsException(
                    'OAuth authentication failed; check user_email, user_password, api_key, and api_secret.')
            else:
                raise

        return api_response['access_token']

    def call_endpoint(
            self, api_endpoint: str, data: bytes=None, method='GET'
    ) -> dict:
        """Call an API endpoint, optionally with data and the specified method.
        
        If data is passed, the method will be set to POST regardless of the
        method parameter. Data should be in URL-encoded form format.

        :param api_endpoint: Path to the endpoint to call
        :param data: Bytes to POST
        :param method: HTTP method to use for the request

        :return: Response from the BMW API
        """

        if data:
            method = 'POST'
        if not hasattr(self, 'access_token') or self.access_token is None:
            self.access_token = self.get_access_token()

        request_headers = {
            'Authorization': 'Bearer {token}'.format(token=self.access_token),
            'Content-Type': 'x-www-form-urlencoded',
        }
        api_request = urllib.request.Request(
            urllib.parse.urljoin(API_BASE_URL, api_endpoint), data=data,
            headers=request_headers, method=method)

        try:
            with urllib.request.urlopen(api_request) as http_response:
                api_response = json.loads(
                    str(http_response.read(), encoding='utf8'))
        except urllib.error.HTTPError as http_error:
            raise

        return api_response

    def get_car(self, vin: str) -> Car:
        """Retrieve a specific car by its VIN.
        
        :param vin: Car to query
        
        :return: The Car
        """

        api_response = self.call_endpoint(
            'vehicles/{vin}/status'.format(vin=vin))

        return Car(self, api_response['vehicleStatus'])
