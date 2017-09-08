import collections
import urllib.parse

from iota import api

# It's nice to be exact; official SI unit conversion states that one inch is
# equal to 2.54 centimeters. This factor derives from that fact.
MILE_CONVERSION_FACTOR = 2.54 * 12 * 5280 / 100 / 1000


class Vehicle(object):
    """Represents a single vehicle registered to a ConnectedDrive account.
    
    Vehicle commands are executed asynchronously on the servers; the returned
    object can be used to later check on the status of the command. An example
    of the returned event details:
            
    {
        "executionStatus": {
            "eventId": "<some string>@bmw.de",
            "status": "INITIATED",
            "serviceType": "LIGHT_FLASH"
        }
    }
            
    Attributes:
        body_type: BMW's internal model code (eg I01, I12).
        brand: Line of vehicles this instance belongs to.
        charging_modes: A list of charging methods supported by the vehicle. It
            should be possible to determine if the vehicle supports DC fast
            charging by the presence or absence of the string 'DC' in this
            list.
        charging_status: The current charging status of the vehicle.
        connection_status: A status indicating if the vehicle is currently
            connected to the telematics network.
        construction_year: The year the vehicle was built (which may not match
            the registration model year).
        dealer: A dictionary of the contact information of the designated agent
            dealer for the vehicle.
        doors: A named tuple enabling member access to individual doors of the
            vehicle and their statuses. For example,
            Vehicle.doors.passenger_rear.
        drive_train: A description of the vehicle's drive method (eg BEV, REx).
        has_alarm: Indicates the presence/support of an alarm system.
        hood: The status of the vehicle's hood.
        mileage: The current mileage of the vehicle. Internally, BMW vehicles
            record and report their mileage in kilometers.
        model: A specifc BMW model corresponding to the vehicle (eg i3, i8).
        parking_light: The status of the vehicle's lights.
        range: A named tuple holding the various range attributes of the
            vehicle. This includes maximum potential electric range (BEV and
            REx), current potential electric range (BEV and REx), and the fuel
            level in the tank (REx only).
        steering: An indication of the vehicle's driver orientation (eg LH or
            RH).
        trunk: The current status of the vehicle's trunk.
        update_time: A timestamp indicating the age of the currently-reported
            status data.
        vin: The vehicle's VIN.
        windows: A named tuple enabling access to individual windows and their
            status. For example, Vehicle.windows.driver_front.
    """

    # Attributes that match the vehicle data JSON
    brand = str
    dealer = dict
    model = str
    steering = str
    vin = str

    # Attributes that are translated from the vehicle data JSON
    body_type = str
    charging_modes = []
    construction_year = str
    drive_train = str
    has_alarm = bool

    # Named tuples from vehicle data JSON
    __Features = collections.namedtuple(
        '__Features', [
            'a4a', 'car_cloud', 'charge_now', 'climate_control', 'climate_now',
            'door_lock', 'door_unlock', 'horn_blow', 'last_destinations',
            'light_flash', 'remote_360', 'send_poi', 'smart_solution',
            'vehicle_finder',
        ]
    )
    features = __Features

    # Attributes that match the status data JSON
    hood = str
    mileage = int
    trunk = str

    # Attributes that are translated from the status data JSON
    charging_status = str
    connection_status = str
    parking_light = str
    update_time = str

    # Named tuples from status data JSON
    __Doors = collections.namedtuple(
        '__Doors', [
            'driver_front', 'driver_rear', 'passenger_front',
            'passenger_rear', 'locked',
        ]
    )
    doors = __Doors
    __Range = collections.namedtuple(
        '__Range', [
            'fuel_level', 'max_electric', 'remaining_electric',
        ]
    )
    range = __Range
    __Windows = collections.namedtuple(
        '__Windows', [
            'driver_front', 'driver_rear', 'passenger_front',
            'passenger_rear',
        ]
    )
    windows = __Windows

    __API_ENDPOINT_TEMPLATE = '/vehicles/{vin}/{endpoint}'

    def __init__(
            self, api_client: api.BMWiApiClient, vehicle_data: dict,
            status_data: dict, distance_unit: str='kilometers'
    ):

        self.__api_client = api_client
        self.distance_unit = distance_unit

        for attribute in [
            'brand',
            'dealer',
            'model',
            'steering',
            'vin',
        ]:
            setattr(self, attribute, vehicle_data[attribute])

        for attribute, source in {
            'body_type': 'bodytype',
            'charging_modes': 'supportedChargingModes',
            'construction_year': 'yearOfConstruction',
            'drive_train': 'driveTrain',
            'has_alarm': 'hasAlarmSystem',
        }.items():
            setattr(self, attribute, vehicle_data[source])

        self.features = self.__Features(
            a4a=vehicle_data['a4a'], car_cloud=vehicle_data['carCloud'],
            charge_now=vehicle_data['chargeNow'],
            climate_control=vehicle_data['climateControl'],
            climate_now=vehicle_data['climateNow'],
            door_lock=vehicle_data['doorLock'],
            door_unlock=vehicle_data['doorUnlock'],
            horn_blow=vehicle_data['hornBlow'],
            last_destinations=vehicle_data['lastDestinations'],
            light_flash=vehicle_data['lightFlash'],
            remote_360=vehicle_data['remote360'],
            send_poi=vehicle_data['sendPoi'],
            smart_solution=vehicle_data['smartSolution'],
            vehicle_finder=vehicle_data['vehicleFinder'],
        )

        self.__update_status(status_data)

    def __update_status(self, status_data: dict):

        for attribute in [
            'hood',
            'mileage',
            'steering',
            'trunk',
            'vin',
        ]:
            setattr(self, attribute, status_data[attribute])

        for attribute, source in {
            'charging_status': 'chargingStatus',
            'connection_status': 'connectionStatus',
            'parking_light': 'parkingLight',
            'update_time': 'updateTime',
        }.items():
            setattr(self, attribute, status_data[source])

        doors_are_locked = status_data['doorLockState'] == 'SECURED'
        self.doors = self.__Doors(
            status_data['doorDriverFront'], status_data['doorDriverRear'],
            status_data['doorPassengerFront'], status_data['doorPassengerRear'],
            doors_are_locked
        )

        self.range = self.__Range(
            status_data['remainingFuel'], status_data['maxRangeElectric'],
            status_data['remainingRangeElectric'],
        )

        self.windows = self.__Windows(
            status_data['windowDriverFront'], status_data['windowDriverRear'],
            status_data['windowPassengerFront'], status_data['windowPassengerRear']
        )

    def update(self):
        """Make a call to BMW servers and refresh this vehicle's status.
        """

        api_response = self.__api_client.call_endpoint(
            'vehicles/{vin}/status'.format(vin=self.vin))

        self.__update_status(api_response['vehicleStatus'])

    def __execute_command(self, command: str, **kwargs) -> dict:
        """

        Args:
            command: API-recognized command string (eg

        Returns:
            The response from the BMW API. Vehicle commands are executed
            asynchronously on the servers so the returned object can be used
            to later check on the status of the command. An example of the
            return:
            
            {
                "executionStatus": {
                    "eventId": "<some string>@bmw.de",
                    "status": "INITIATED",
                    "serviceType": "LIGHT_FLASH"
                }
            }
        """

        api_endpoint = self.__API_ENDPOINT_TEMPLATE.format(
            vin=self.vin, endpoint='executeService'
        )
        payload = {
            'serviceType': command,
        }
        for parameter, value in kwargs.items():
            if type(parameter) is str and type(value) is str:
                payload[parameter] = value
        post_data = urllib.parse.urlencode(payload).encode()

        return self.__api_client.call_endpoint(
            api_endpoint, data=post_data, method='POST'
        )

    def flash_lights(self, count: int=1) -> dict:
        """Flash the vehicle's lights.
        
        Args: 
            count: Number of times to cycle the lights on and off.

        Returns:
            Details of the light flash command event.
        """

        return self.__execute_command('LIGHT_FLASH', count=str(count))

    def honk_horn(self) -> dict:
        """Sound the vehicle's horn.
        
        This apparently doesn't work with UK-registered BMW vehicles, but I
        have no way to test and cannot verify. Regardless, don't be a jerk.
        
        Returns:
            Details of the horn command event.
        """

        return self.__execute_command('HORN_BLOW')