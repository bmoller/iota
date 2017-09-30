import collections
import urllib.error
import urllib.parse

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
    features = collections.namedtuple

    # Attributes that match the status data JSON
    hood = str
    mileage = int
    trunk = str

    # Attributes that are translated from the status data JSON
    connection_status = str
    parking_light = str
    update_time = str

    # Named tuples from status data JSON
    charge = collections.namedtuple
    doors = collections.namedtuple
    range = collections.namedtuple
    windows = collections.namedtuple

    __API_ENDPOINT_TEMPLATE = 'vehicles/{vin}/{endpoint}'

    def __init__(
            self, api_client, vehicle_data: dict, status_data: dict,
            distance_unit: str='kilometers'
    ):

        self.__charging_profile = None
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

        Features = collections.namedtuple(
            'Features', [
                'a4a', 'car_cloud', 'charge_now', 'climate_control',
                'climate_now', 'door_lock', 'door_unlock', 'horn_blow',
                'last_destinations', 'light_flash', 'remote_360', 'send_poi',
                'smart_solution', 'vehicle_finder',
            ]
        )
        self.features = Features(
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

    def __update_status(self, status_values: dict):

        for attribute in [
            'hood',
            'mileage',
            'steering',
            'trunk',
            'vin',
        ]:
            setattr(self, attribute, status_values[attribute])

        for attribute, source in {
            'connection_status': 'connectionStatus',
            'parking_light': 'parkingLight',
            'update_time': 'updateTime',
        }.items():
            setattr(self, attribute, status_values[source])

        Charge = collections.namedtuple(
            'Charge', [
                'minutes_until_full', 'percentage', 'status',
            ]
        )
        self.charge = Charge(
            minutes_until_full=status_values['chargingTimeRemaining'] if 'chargingTimeRemaining' in status_values else 'N/A',
            percentage=status_values['chargingLevelHv'],
            status=status_values['chargingStatus'] if 'chargingStatus' in status_values else 'N/A'
        )

        Doors = collections.namedtuple(
            'Doors', [
                'driver_front', 'driver_rear', 'passenger_front',
                'passenger_rear', 'locked',
            ]
        )
        self.doors = Doors(
            driver_front=status_values['doorDriverFront'] if 'doorDriverFront' in status_values else 'N/A',
            driver_rear=status_values['doorDriverRear'] if 'doorDriverRear' in status_values else 'N/A',
            passenger_front=status_values['doorPassengerFront'] if 'doorPassengerFront' in status_values else 'N/A',
            passenger_rear=status_values['doorPassengerRear'] if 'doorPassengerRear' in status_values else 'N/A',
            locked=(status_values['doorLockState'] == 'SECURED')
        )

        Range = collections.namedtuple(
            'Range', ['fuel_level', 'max_electric', 'remaining_electric', ]
        )
        self.range = Range(
            fuel_level=status_values['remainingFuel'],
            max_electric=status_values['maxRangeElectric'],
            remaining_electric=status_values['remainingRangeElectric']
        )

        Windows = collections.namedtuple(
            'Windows', [
                'driver_front', 'driver_rear', 'passenger_front',
                'passenger_rear',
            ]
        )
        self.windows = Windows(
            driver_front=status_values['windowDriverFront'] if 'windowDriverFront' in status_values else 'N/A',
            driver_rear=status_values['windowDriverRear'] if 'windowDriverRear' in status_values else 'N/A',
            passenger_front=status_values['windowPassengerFront'] if 'windowPassengerFront' in status_values else 'N/A',
            passenger_rear=status_values['windowPassengerRear'] if 'windowPassengerRear' in status_values else 'N/A'
        )

    def update(self):
        """Make a call to BMW servers and refresh this vehicle's status.
        """

        api_response = self.__api_client.call_endpoint(
            'vehicles/{vin}/status'.format(vin=self.vin))

        self.__update_status(api_response['vehicleStatus'])

    def __execute_command(self, command: str, **kwargs) -> dict:
        """Send a command to the vehicle.

        There is obviously no guarantee of accuracy, but the list of service
        types appears to be:

            CHARGE_NOW
            CHARGING_CONTROL
            CLIMATE_CONTROL
            CLIMATE_NOW
            DOOR_LOCK
            DOOR_UNLOCK
            GET_ALL_IMAGES
            GET_PASSWORD_RESET_INFO
            GET_VEHICLES
            GET_VEHICLE_IMAGE
            GET_VEHICLE_STATUS
            HORN_BLOW
            LIGHT_FLASH
            LOCAL_SEARCH
            LOCAL_SEARCH_SUGGESTIONS
            SEND_POI_TO_CAR
            VEHICLE_FINDER

        Args:
            command: API-recognized service type (see above list)
            kwargs: Key/value pairs of strings. These will be URL-encoded and
                    sent via POST in the body

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

    @property
    def charging_profile(self) -> collections.namedtuple:
        """The automated charging and climate settings of this Vehicle.

        The data for this parameter is loaded on first access; subsequent
        access will return the previously-received data.

        Returns:
            A complete charging profile.
        """

        if self.__charging_profile:
            return self.__charging_profile

        ChargingProfile = collections.namedtuple(
            'ChargingProfile', [
                'weekly_planner',
            ]
        )
        WeeklyPlanner = collections.namedtuple(
            'WeeklyPlanner', [
                'climatization_enabled', 'mode', 'override_timer',
                'preferences', 'preferred_window', 'timer_1', 'timer_2',
                'timer_3',
            ]
        )
        ChargingTimer = collections.namedtuple(
            'ChargingTimer', [
                'departure_time', 'enabled', 'weekdays',
            ]
        )
        ChargingWindow = collections.namedtuple(
            'ChargingWindow', [
                'enabled', 'end_time', 'start_time',
            ]
        )

        api_response = self.__api_client.call_endpoint(
            self.__API_ENDPOINT_TEMPLATE.format(
                vin=self.vin, endpoint='chargingprofile'
            )
        )

        weekly_planner_values = api_response['weeklyPlanner']
        preferred_window_values = weekly_planner_values['preferredChargingWindow']
        preferred_window = ChargingWindow(
            enabled=preferred_window_values['enabled'],
            end_time=preferred_window_values['endTime'],
            start_time=preferred_window_values['startTime']
        )
        # It appears that unconfigured timers have only the 'weekdays' property
        timer_1 = None
        if len(weekly_planner_values['timer1']) > 1:
            timer_1_values = weekly_planner_values['timer1']
            timer_1 = ChargingTimer(
                departure_time=timer_1_values['departureTime'],
                enabled=timer_1_values['timerEnabled'],
                weekdays=timer_1_values['weekdays'],
            )
        timer_2 = None
        if len(weekly_planner_values['timer2']) > 1:
            timer_2_values = weekly_planner_values['timer2']
            timer_2 = ChargingTimer(
                departure_time=timer_2_values['departureTime'],
                enabled=timer_2_values['timerEnabled'],
                weekdays=timer_2_values['weekdays'],
            )
        timer_3 = None
        if len(weekly_planner_values['timer3']) > 1:
            timer_3_values = weekly_planner_values['timer3']
            timer_3 = ChargingTimer(
                departure_time=timer_3_values['departureTime'],
                enabled=timer_3_values['timerEnabled'],
                weekdays=timer_3_values['weekdays'],
            )
        override_timer = None
        if len(weekly_planner_values['overrideTimer']) > 1:
            override_timer_values = weekly_planner_values['overrideTimer']
            override_timer = ChargingTimer(
                departure_time=override_timer_values['departureTime'],
                enabled=override_timer_values['timerEnabled'],
                weekdays=override_timer_values['weekdays'],
            )

        weekly_planner = WeeklyPlanner(
            climatization_enabled=weekly_planner_values['climatizationEnabled'],
            mode=weekly_planner_values['chargingMode'],
            override_timer=override_timer,
            preferences=weekly_planner_values['chargingPreferences'],
            preferred_window=preferred_window, timer_1=timer_1,
            timer_2=timer_2, timer_3=timer_3
        )
        self.__charging_profile = ChargingProfile(
            weekly_planner=weekly_planner
        )

        return self.__charging_profile

    @charging_profile.setter
    def charging_profile(self, value):
        """Prevents setting the 'charging_profile' property.

        To update this property, call update_charging_profile on the instance.

        Args:
            value: Doesn't matter; shouldn't make this call.

        Raises:
            TypeError: Raised every time.
        """

        raise TypeError(
            'Method not supported; call update_charging_profile() on the '
            'instance to refresh the profile'
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

    def lock_doors(self) -> dict:
        """Lock the vehicle's doors.

        Returns:
            Details of the lock command event.
        """

        return self.__execute_command('DOOR_LOCK')

    def precondition(self) -> dict:
        """Activate the vehicle's climate control.

        This command doesn't allow for setting a temperature or making other
        modifications; the system will be activated with the last settings in
        place.

        Returns:
            Details of the climate command event.
        """

        return self.__execute_command('CLIMATE_NOW')

    def charge(self) -> dict:
        """Start the vehicle's charging system, if inactive.

        If the vehicle is configured with a charging schedule and is not
        currently charging, this command starts charging manually.

        Returns:
            Details of the charge command event.
        """

        return self.__execute_command('CHARGE_NOW')

    def get_all_images(self) -> dict:
        """Get the images used for 360 view?

        My i3 doesn't support this service, so I have no means of testing and
        implementing.

        Raises:
            NotImplementedError: Currently raised in response to every call.
        """

        raise NotImplementedError('This command is not yet implemented.')

        return self.__execute_command('GET_ALL_IMAGES')

    def check_command_status(self, service_type: str) -> dict:
        """Check the current status of a prior-issued command.

        Commands are executed asynchronously; the API returns without waiting
        for a response. The status of a command can be checked by sending the
        type as a parameter. I've tested, and it appears that only the last
        event of a type is available to check. Passing eventId as a parameter
        will not retrieve the event details for a different command.

        Args:
            service_type: Command type, such as HORN_BLOW or LIGHT_FLASH.

        Returns:
            The current status of the command as returned by the API. The dict
            will look something like:

            {
                "executionStatus": {
                    "extendedStatus": {
                        "result": "STATUS_CHANGED"
                    },
                    "eventId": "<some string>@bmw.de",
                    "status": "EXECUTED",
                    "serviceType": "HORN_BLOW"
                }
            }

        Raises:
            HTTPError: The API doesn't have a record of a command of the passed
                       type.
        """

        api_endpoint = self.__API_ENDPOINT_TEMPLATE.format(
            vin=self.vin,
            endpoint='serviceExecutionStatus?serviceType={service_type}'.format(
                service_type=service_type
            )
        )

        try:
            return self.__api_client.call_endpoint(api_endpoint)
        except urllib.error.HTTPError:
            raise

    def get_image(self, view: str='FRONT', width: int=1024) -> bytes:
        """Get an image of the vehicle from the specified view.

        From my extremely limited testing, this appears to be accurate to the
        specific vehicle's options. My i3 shows up with the sport wheels,
        correct color, and without REx, as in real-life.

        Args:
            view: Angle of the image. Valid views known so far are FRONT, REAR,
                  and SIDE.
            width: Width of the returned image in pixels. I'm sure there are
                   bounds on the value, but I haven't tested extensively enough
                   to determine what they are.

        Returns:
            The requested image, in PNG format.
        """

        return self.__api_client.call_endpoint(
            self.__API_ENDPOINT_TEMPLATE.format(
                vin=self.vin,
                endpoint='image?view={view}&width={width}'.format(
                    view=view, width=width
                )
            ), parse_as_json=False
        )
