import collections

# It's nice to be exact; official SI unit conversion states that one inch is
# equal to 2.54 centimeters. This factor derives from that fact.
MILE_CONVERSION_FACTOR = 2.54 * 12 * 5280 / 100 / 1000


class Car(object):

    def __init__(
            self, api_client, car_data: dict, distance_unit: str='kilometers'):

        self.api_client = api_client
        self.distance_unit = distance_unit
        self.update_data(car_data)

    def update_data(self, car_data):

        for attribute in [
            'hood',
            'mileage',
            'steering',
            'trunk',
            'vin',
        ]:
            setattr(self, attribute, car_data[attribute])

        for attribute, source in {
            'charging_status': 'chargingStatus',
            'connection_status': 'connectionStatus',
            'parking_light': 'parkingLight',
            'update_time': 'updateTime',
        }.items():
            setattr(self, attribute, car_data[source])

        Doors = collections.namedtuple(
            'Doors', [
                'driver_front', 'driver_rear', 'passenger_front',
                'passenger_rear', 'locked',
            ]
        )
        doors_are_locked = car_data['doorLockState'] == 'SECURED'
        self.doors = Doors(
            car_data['doorDriverFront'], car_data['doorDriverRear'],
            car_data['doorPassengerFront'], car_data['doorPassengerRear'],
            doors_are_locked
        )

        Range = collections.namedtuple(
            'Range', [
                'fuel_level', 'max_electric', 'remaining_electric',
            ]
        )
        self.range = Range(
            car_data['remainingFuel'], car_data['maxRangeElectric'],
            car_data['remainingRangeElectric'],
        )

        Windows = collections.namedtuple(
            'Windows', [
                'driver_front', 'driver_rear', 'passenger_front',
                'passenger_rear',
            ]
        )
        self.windows = Windows(
            car_data['windowDriverFront'], car_data['windowDriverRear'],
            car_data['windowPassengerFront'], car_data['windowPassengerRear']
        )

        self.trunk = car_data['trunk']
