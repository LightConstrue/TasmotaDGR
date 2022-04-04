import logging
from time import sleep
from TasmotaDGR import DeviceGroup
import sys, signal

logging.basicConfig(level=logging.INFO)  

def signal_handler(signal, frame):
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def test_observer(devicegroup, **kwargs):
    if 'ready' in kwargs:
        logging.info('DeviceGroup %s is now ready for changes', devicegroup.name)
    if 'power' in kwargs:
        logging.info('DeviceGroup %s Power is now %s', devicegroup.name, kwargs.get('power'))
    if 'dimmer' in kwargs:
        logging.info('DeviceGroup %s Dimmer is now %s', devicegroup.name, kwargs.get('dimmer'))

# "boot device" with DevGroupName 'test', and state Power On and Dimmer 100%
# Said values only stick if no other tasmota devices are online after a timeout.
testgroup = DeviceGroup('test') # ('test', power=True, dimmer=100)

# call our test_observer method when other tasmota devices in the devicegroup change the state
testgroup.add_observer(test_observer)

# Await either discovery of other tasmota devices in a devicegroup,
# or by timeout make self the source of truth for the devicegroup
while not testgroup.ready: 
    sleep(.1)

while True:
    logging.info('Setting dimmer to 50')
    testgroup.dimmer = 50

    sleep(2)

    logging.info('Setting dimmer to 100')
    testgroup.dimmer = 100

    sleep(2)

    logging.info('Setting power to false')
    testgroup.power = False

    sleep(2)

    logging.info('Setting power to true')
    testgroup.power = True

    sleep(2)

testgroup.shutdown()

