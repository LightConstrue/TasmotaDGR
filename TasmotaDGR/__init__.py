# TasmotaDGR Module
# -*- coding: utf-8 -*-
"""
 Python module to interface with Tasmota Device Groups
 Author: MoogleTroupe, Tediore
 For more information see https://github.com/LightConstrue/TasmotaDGR
 
 Credits
  * Tasmota Device Groups https://github.com/arendst/Tasmota/blob/development/tasmota/support_device_groups.ino by pcdiem
"""

# Copyright 2022 MoogleTroupe, Tediore
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import logging
import queue
import signal
import socket
import struct
import sys
import threading
import enum
import time
import traceback
import re
import signal
import typing

version_tuple = (0, 0, 1)
version = __version__ = "%d.%d.%d" % version_tuple
__author__ = "MoogleTroupe, Tediore"
__name__ = "TasmotaDGR"

_MCAST_PORT = 4447
_MCAST_ADDR = "239.255.250.250"

_log = logging.getLogger(__name__)

_log.debug("%s version %s", __name__, __version__)
_log.debug("Python %s on %s", sys.version, sys.platform)

_active_devicegroups = []
_change_queue: queue.Queue(typing.Dict[str, typing.Any]) = queue.Queue()  # type: ignore

__exit_event = threading.Event()
def __signal_handler(signum, frame):
    __exit_event.set()
signal.signal(signal.SIGINT, __signal_handler)

def __udp_manager():
    _log.info("Starting DeviceGroups Manager")

    class DevGroupRelayPoweredOn(enum.IntFlag):
        DGR_RELAY_NONE = 0
        DGR_RELAY_1 = 1
        DGR_RELAY_2 = 2
        DGR_RELAY_3 = 4
        DGR_RELAY_4 = 8
        DGR_RELAY_5 = 16
        DGR_RELAY_6 = 32
        DGR_RELAY_7 = 64
        DGR_RELAY_8 = 128
        DGR_RELAY_9 = 256
        DGR_RELAY_10 = 512
        DGR_RELAY_11 = 1024
        DGR_RELAY_12 = 2048
        DGR_RELAY_13 = 4096
        DGR_RELAY_14 = 8192
        DGR_RELAY_15 = 16384
        DGR_RELAY_16 = 32768
        DGR_RELAY_17 = 65536
        DGR_RELAY_18 = 131072
        DGR_RELAY_19 = 262144
        DGR_RELAY_20 = 524288
        DGR_RELAY_21 = 1048576
        DGR_RELAY_22 = 2097152
        DGR_RELAY_23 = 4194304
        DGR_RELAY_24 = 8388608

    class DevGroupMessageFlag(enum.IntFlag):
        DGR_FLAG_NONE = 0
        DGR_FLAG_RESET = 1
        DGR_FLAG_STATUS_REQUEST = 2
        DGR_FLAG_FULL_STATUS = 4
        DGR_FLAG_ACK = 8
        DGR_FLAG_MORE_TO_COME = 16
        DGR_FLAG_DIRECT = 32
        DGR_FLAG_ANNOUNCEMENT = 64
        DGR_FLAG_LOCAL = 128

    class DevGroupItem(enum.IntEnum):
        DGR_ITEM_EOL = 0
        DGR_ITEM_STATUS = 1
        DGR_ITEM_FLAGS = 2
        DGR_ITEM_LIGHT_FADE = 3
        DGR_ITEM_LIGHT_SPEED = 4
        DGR_ITEM_LIGHT_BRI = 5 # Value = 0-100
        DGR_ITEM_LIGHT_SCHEME = 6
        DGR_ITEM_LIGHT_FIXED_COLOR = 7
        DGR_ITEM_BRI_PRESET_LOW = 8
        DGR_ITEM_BRI_PRESET_HIGH = 9
        DGR_ITEM_BRI_POWER_ON = 10 # Value = 0-100
        DGR_ITEM_LAST_8BIT = 11
        DGR_ITEM_MAX_8BIT = 63

        DGR_ITEM_LAST_16BIT = 64
        DGR_ITEM_MAX_16BIT = 127

        DGR_ITEM_POWER = 128 # Value = (DevGroupRelayPoweredOn, total count of relays)
        DGR_ITEM_NO_STATUS_SHARE = 129
        DGR_ITEM_LAST_32BIT = 130
        DGR_ITEM_MAX_32BIT = 191

        DGR_ITEM_EVENT = 192
        DGR_ITEM_COMMAND = 193
        DGR_ITEM_LAST_STRING = 194
        DGR_ITEM_MAX_STRING = 223

        DGR_ITEM_LIGHT_CHANNELS = 224 # Value = [red, green, blue]
        DGR_ITEM_LAST_ARRAY = 225
        DGR_ITEM_MAX_ARRAY = 255

    class DevGroupPacket(object):
        def __init__(self, **kwargs):
          self.name: str = kwargs.get("name", "tasmotas")
          self.sequence: int = kwargs.get("sequence", 1)
          self.flags: DevGroupMessageFlag = kwargs.get("flags", DevGroupMessageFlag.DGR_FLAG_NONE)
          self.mailbox: typing.List[typing.Tuple[DevGroupItem,typing.Any]] = kwargs.get("mailbox", [])

        def encode(self):
            data = bytearray()
            data += struct.pack('<11s', str.encode('TASMOTA_DGR'))
            data += struct.pack('<{}sx'.format(len(self.name)), str.encode(self.name))
            data += struct.pack('<HH',self.sequence,self.flags.value)
            if (len(self.mailbox) > 0):
                for mail in self.mailbox:
                    flag = mail[0]
                    value = mail[1]
                    if (flag < DevGroupItem.DGR_ITEM_MAX_8BIT):
                        if (flag == DevGroupItem.DGR_ITEM_LIGHT_BRI or flag == DevGroupItem.DGR_ITEM_BRI_POWER_ON):
                            data += struct.pack('<BB', flag.value, round(value * 255.0 / 100.0))
                        else:
                            data += struct.pack('<BB',flag.value,value)
                    elif (flag < DevGroupItem.DGR_ITEM_MAX_16BIT):
                        data += struct.pack('<BH',flag.value,value)
                    elif (flag < DevGroupItem.DGR_ITEM_MAX_32BIT):
                        if (flag == DevGroupItem.DGR_ITEM_POWER):
                            data += struct.pack('<BBBBB', flag.value, value[0] & 0xff, (value[0] >> 8) & 0xff, (value[0] >> 16) & 0xff, value[1])
                        else:
                            data += struct.pack('<BI',flag.value,value)
                    elif (flag < DevGroupItem.DGR_ITEM_MAX_STRING):
                        data += struct.pack('<BB{}sx'.format(len(value)),flag.value,len(value),value)
                    else:
                        data += struct.pack('<BB{}Bx'.format(len(value)),flag.value,len(value),*value)
                data += struct.pack('<B',DevGroupItem.DGR_ITEM_EOL)
            data = bytes(data)
            _log.debug("Encoded packet Data: %s", data)
            return bytes(data)

        def decode(self, data):
            data = bytearray(data)
            del data[:11]

            self.name = ''
            for byte in data:
                if (byte == 0): break
                self.name+=chr(byte)
            del data[:len(self.name)+1]

            self.sequence, flags = struct.unpack("<HH", data[:4])
            self.flags = DevGroupMessageFlag(flags)
            del data[:4]

            while len(data)>0:
                flag = DevGroupItem(int.from_bytes(data[:1], "little", signed=False))
                if (flag == DevGroupItem.DGR_ITEM_EOL):
                    del data[:1]
                    break
                elif (flag < DevGroupItem.DGR_ITEM_MAX_8BIT):
                    if (flag == DevGroupItem.DGR_ITEM_LIGHT_BRI or flag == DevGroupItem.DGR_ITEM_BRI_POWER_ON):
                        self.mailbox.append((flag,round(int.from_bytes(data[1:2], "little", signed=False) * 100.0 / 255.0)))
                    else:
                        blah = int.from_bytes(data[1:2], "little", signed=False)
                        self.mailbox.append((flag,blah))
                    del data[:2]
                elif (flag < DevGroupItem.DGR_ITEM_MAX_16BIT):
                    self.mailbox.append((flag,int.from_bytes(data[1:3], "little", signed=False)))
                    del data[:3]
                elif (flag < DevGroupItem.DGR_ITEM_MAX_32BIT):
                    if (flag == DevGroupItem.DGR_ITEM_POWER):
                        self.mailbox.append((flag,(DevGroupRelayPoweredOn(int.from_bytes(data[1:4], "little", signed=False)), int.from_bytes(data[4:5], "little", signed=False))))
                    else:
                        self.mailbox.append((flag,int.from_bytes(data[1:5], "little", signed=False)))
                    del data[:5]
                elif (flag < DevGroupItem.DGR_ITEM_MAX_STRING):
                    length = int.from_bytes(data[1:2], "little", signed=False)
                    string_value = ''
                    for byte in data[2:length-1]:
                        string_value+=chr(byte)
                    self.mailbox.append((flag,string_value))
                    del data[:2+length]
                else:
                    length = int.from_bytes(data[1:2], "little", signed=False)
                    int_array = []
                    for byte in data[2:length-1]:
                        int_array.append(byte)
                    self.mailbox.append((flag,int_array))
                    del data[:2+length]

            _log.debug('Decoded packet: DeviceGroup: %s  Sequence: %s  Flags: %s  MailBox: %s', self.name, self.sequence, self.flags, self.mailbox)

    def validate(data):
        if (len(data) > 16):
            header = ''
            for byte in data[:11]:
                header+=chr(byte)
            if (header == "TASMOTA_DGR"):
                name = ''
                for byte in data[11:]:
                    if (byte == 0): break
                    name+=chr(byte)
                if (any(devicegroup.name == name for devicegroup in _active_devicegroups)):
                    return True
        return False

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, struct.pack('b', 1))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
    sock.bind(('0.0.0.0', _MCAST_PORT))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(_MCAST_ADDR) + socket.inet_aton('0.0.0.0'))

    while True:
        try:
            data, addr = sock.recvfrom(2048)
        except socket.error:
            pass
        else:
            try:
                if (validate(data)):
                    remoteip = addr[0]
                    _log.debug("Recieved packet From: %s Data: %s", remoteip, data)
                    packet = DevGroupPacket()
                    packet.decode(data)

                    try:
                        devicegroup: DeviceGroup = next((devicegroup for devicegroup in _active_devicegroups if devicegroup.name == packet.name))
                    except:
                        pass
                    else:
                        if DevGroupMessageFlag.DGR_FLAG_ACK in packet.flags:
                            pass
                        
                        if (remoteip not in devicegroup._members):
                            devicegroup._members[remoteip] = packet.sequence

                        if DevGroupMessageFlag.DGR_FLAG_RESET in packet.flags:
                            devicegroup._members[remoteip] = 1

                        if (devicegroup._members[remoteip] - 100 > packet.sequence):
                            devicegroup._members[remoteip] = packet.sequence - 1

                        if DevGroupMessageFlag.DGR_FLAG_MORE_TO_COME not in packet.flags:
                            replydata = DevGroupPacket(name=packet.name, sequence=packet.sequence, flags=DevGroupMessageFlag.DGR_FLAG_ACK).encode()
                            if (validate(replydata)):
                                sock.sendto(replydata, addr)
                                sock.sendto(replydata, addr)

                        if DevGroupMessageFlag.DGR_FLAG_STATUS_REQUEST in packet.flags:
                            replypacket = DevGroupPacket(name=devicegroup._name, sequence=devicegroup._sequence)
                            replypacket.mailbox.append((DevGroupItem.DGR_ITEM_LIGHT_BRI,devicegroup._dimmer))
                            replypacket.mailbox.append((DevGroupItem.DGR_ITEM_POWER,(DevGroupRelayPoweredOn.DGR_RELAY_1 if devicegroup._power else DevGroupRelayPoweredOn.DGR_RELAY_NONE, 1)))
                            replydata = packet.encode()
                            if (validate(replydata)):
                                sock.sendto(replydata, (_MCAST_ADDR, _MCAST_PORT))
                                sock.sendto(replydata, (_MCAST_ADDR, _MCAST_PORT))
                                sock.sendto(replydata, addr)

                        if DevGroupMessageFlag.DGR_FLAG_FULL_STATUS in packet.flags and packet.sequence > devicegroup._members[remoteip]:
                            devicegroup._members[remoteip] = packet.sequence

                            if not devicegroup._ready:
                                if DevGroupItem.DGR_ITEM_LIGHT_BRI in packet.mailbox:
                                    devicegroup._dimmer = packet.mailbox[DevGroupItem.DGR_ITEM_LIGHT_BRI][1]

                                if DevGroupItem.DGR_ITEM_POWER in packet.mailbox:
                                    relays = packet.mailbox[DevGroupItem.DGR_ITEM_POWER][1]
                                    if DevGroupRelayPoweredOn.DGR_RELAY_1 in relays[0]:
                                        devicegroup._power = True
                                    else:
                                        devicegroup._power = False

                                devicegroup._set_ready(True)

                        if DevGroupMessageFlag.DGR_FLAG_NONE in packet.flags and packet.sequence > devicegroup._members[remoteip]:
                            devicegroup._members[remoteip] = packet.sequence

                            if DevGroupItem.DGR_ITEM_LIGHT_BRI in packet.mailbox:
                                if devicegroup._dimmer != packet.mailbox[DevGroupItem.DGR_ITEM_LIGHT_BRI]:
                                    devicegroup._set_dimmer(packet.mailbox[DevGroupItem.DGR_ITEM_LIGHT_BRI])

                            if DevGroupItem.DGR_ITEM_POWER in packet.mailbox:
                                relays = packet.mailbox[DevGroupItem.DGR_ITEM_POWER][1]
                                if DevGroupRelayPoweredOn.DGR_RELAY_1 in relays[0] and devicegroup._power == False:
                                    devicegroup._set_power(True)
                                elif devicegroup._power == True:
                                    devicegroup._set_power(False)
 
            except:
                _log.error("Error in packet: From: %s Data: %s %s", addr[0], data, traceback.format_exc())
        
        for devicegroup in _active_devicegroups:
            try:
                if (devicegroup._last_announcement_time == 0):
                    packet = DevGroupPacket(name=devicegroup._name, flags=DevGroupMessageFlag.DGR_FLAG_RESET | DevGroupMessageFlag.DGR_FLAG_STATUS_REQUEST)
                    data = packet.encode()
                    if (validate(data)):
                        sock.sendto(data, (_MCAST_ADDR, _MCAST_PORT))
                    packet.flags = DevGroupMessageFlag.DGR_FLAG_STATUS_REQUEST
                    data = packet.encode()
                    if (validate(data)):
                        sock.sendto(data, (_MCAST_ADDR, _MCAST_PORT))
                        sock.sendto(data, (_MCAST_ADDR, _MCAST_PORT))
                    devicegroup._last_announcement_time = time.perf_counter_ns()
                
                if (time.perf_counter_ns() / 1000000 - 59000 > devicegroup._last_announcement_time / 1000000):
                    packet = DevGroupPacket(name=devicegroup._name, sequence=devicegroup._sequence, flags=DevGroupMessageFlag.DGR_FLAG_ANNOUNCEMENT)
                    data = packet.encode()
                    if (validate(data)):
                        sock.sendto(data, (_MCAST_ADDR, _MCAST_PORT))
                    devicegroup._last_announcement_time = time.perf_counter_ns()
            except:
                _log.error("Error in checking DeviceGroup %s", traceback.format_exc())

        while (not _change_queue.empty()):
            try:
                changeset = _change_queue.get_nowait()
                try:
                    devicegroup: DeviceGroup = changeset['devicegroup']
                    devicegroup._sequence += 1
                    packet = DevGroupPacket(name=devicegroup._name, sequence=devicegroup._sequence)
                    if 'dimmer' in changeset:
                        packet.mailbox.append((DevGroupItem.DGR_ITEM_LIGHT_BRI,changeset.get('dimmer')))
                    if 'power' in changeset:
                        packet.mailbox.append((DevGroupItem.DGR_ITEM_POWER,(DevGroupRelayPoweredOn.DGR_RELAY_1 if changeset.get('power') else DevGroupRelayPoweredOn.DGR_RELAY_NONE, 1)))
                    data = packet.encode()
                    if (validate(data)):
                        sock.sendto(data, (_MCAST_ADDR, _MCAST_PORT))
                        sock.sendto(data, (_MCAST_ADDR, _MCAST_PORT))
                except:
                    _log.error("Error processing queue message %s", traceback.format_exc())
            except:
                pass

        if __exit_event.is_set():
            break

__udp_manager_task = threading.Thread(target=__udp_manager)
__udp_manager_task.start()

# Tasmota does not filter this, for example setting a space in the dev group name will crash the device.
# Add to this regex if other ascii characters are known to be safe.
_valid_devicegroup_name_regex = "[a-zA-Z0-9_-]+"
_valid_devicegroup_name = re.compile(_valid_devicegroup_name_regex)

class DeviceGroup(object):

    def __init__(self, name, **kwargs):

        if (not _valid_devicegroup_name.fullmatch(name)):
            raise ValueError('DeviceGroup name \'%s\' is invalid. It must match this regex: \'%s\'' % name, _valid_devicegroup_name_regex)
        if (len(name) < 1 or len(name) > 150):
            raise ValueError('DeviceGroup name \'%s\' is invalid. It must be between 1 and 150 characters' % name)
        if (any(device_group.name == name for device_group in _active_devicegroups)):
            raise ValueError('DeviceGroup name \'%s\' is already active.' % name)

        _log.debug('Initializing DeviceGroup \'%s\'.' % name)

        self._last_announcement_time: int = 0
        self._ready: bool = False
        self._sequence: int = 1
        self._members: typing.Dict[str, int] = {}
        self._observers = []
        self._name: str = name
        self._power: bool = True
        self._dimmer: int = 100

        self._set_power(kwargs.get("power", True))
        self._set_dimmer(kwargs.get("dimmer", 100))

        _active_devicegroups.append(self)
    
    def shutdown(self):
        self._ready = False
        self._sequence = 1
        self._observers.clear()
        self._members.clear()
        if (any(device_group.name == self.name for device_group in _active_devicegroups)):
            _active_devicegroups.remove(self)

    @property
    def name(self):
        return self._name

    def _set_ready(self, value):
        self._ready = value
        changeset = dict(devicegroup=self, ready=self._ready, power=self._power, dimmer=self._dimmer)
        for observer in self._observers:
            try:
                observer(**changeset)
            except:
                _log.error("Error alerting an observer of a DeviceGroup change: %s", traceback.format_exc())

    @property
    def ready(self):
        return self._ready

    def _set_power(self, value):
        if (isinstance(value, str)):
            if (value.lower() == 'on'):
                value = True
            elif (value.lower() == 'off'):
                value = False
            else:
                raise ValueError('DeviceGroup power value \'%s\' is invalid. It must be a bool, int 0 or 1, or string \'on\' or \'off\'.' % value)
        elif (isinstance(value, int)):
            if (value == 1):
                value = True
            elif (value == 0):
                value = False
            else:
                raise ValueError('DeviceGroup power value \'%s\' is invalid. It must be a bool, int 0 or 1, or string \'on\' or \'off\'.' % value)
        elif (not isinstance(value, bool)):
            raise ValueError('DeviceGroup power value \'%s\' is invalid. It must be a bool, int 0 or 1, or string \'on\' or \'off\'.' % value)

        self._power = value
        changeset = dict(devicegroup=self, power=self._power)
        for observer in self._observers:
            try:
                observer(**changeset)
            except:
                _log.error("Error alerting an observer of a DeviceGroup change: %s", traceback.format_exc())
        return(changeset)

    @property
    def power(self):
        return self._power

    @power.setter
    def power(self, value):
        if (not self._ready):
            raise ValueError('DeviceGroup is not ready for changes yet.')

        _change_queue.put_nowait(self._set_power(value))

    def _set_dimmer(self, value):
        if (not isinstance(value, int)):
            raise ValueError('DeviceGroup dimmer value \'%s\' is invalid. It must be an int between 0 and 100.' % value)
        if (value < 0 or value > 100):
            raise ValueError('DeviceGroup dimmer value \'%s\' is invalid. It must be an int between 0 and 100.' % value)
        
        self._dimmer = value
        changeset = dict(devicegroup=self, dimmer=self._dimmer)  # type: ignore
        for observer in self._observers:
            try:
                observer(**changeset)
            except:
                _log.error("Error alerting an observer of a DeviceGroup change: %s", traceback.format_exc())
        return(changeset)

    @property
    def dimmer(self):
        return self._dimmer

    @dimmer.setter
    def dimmer(self, value):
        if (not self._ready):
            raise ValueError('DeviceGroup is not ready for changes yet.')

        _change_queue.put_nowait(self._set_dimmer(value))

    def add_observer(self, observer):
        self._observers.append(observer)
