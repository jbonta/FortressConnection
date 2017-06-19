#!/usr/local/bin/python
# coding: utf-8
#
################################################################################
# Handles connection to Fortress Security's "total wifi" panel.
# Provides reading status, setting status, detecting immediate alarm (and zone).
#
# === Usage: ===
# fortress = FortressConnection()
# fortress.work()
# fortress.onErrorChange = errorCallback # takes a boolean isGood argument
# fortress.onStatusChange = self.fireStatusChanges # takes a status argument [ARM, DISARM, STAY_ARM]
# fortress.onAlarmChange = self.fireAlarmChanges # takes boolean isAlarming and zoneNumber args
#
# === How to send a command to Fortress: ===
# fortress.sendCommand(FortressConnection.DISARM)
#
################################################################################

from datetime import datetime
import select
import socket
import sys
import threading
import traceback
from RepeatingTimer import RepeatingTimer
from LoggerMixin import LoggerMixin

FORTRESS_IP = '192.168.1.73'
TCP_PORT = 12416
HEARTBEAT_INTERVAL = 4
TIMEOUT_AFTER = 9
RETRY_AFTER_ERROR = 3

HANDSHAKE = b'\x00\x00\x00\x03\x0f\x00\x00\x08\x00\x0a\x4a\x51\x45\x42\x53\x53\x42\x4f\x4c\x41'
BIND_ME = b'\x00\x00\x00\x03\x04\x00\x00\x90\x02'
CONNECTION_IS_BOUND = b'\x00\x00\x00\x03\x04\x00\x00\x09\x00'
HEARTBEAT = b'\x00\x00\x00\x03\x03\x00\x00\x15'
HEARTBEAT_ACK = b'\x00\x00\x00\x03\x03\x00\x00\x16'
COMMAND = b'\x00\x00\x00\x03\x57\x00\x00\x90\x01\x00\x10\x00\x00'

ALARMING = b'\x01'

def _to_bin_char(ch):
    return bytes(chr(ch), 'utf-8')

class FortressConnection(LoggerMixin):
    DISARM = b'\x10'
    ARM = b'\x00'
    STAY_ARM = b'\x20'

    def __init__(self):
        self.timeout_timer = None
        self.fortress_socket = None
        self.arm_status = None
        self.alarming = None
        self.heartbeat_timer = None
        self.all_good = False
        self.count = 0
        self._onStatusChange = None
        self._onErrorChange = None
        self._onAlarmChange = None

    @property
    def onErrorChange(self): return self._onErrorChange
    @onErrorChange.setter
    def onErrorChange(self, cb): self._onErrorChange = cb
    @property
    def onAlarmChange(self): return self._onAlarmChange
    @onAlarmChange.setter
    def onAlarmChange(self, cb): self._onAlarmChange = cb
    @property
    def onStatusChange(self): return self._onStatusChange
    @onStatusChange.setter
    def onStatusChange(self, cb): self._onStatusChange = cb

    def isAllGood(self):
        return self.all_good

    def getStatus(self):
        return self.arm_status

    def isAlarming(self):
        return self.alarming

    def sendCommand(self, msg):
        self._send_to_socket(COMMAND + msg + b'\x00' * 78)

    def work(self):
        try:
            self.fortress_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.fortress_socket.connect((FORTRESS_IP, TCP_PORT))
            self._send_to_socket(HANDSHAKE)
            self._send_to_socket(BIND_ME)
            self._info('------------------------- Connected to Fortress')
            self._set_all_good(True)
            self._reschedule_reconnect()
            self.heartbeat_timer = RepeatingTimer(HEARTBEAT_INTERVAL, self._send_heartbeat)
            self.heartbeat_timer.start()
        except:
            self._reschedule_reconnect_asap()
            self._info("error occurred in work")
            self._debug(traceback.format_exc())
            return
        while self.all_good:
            try:
                ready_to_read,_,_ = select.select(
                    [self.fortress_socket], [], [], TIMEOUT_AFTER
                )
                if not ready_to_read: # a timeout occurred on the select()
                    return
                data = self.fortress_socket.recv(1024)
                self._process_update(data)
            except KeyboardInterrupt:
                self._tear_down()
                sys.exit()
                return
            except SystemExit:
                return
            except:
                self._info("error occurred in loop")
                self._debug(traceback.format_exc())
                self._reschedule_reconnect_asap()
                return

    def _set_all_good(self, isGood):
        self.all_good = isGood
        if self.onErrorChange:
            self.onErrorChange(self.all_good)

    def _reschedule_reconnect_asap(self):
        self._set_all_good(False)
        self._clear_timers()
        self.timeout_timer = threading.Timer(
            RETRY_AFTER_ERROR,
            self._reconnect,
            ['...AFTER EXCEPTION']
        )
        self.timeout_timer.start()

    def _reschedule_reconnect(self):
        if self.timeout_timer:
            self.timeout_timer.cancel()
            self.timeout_timer = None
        self.timeout_timer = threading.Timer(TIMEOUT_AFTER, self._reconnect)
        self.timeout_timer.start() # expecting this to get canceled

    def _send_heartbeat(self):
        if self.count % 900 == 0:
            self._info('★ Alive checkpoint:', str(threading.active_count()), 'threads')
        if self.count % 10 == 0:
            print('\x1b[2K\r', end='') # clear existing line
            print(datetime.now().strftime('%m-%d %H:%M:%S'), end=' ')
            print('Sending heartbeat: ', end='')
        print('♥', end='')
        sys.stdout.flush()
        self.count += 1
        self._send_to_socket(HEARTBEAT)

    def _send_to_socket(self, msg):
        self.fortress_socket.send(msg)

    def _process_update(self, data):
        if not data or len(data) != 182 and len(data) != 8 and data != CONNECTION_IS_BOUND:
            self._info("UNEXPECTED data", len(data) if data else 0)
            self._debug(data)
            self._reschedule_reconnect_asap()
            return
        if data.find(HEARTBEAT_ACK) != -1:
            print('√', end='')
            sys.stdout.flush()
            self._reschedule_reconnect()
        if len(data) == 182:
            now_alarming = _to_bin_char(data[181]) == ALARMING
            status_and_outlets = int.from_bytes(data[10:13], byteorder='big')
            # first 4 bits of this 24-bit status_and_outlets are the arm status,
            # storing 0, 1, or 2. Next 20 are the 20 smart outlets.
            # so to get the status of outlet 1: status_and_outlets >> 20 & 1
            # so to get the status of outlet 9: status_and_outlets >> 12 & 1

            # extract the 0, 1, or 2 and convert to b'\x00', b'\x010', or b'\x020':
            latest_arm_status = _to_bin_char(status_and_outlets >> 20 << 4)
            zone = _to_bin_char(data[89])
            if latest_arm_status != self.arm_status:
                self._set_arm_status(latest_arm_status)
            if now_alarming != self.alarming:
                if not self.alarming or latest_arm_status == FortressConnection.DISARM:
                    # don't trust now_alarming==false unless also in disarmed state
                    self._set_alarming(now_alarming, zone)

    def _set_alarming(self, cur_alarming, zone=b'\x00'):
        zone = int.from_bytes(zone, byteorder='big')
        self.alarming = cur_alarming
        if self.alarming:
            self._debug("=========== ALARM IN ZONE: ", zone)
        else:
            self._debug("not alarming")
        if self.onAlarmChange:
            self.onAlarmChange(self.alarming, zone)

    def _set_arm_status(self, cur_arm_status):
        self.arm_status = cur_arm_status
        if self.arm_status == FortressConnection.ARM:
            self._info("🔒  Arm status: Armed")
        if self.arm_status == FortressConnection.DISARM:
            self._info("🔒  Arm status: Disarmed")
        if self.arm_status == FortressConnection.STAY_ARM:
            self._info("🔒  Arm status: Stay armed")
        if self.onStatusChange:
            self._onStatusChange(self.arm_status)

    def _clear_timers(self):
        if self.timeout_timer:
            self.timeout_timer.cancel()
            self.timeout_timer = None
        if self.heartbeat_timer:
            self.heartbeat_timer.cancel()
            self.heartbeat_timer = None

    def _tear_down(self):
        self._debug("closing everything ****")
        self._set_all_good(False)
        self.count = 0
        self.arm_status = None
        self._set_alarming(None)
        if self.fortress_socket:
            self.fortress_socket.shutdown(socket.SHUT_WR)
            self.fortress_socket.close()
            self.fortress_socket = None
        self._clear_timers()

    def _reconnect(self, more_info = ''):
        self._info('RECONNECTING' + more_info)
        self._tear_down()
        self.work()
