import logging
import plistlib
import select
import socket
import struct
import threading
from enum import Enum

from pymobiledevice3 import usbmux
from pymobiledevice3.exceptions import ConnectionFailedError, NoDeviceConnectedError, PyMobileDevice3Exception
from pymobiledevice3.service_connection import LockdownServiceConnection

CTRL_PORT = 0x43a  # 1082
CTRLCMD = b'BeginCtrl\0'
HELLOCTRLCMD = b'HelloCtrl\0'
HELLOCMD = b'HelloConn\0'

FDR_SYNC_MSG = 0x1
FDR_PROXY_MSG = 0x105
FDR_PLIST_MSG = 0xbbaa
CHUNK_SIZE = 1048576

conn_port = None

logger = logging.getLogger(__name__)


class fdr_type(Enum):
    FDR_CTRL = 1
    FDR_CONN = 2


class FDRClient:
    SERVICE_PORT = CTRL_PORT

    ctrlprotoversion = 2

    def __init__(self, type_: fdr_type, udid=None):
        global conn_port

        device = usbmux.select_device(udid)
        if device is None:
            if udid:
                raise ConnectionFailedError()
            else:
                raise NoDeviceConnectedError()

        logger.debug('connecting to FDR')

        if type_ == fdr_type.FDR_CTRL:
            self.service = LockdownServiceConnection.create_using_usbmux(
                device.serial, self.SERVICE_PORT, connection_type='USB'
            )
            self.ctrl_handshake()
        else:
            self.service = LockdownServiceConnection.create_using_usbmux(device.serial, conn_port, connection_type='USB')
            self.sync_handshake()

        logger.debug('FDR connected')

    def recv_plist(self):
        return self.service.recv_plist(endianity='<')

    def send_recv_plist(self, plist):
        return self.service.send_recv_plist(plist, endianity='<', fmt=plistlib.FMT_BINARY)

    def ctrl_handshake(self):
        global conn_port

        logger.debug('About to do ctrl handshake')

        self.service.sendall(CTRLCMD)

        if self.ctrlprotoversion != 2:
            raise NotImplementedError('TODO')

        req = {
            'Command': CTRLCMD,
            'CtrlProtoVersion': self.ctrlprotoversion,
        }
        resp = self.send_recv_plist(req)
        conn_port = resp['ConnPort']

        logger.debug(f'Ctrl handshake done (ConnPort = {conn_port})')

    def sync_handshake(self):
        self.service.sendall(HELLOCMD)

        if self.ctrlprotoversion != 2:
            raise NotImplementedError('TODO')

        reply = self.recv_plist()
        cmd = reply['Command']
        identifier = reply['Identifier']

        if cmd != 'HelloConn':
            raise PyMobileDevice3Exception('Did not receive HelloConn reply...')

        if identifier:
            logger.debug(f'got device identifier: {identifier}')

    def handle_sync_cmd(self):
        self.service.recvall(2)

        # Open a new connection and wait for messages on it
        logger.debug('FDR connected in reply to sync message, starting command thread')
        start_fdr_thread(fdr_type.FDR_CONN)

    def handle_proxy_cmd(self):
        buf = self.service.recv(1048576)
        logger.debug(f'got proxy command with {len(buf)} bytes')

        # Just return success here unconditionally because we don't know
        # anything else, and we will eventually abort on failure anyway
        self.service.sendall(struct.pack('<H', 5))

        if len(buf) < 3:
            logger.debug(f'FDR {self} proxy command data too short, retrying')
            return self.poll_and_handle_message()

        # ack command data too
        self.service.sendall(buf)

        host = None
        port = None

        # Now try to handle actual messages
        # Connect: 0 3 hostlen <host> <port>
        if buf[0] == 0 and buf[1] == 3:
            port = struct.unpack('>H', buf[-2:])[0]
            hostlen = buf[2]
            host = buf[3:3 + hostlen]

            logger.debug(f'FDR {self} Proxy connect request to {host}:{port}')

        if host is None:
            # missing or zero length host name
            return

        sockfd = socket.socket()
        sockfd.connect((host, port))

        while True:
            readable, writable, exceptional = select.select([sockfd, self.service.socket],
                                                            [],
                                                            [sockfd, self.service.socket])

            for current_sock in readable:
                if current_sock == self.service.socket:
                    buf = self.service.recv(CHUNK_SIZE)

                    logger.debug(f'FDR {self} got payload of {len(buf)} bytes, now try to proxy it')
                    logger.debug(f'Sending {len(buf)} bytes of data')

                    sockfd.sendall(buf)
                else:
                    buf = sockfd.recv(CHUNK_SIZE)
                    logger.debug(f'Received {len(buf)} bytes')
                    self.service.sendall(buf)

            if exceptional:
                if exceptional[0] == sockfd:
                    logger.debug('Remote closed the connection')
                else:
                    logger.debug('Local service closed the connection')
                break

        sockfd.close()
        self.service.close()

    def handle_plist_cmd(self):
        d = self.recv_plist()
        command = d['Command']

        if command == 'Ping':
            self.send_recv_plist({'Pong': True})
        else:
            logger.warning(f'FDR {self} received unknown plist command: {command}')

    def poll_and_handle_message(self):
        # TODO: is it okay?
        cmd = struct.unpack('<H', self.service.recvall(2))[0]

        handlers = {
            FDR_SYNC_MSG: self.handle_sync_cmd,
            FDR_PROXY_MSG: self.handle_proxy_cmd,
            FDR_PLIST_MSG: self.handle_plist_cmd,
        }

        if cmd in handlers:
            handlers[cmd]()
        else:
            logger.warning(f'ignoring FDR message: {cmd}')


def fdr_listener_thread(type_: fdr_type):
    try:
        client = FDRClient(type_)

        logger.debug(f'FDR {client} waiting for message...')

        while True:
            client.poll_and_handle_message()
    except ConnectionAbortedError:
        pass

    logger.debug(f'FDR {client} terminating...')


def start_fdr_thread(type_: fdr_type):
    thread = threading.Thread(target=fdr_listener_thread, args=(type_,))
    thread.start()
    return thread
