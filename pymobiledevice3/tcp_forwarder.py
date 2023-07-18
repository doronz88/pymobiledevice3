import logging
import select
import socket
import threading

from pymobiledevice3 import usbmux
from pymobiledevice3.exceptions import ConnectionFailedError
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.service_connection import LockdownServiceConnection


class TcpForwarder:
    """
    Allows forwarding local tcp connection into the device via a given lockdown connection
    """

    MAX_FORWARDED_CONNECTIONS = 200
    TIMEOUT = 1

    def __init__(self, src_port: int, dst_port: int, serial: str = None, enable_ssl=False,
                 listening_event: threading.Event = None, usbmux_connection_type: str = None):
        """
        Initialize a new tcp forwarder

        :param src_port: tcp port to listen on
        :param dst_port: tcp port to connect to each new connection via the supplied lockdown object
        :param serial: device serial
        :param enable_ssl: enable ssl wrapping for the transferred data
        :param listening_event: event to fire when the listening occurred
        :param usbmux_connection_type: preferred connection type
        """
        self.logger = logging.getLogger(__name__)
        self.serial = serial
        self.src_port = src_port
        self.dst_port = dst_port
        self.server_socket = None
        self.inputs = []
        self.enable_ssl = enable_ssl
        self.stopped = threading.Event()
        self.listening_event = listening_event
        self.usbmux_connection_type = usbmux_connection_type

        # dictionaries containing the required maps to transfer data between each local
        # socket to its remote socket and vice versa
        self.connections = {}

    def start(self, address='0.0.0.0'):
        """ forward each connection from given local machine port to remote device port """
        # create local tcp server socket
        self.server_socket = socket.socket()
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((address, self.src_port))
        self.server_socket.listen(self.MAX_FORWARDED_CONNECTIONS)
        self.server_socket.setblocking(False)

        self.inputs = [self.server_socket]
        if self.listening_event:
            self.listening_event.set()

        while self.inputs:
            # will only perform the socket select on the inputs. the outputs will handled
            # as synchronous blocking
            readable, writable, exceptional = select.select(self.inputs, [], self.inputs, self.TIMEOUT)
            if self.stopped.is_set():
                break

            closed_sockets = set()
            for current_sock in readable:
                if current_sock is self.server_socket:
                    self._handle_server_connection()
                else:
                    if current_sock not in closed_sockets:
                        try:
                            self._handle_data(current_sock, closed_sockets)
                        except ConnectionResetError:
                            self._handle_close_or_error(current_sock)

            for current_sock in exceptional:
                self._handle_close_or_error(current_sock)

        # on stop, close all currently opened sockets
        for current_sock in self.inputs:
            current_sock.close()

    def _handle_close_or_error(self, from_sock):
        """ if an error occurred its time to close the two sockets """
        other_sock = self.connections[from_sock]

        other_sock.close()
        from_sock.close()
        self.inputs.remove(other_sock)
        self.inputs.remove(from_sock)

        self.logger.info(f'connection {other_sock} was closed')

    def _handle_data(self, from_sock, closed_sockets):
        data = from_sock.recv(1024)

        if len(data) == 0:
            # no data means socket was closed
            self._handle_close_or_error(from_sock)
            closed_sockets.add(from_sock)
            closed_sockets.add(self.connections[from_sock])
            return

        # when data is received from one end, just forward it to the other
        other_sock = self.connections[from_sock]

        # send the data in blocking manner
        other_sock.setblocking(True)
        other_sock.sendall(data)
        other_sock.setblocking(False)

    def _handle_server_connection(self):
        """ accept the connection from local machine and attempt to connect at remote """
        local_connection, client_address = self.server_socket.accept()
        local_connection.setblocking(False)

        try:
            if self.enable_ssl:
                # use the lockdown pairing record
                lockdown = create_using_usbmux(self.serial, connection_type=self.usbmux_connection_type)
                service_connection = LockdownServiceConnection.create_using_usbmux(
                    self.serial, self.dst_port, connection_type=self.usbmux_connection_type)

                with lockdown.ssl_file() as ssl_file:
                    service_connection.ssl_start(ssl_file)

                remote_connection = service_connection.socket
            else:
                # connect directly using usbmuxd
                mux_device = usbmux.select_device(self.serial, connection_type=self.usbmux_connection_type)
                if mux_device is None:
                    raise ConnectionFailedError()
                remote_connection = mux_device.connect(self.dst_port)
        except ConnectionFailedError:
            self.logger.error(f'failed to connect to port: {self.dst_port}')
            local_connection.close()
            return

        remote_connection.setblocking(False)

        # append the newly created sockets into input list
        self.inputs.append(local_connection)
        self.inputs.append(remote_connection)

        # and store a map of which local connection is transferred to which remote one
        self.connections[remote_connection] = local_connection
        self.connections[local_connection] = remote_connection

        self.logger.info(f'connection established from local to remote port {self.dst_port}')

    def stop(self):
        """ stop forwarding """
        self.stopped.set()
