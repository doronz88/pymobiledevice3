import logging
import select
import socket
import threading
import time
from abc import abstractmethod
from typing import Optional

from pymobiledevice3 import usbmux
from pymobiledevice3.exceptions import ConnectionFailedError
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider


class TcpForwarderBase:
    """
    Allows forwarding local tcp connection into the device via a given lockdown connection
    """

    MAX_FORWARDED_CONNECTIONS = 200
    TIMEOUT = 1

    def __init__(self, src_port: int, listening_event: Optional[threading.Event] = None):
        """
        Initialize a new tcp forwarder

        :param src_port: tcp port to listen on
        :param enable_ssl: enable ssl wrapping for the transferred data
        :param listening_event: event to fire when the listening occurred
        """
        self.logger = logging.getLogger(__name__)
        self.src_port = src_port
        self.server_socket = None
        self.inputs = []
        self.stopped = threading.Event()
        self.listening_event = listening_event

        # dictionaries containing the required maps to transfer data between each local
        # socket to its remote socket and vice versa
        self.connections = {}

    def start(self, address="0.0.0.0"):
        """forward each connection from given local machine port to remote device port"""
        # create local tcp server socket
        self.server_socket = socket.socket()
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((address, self.src_port))
        self.server_socket.listen(self.MAX_FORWARDED_CONNECTIONS)
        self.server_socket.setblocking(False)

        self.inputs = [self.server_socket]
        if self.listening_event:
            self.listening_event.set()

        try:
            while self.inputs:
                # will only perform the socket select on the inputs. the outputs will handled
                # as synchronous blocking
                readable, _writable, exceptional = select.select(self.inputs, [], self.inputs, self.TIMEOUT)
                if self.stopped.is_set():
                    self.logger.debug("Closing since stopped is set")
                    break

                closed_sockets = set()
                for current_sock in readable:
                    self.logger.debug("Processing %r", current_sock)
                    if current_sock is self.server_socket:
                        self._handle_server_connection()
                    else:
                        if current_sock not in closed_sockets:
                            try:
                                self._handle_data(current_sock, closed_sockets)
                            except ConnectionResetError:
                                self.logger.error("Error when handling data")
                                self._handle_close_or_error(current_sock)
                        else:
                            self.logger.debug("Is closed")

                for current_sock in exceptional:
                    self.logger.error("Sock failed: %r", current_sock)
                    self._handle_close_or_error(current_sock)
        finally:
            self.logger.info("Closing everything")
            # on stop, close all currently opened sockets
            for current_sock in self.inputs:
                current_sock.close()

    def _handle_close_or_error(self, from_sock):
        """if an error occurred its time to close the two sockets"""
        other_sock = self.connections[from_sock]

        other_sock.close()
        from_sock.close()
        self.inputs.remove(other_sock)
        self.inputs.remove(from_sock)

        self.logger.info(f"connection {other_sock} was closed")

    def _handle_data(self, from_sock, closed_sockets):
        self.logger.debug(f"Handling data from {from_sock}")
        try:
            data = from_sock.recv(1024)
            if not data:
                raise ConnectionResetError("Connection closed by the peer.")
        except BlockingIOError:
            self.logger.warning(f"Non-blocking read failed on {from_sock}, retrying later.")
            return
        except OSError:
            self.logger.error(f"Error reading from socket {from_sock}")
            self._handle_close_or_error(from_sock)
            closed_sockets.add(from_sock)
            return

        other_sock = self.connections.get(from_sock)
        if not other_sock:
            self.logger.error(f"No connection mapping found for {from_sock}.")
            return

        try:
            total_sent = 0
            while total_sent < len(data):
                try:
                    sent = other_sock.send(data[total_sent:])
                    total_sent += sent
                except BlockingIOError:
                    self.logger.warning(f"Socket buffer full for {other_sock}, retrying in 100ms.")
                    time.sleep(0.1)  # Introduce a small delay
                except BrokenPipeError:
                    self.logger.error(f"Broken pipe error on {other_sock}.")
                    raise
        except OSError:
            self.logger.error("Unhandled error while forwarding data")
            self._handle_close_or_error(from_sock)
            closed_sockets.add(from_sock)
            closed_sockets.add(other_sock)

    @abstractmethod
    def _establish_remote_connection(self) -> socket.socket:
        pass

    def _handle_server_connection(self):
        """accept the connection from local machine and attempt to connect at remote"""
        local_connection, _client_address = self.server_socket.accept()
        local_connection.setblocking(False)

        try:
            remote_connection = self._establish_remote_connection()
        except ConnectionFailedError:
            self.logger.error(f"failed to connect to port: {self.dst_port}")
            local_connection.close()
            return

        remote_connection.setblocking(False)

        # append the newly created sockets into input list
        self.inputs.append(local_connection)
        self.inputs.append(remote_connection)

        # and store a map of which local connection is transferred to which remote one
        self.connections[remote_connection] = local_connection
        self.connections[local_connection] = remote_connection

        self.logger.info("connection established from local to remote")

    def stop(self):
        """stop forwarding"""
        self.stopped.set()


class UsbmuxTcpForwarder(TcpForwarderBase):
    """
    Allows forwarding local tcp connection into the device via a given lockdown connection
    """

    def __init__(
        self,
        serial: str,
        dst_port: int,
        src_port: int,
        listening_event: Optional[threading.Event] = None,
        usbmux_connection_type: Optional[str] = None,
        usbmux_address: Optional[str] = None,
    ):
        """
        Initialize a new tcp forwarder

        :param serial: device serial
        :param dst_port: tcp port to connect to each new connection via the supplied lockdown object
        :param src_port: tcp port to listen on
        :param listening_event: event to fire when the listening occurred
        :param usbmux_connection_type: preferred connection type
        :param usbmux_address: usbmuxd address
        """
        super().__init__(src_port, listening_event)
        self.serial = serial
        self.dst_port = dst_port
        self.usbmux_connection_type = usbmux_connection_type
        self.usbmux_address = usbmux_address

    def _establish_remote_connection(self) -> socket.socket:
        # connect directly using usbmuxd
        mux_device = usbmux.select_device(
            self.serial, connection_type=self.usbmux_connection_type, usbmux_address=self.usbmux_address
        )
        self.logger.debug("Selected device: %r", mux_device)
        if mux_device is None:
            raise ConnectionFailedError()
        return mux_device.connect(self.dst_port, usbmux_address=self.usbmux_address)


class LockdownTcpForwarder(TcpForwarderBase):
    """
    Allows forwarding local tcp connection into the device via a given lockdown connection
    """

    def __init__(
        self,
        service_provider: LockdownServiceProvider,
        src_port: int,
        service_name: str,
        listening_event: Optional[threading.Event] = None,
    ):
        """
        Initialize a new tcp forwarder

        :param src_port: tcp port to listen on
        :param service_name: service name to connect to
        :param listening_event: event to fire when the listening occurred
        """
        super().__init__(src_port, listening_event)
        self.service_provider = service_provider
        self.service_name = service_name

    def _establish_remote_connection(self) -> socket.socket:
        return self.service_provider.start_lockdown_developer_service(self.service_name).socket
