import logging
import socket
import select

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.service_connection import ServiceConnection, ConnectionFailedException


class TcpForwarder:
    MAX_FORWARDED_CONNECTIONS = 200

    def __init__(self, lockdown: LockdownClient, src_port: int, dst_port: int):
        self.logger = logging.getLogger(__name__)
        self.lockdown = lockdown
        self.src_port = src_port
        self.dst_port = dst_port
        self.inputs = []

        # dictionaries containing the required maps to transfer data between each local
        # socket to its remote socket and vice versa
        self.connections = {}

    def start(self):
        """
        forward each connection from given local machine port to remote device port
        """
        # create local tcp server socket
        self.server_socket = socket.socket()
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(('0.0.0.0', self.src_port))
        self.server_socket.listen(self.MAX_FORWARDED_CONNECTIONS)
        self.server_socket.setblocking(False)

        self.inputs = [self.server_socket]

        local_connection = None
        remote_connection = None

        while self.inputs:
            # will only perform the socket select on the inputs. the outputs will handled
            # as synchronous blocking
            readable, writable, exceptional = select.select(self.inputs, [], self.inputs)

            for current_sock in readable:
                if current_sock is self.server_socket:
                    self._handle_server_connection()
                else:
                    self._handle_data(current_sock)

            for current_sock in exceptional:
                self._handle_close_or_error(current_sock)

    def _handle_close_or_error(self, from_sock):
        # if an error occurred its time to close the two sockets
        other_sock = self.connections[current_sock]

        other_sock.close()
        current_sock.close()
        inputs.remove(other_sock)
        inputs.remove(current_sock)

        self.logger.info(f'connection {other_sock} was closed')

    def _handle_data(self, from_sock):
        data = from_sock.recv(1024)

        if data is None:
            # no data means socket was closed
            self._handle_close_or_error()
            return

        # when data is received from one end, just forward it to the other
        other_sock = self.connections[from_sock]

        # send the data in blocking manner
        other_sock.setblocking(True)
        other_sock.sendall(data)
        other_sock.setblocking(False)

    def _handle_server_connection(self):
        # accept the connection from local machine and attempt to connect at remote
        local_connection, client_address = self.server_socket.accept()
        local_connection.setblocking(False)

        try:
            remote_connection = ServiceConnection.create(self.lockdown.udid, self.dst_port).socket
        except ConnectionFailedException:
            self.logger.error(f'failed to connect to port: {self.dst_port}')
            local_connection.close()
        remote_connection.setblocking(False)

        # append the newly created sockets into input list
        self.inputs.append(local_connection)
        self.inputs.append(remote_connection)

        # and store a map of which local connection is transferred to which remote one
        self.connections[remote_connection] = local_connection
        self.connections[local_connection] = remote_connection

        self.logger.info(f'connection established from local to remote port {self.dst_port}')
