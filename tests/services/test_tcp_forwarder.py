import threading
from socket import socket

import pytest

from pymobiledevice3.lockdown import SERVICE_PORT, LockdownClient
from pymobiledevice3.tcp_forwarder import TcpForwarder

FREE_PORT = 3582


def attempt_local_connection(port: int):
    client = socket()
    client.connect(('127.0.0.1', port))
    client.close()


@pytest.mark.parametrize('dst_port', [FREE_PORT, SERVICE_PORT])
def test_tcp_forwarder_bad_port(lockdown: LockdownClient, dst_port: int):
    # start forwarder
    listening_event = threading.Event()
    forwarder = TcpForwarder(FREE_PORT, dst_port, listening_event=listening_event)
    thread = threading.Thread(target=forwarder.start)
    thread.start()

    # wait for it to actually start listening
    listening_event.wait()
    attempt_local_connection(FREE_PORT)

    # tell it to stop
    forwarder.stop()

    # make sure it stops
    thread.join()
