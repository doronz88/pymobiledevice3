from construct import Container, ListContainer

from pymobiledevice3.services.dvt.instruments.kdebug_events_parser import KdebugEventsParser, BscOpenFlags
from pymobiledevice3.services.dvt.instruments.device_info import DeviceInfo
from pymobiledevice3.services.dvt.dvt_secure_socket_proxy import DvtSecureSocketProxyService


def test_parsing_bsc_open(lockdown):
    """
    Test parsing BSC_open.
    :param pymobiledevice3.lockdown.LockdownClient lockdown: Lockdown client.
    """
    events = [
        Container({
            'timestamp': 458577723780, 'args': Container(
                data=(b'\x88\x95\xd7m\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                      b'\x00\x00\x00\x00P\x88\xd7m\x01\x00\x00\x00'),
                value=ListContainer([6137812360, 0, 0, 6137808976]), offset1=245320, offset2=245352, length=32),
            'tid': 53906, 'debugid': 67895317, 'eventid': 0x40c0014, 'class': 4, 'subclass': 12, 'code': 5,
            'func_qualifier': 1, 'cpuid': 1, 'unused': 0}),
        Container({
            'timestamp': 458577724301, 'args': Container(
                data=b'\xd5\xcbv\x1d7\xeb\xebL/System/Library/CoreServ',
                value=ListContainer(
                    [5542782388359580629, 3417499243072017199, 3420891154821048652, 8534995652679200579]),
                offset1=245384, offset2=245416, length=32),
            'tid': 53906, 'debugid': 50397329, 'eventid': 0x3010090, 'class': 3, 'subclass': 1, 'code': 36,
            'func_qualifier': 1, 'cpuid': 1, 'unused': 0}),
        Container({
            'timestamp': 458577724316, 'args': Container(
                data=b'ices/SpringBoard.app/SpringBoard',
                value=ListContainer(
                    [8246182380979970921, 7237954681621147241, 8246182380930359598, 7237954681621147241]),
                offset1=245448, offset2=245480, length=32),
            'tid': 53906, 'debugid': 50397330, 'eventid': 0x3010090, 'class': 3, 'subclass': 1, 'code': 36,
            'func_qualifier': 2, 'cpuid': 1, 'unused': 0}),
        Container({
            'timestamp': 458577726009, 'args': Container(
                data=(b'\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                      b'\x00\x00+\x00\x00\x00\x00\x00\x00\x00'),
                value=ListContainer(
                    [0, 8, 0, 43]),
                offset1=245512, offset2=245544, length=32),
            'tid': 53906, 'debugid': 67895318, 'eventid': 0x40c0014, 'class': 4, 'subclass': 12, 'code': 5,
            'func_qualifier': 2, 'cpuid': 1, 'unused': 0})
    ]
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        trace_codes_map = DeviceInfo(dvt).trace_codes()

    parser = KdebugEventsParser(trace_codes_map)
    for event in events:
        parser.feed(event)
    bsc_open = parser.fetch()
    assert bsc_open.path == '/System/Library/CoreServices/SpringBoard.app/SpringBoard'
    assert bsc_open.ktraces == events
    assert bsc_open.flags == [BscOpenFlags.O_RDONLY]
    assert bsc_open.result == 'fd: 8'
