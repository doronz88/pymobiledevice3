from pymobiledevice3.services.dvt.instruments.core_profile_session_tap import KdBuf
from pymobiledevice3.services.dvt.instruments.kdebug_events_parser import KdebugEventsParser, BscOpenFlags
from pymobiledevice3.services.dvt.instruments.device_info import DeviceInfo
from pymobiledevice3.services.dvt.dvt_secure_socket_proxy import DvtSecureSocketProxyService


def test_parsing_bsc_open(lockdown):
    """
    Test parsing BSC_open.
    :param pymobiledevice3.lockdown.LockdownClient lockdown: Lockdown client.
    """
    events = [
        KdBuf(timestamp=50134926677,
              data=(b'f=\xc6o\x01\x00\x00\x00\x05\x02\x02\x00\x00\x00\x00\x00\xb6\x01'
                    b'\x00\x00\x00\x00\x00\x00\xb6\x01\x00\x00\x00\x00\x00\x00'),
              values=(6170230118, 131589, 438, 438), tid=12294, debugid=67895317, eventid=67895316, func_qualifier=1),
        KdBuf(timestamp=50134926946,
              data=(b'=\x9a\xf1\xc9 \x0b\x9a\x08kaki.txt\x00\x00\x00\x00\x00\x00\x00'
                    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
              values=(619820134171777597, 8392585648290881899, 0, 0), tid=12294, debugid=50397331, eventid=50397328,
              func_qualifier=3),
        KdBuf(timestamp=50134927111,
              data=(b'\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00'
                    b'\x00\x00\x00\x00\x00\x00\x00\x00\x85\x01\x00\x00\x00\x00\x00\x00'),
              values=(0, 3, 0, 389), tid=12294, debugid=67895318, eventid=67895316, func_qualifier=2)
    ]
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        trace_codes_map = DeviceInfo(dvt).trace_codes()

    parsed = []
    parser = KdebugEventsParser(parsed.append, trace_codes_map, {})
    for event in events:
        parser.feed(event)
    assert len(parsed) == 1
    bsc_open = parsed[0]
    assert bsc_open.path == 'kaki.txt'
    assert bsc_open.ktraces == events
    assert bsc_open.flags == [BscOpenFlags.O_WRONLY, BscOpenFlags.O_CREAT, BscOpenFlags.O_NONBLOCK]
    assert bsc_open.result == 'fd: 3'


def test_parsing_bsc_write(lockdown):
    """
    Test parsing BSC_write.
    :param pymobiledevice3.lockdown.LockdownClient lockdown: Lockdown client.
    """
    events = [
        KdBuf(timestamp=303055456965,
              data=(b'\x05\x00\x00\x00\x00\x00\x00\x00p\xdf\n\x08\x01\x00\x00\x00'
                    b'\x00\xa0\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00'),
              values=(5, 4429897584, 40960, 16), tid=37419, debugid=67895313, eventid=67895312, func_qualifier=1),
        KdBuf(timestamp=303055457297,
              data=(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00 \x00\x00\x00\x00\x00\x00'
                    b'\x00\x00\x00\x00\x00\x00\x00\x001\x01\x00\x00\x00\x00\x00\x00'),
              values=(0, 8192, 0, 305), tid=37419, debugid=67895314, eventid=67895312, func_qualifier=2)
    ]
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        trace_codes_map = DeviceInfo(dvt).trace_codes()

    parsed = []
    parser = KdebugEventsParser(parsed.append, trace_codes_map, {})
    for event in events:
        parser.feed(event)
    assert len(parsed) == 1
    bsc_write = parsed[0]
    assert bsc_write.fd == 5
    assert bsc_write.ktraces == events
    assert bsc_write.size == 40960
    assert bsc_write.address == 0x1080adf70
    assert bsc_write.result == 'count: 8192'
