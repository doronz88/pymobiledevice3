from pymobiledevice3.services.pcapd import PcapdService


def test_sniffing(lockdown):
    """
    Test sniffing device traffic.
    :param pymobiledevice3.lockdown.LockdownClient lockdown: Lockdown client.
    """
    with PcapdService(lockdown) as pcapd:
        packets = list(pcapd.watch(packets_count=2))
        assert len(packets) == 2

        first_packet_time = packets[0].seconds + (packets[0].microseconds / 1000000)
        second_packet_time = packets[1].seconds + (packets[1].microseconds / 1000000)
        assert first_packet_time < second_packet_time

        assert len(packets[0].data) == packets[0].packet_length
        assert packets[0].header_version == 2
