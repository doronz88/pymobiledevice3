from pymobiledevice3.restore.restore import FIRMWARE_DATA_MAX_CHUNK_SIZE, firmware_response_messages


def test_reply_is_a_single_message_without_a_chunk_size():
    fwdict = {"SE2,Ticket": b"t", "FirmwareData": b"x" * 10}
    assert firmware_response_messages(fwdict, None) == [{"FirmwareResponseData": fwdict}]


def test_reply_is_a_single_message_without_firmware_data():
    fwdict = {"Rap,Ticket": b"t"}
    assert firmware_response_messages(fwdict, 131072) == [{"FirmwareResponseData": fwdict}]


def test_reply_streams_firmware_data_like_apples_host():
    """MobileDevice sends the tickets with DataSize, then FirmwareResponseData chunks, then an empty DataDone."""
    fwdict = {"BMU,Ticket": b"t", "FirmwareData": b"abcdefghij"}
    assert firmware_response_messages(fwdict, 4) == [
        {"FirmwareResponseData": {"BMU,Ticket": b"t"}, "DataSize": 10},
        {"FirmwareResponseData": b"abcd"},
        {"FirmwareResponseData": b"efgh"},
        {"FirmwareResponseData": b"ij"},
        {"FirmwareResponseData": b"", "DataDone": True},
    ]


def test_chunk_size_is_capped_like_apples_host():
    fwdict = {"FirmwareData": b"x" * (FIRMWARE_DATA_MAX_CHUNK_SIZE + 1)}
    messages = firmware_response_messages(fwdict, 10 * FIRMWARE_DATA_MAX_CHUNK_SIZE)
    assert len(messages[1]["FirmwareResponseData"]) == FIRMWARE_DATA_MAX_CHUNK_SIZE
    assert len(messages[2]["FirmwareResponseData"]) == 1
    assert messages[-1] == {"FirmwareResponseData": b"", "DataDone": True}
