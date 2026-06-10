import random
import uuid
from typing import Optional

from pymobiledevice3.remote.core_device.core_device_service import CoreDeviceService
from pymobiledevice3.remote.core_device.media_stream_offer import (
    build_negotiator_offer_audio,
    build_negotiator_offer_video,
    new_call_id,
)
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.xpc_message import XpcInt64Type, XpcUInt64Type

# Bit mask captured from devicectl. Bits identify host-side feature support.
_CLIENT_SUPPORTED_FEATURES = 140

# Defaults captured from a live screen-sharing session.
_DEFAULT_ACCESS_NETWORK_TYPE = 1
_DEFAULT_TRANSPORT_PROTOCOL_TYPE = 2


class DisplayService(CoreDeviceService):
    """
    Query media-streaming capabilities (video/audio/screenshot streams).
    """

    SERVICE_NAME = "com.apple.coredevice.displayservice"

    def __init__(self, rsd: RemoteServiceDiscoveryService):
        super().__init__(rsd, self.SERVICE_NAME)

    async def get_media_support_info(self) -> dict:
        """Return the device's supported media-stream features and AVC framework version."""
        return await self.invoke(
            "com.apple.coredevice.feature.getmediasupportinfo",
            {},
            action_identifier="com.apple.coredevice.action.mediastreamgetsupportinfo",
        )

    async def get_media_stream_server_status(self) -> dict:
        """Return the media-stream server's running state and active sessions."""
        return await self.invoke(
            "com.apple.coredevice.feature.getmediastreamserverstatus",
            {},
            action_identifier="com.apple.coredevice.action.mediastreamstatus",
        )

    async def start_video_stream(
        self,
        receiver_ip: str,
        receiver_port: int,
        sender_ip: str,
        display_id: int = 1,
        timeout: int = 20,
        client_session_id: Optional[uuid.UUID] = None,
    ) -> dict:
        """Start an RTP video stream of one of the device's displays.

        The caller is responsible for binding a UDP socket at ``receiver_ip:receiver_port``
        BEFORE calling this method — the device starts pushing RTP/RTCP frames there as
        soon as the answer is returned.

        :param receiver_ip: Host IPv6 address where the device should send RTP/RTCP.
        :param receiver_port: Host UDP port (must already be bound).
        :param sender_ip: Device's IPv6 address (the RSD tunnel peer).
        :param display_id: ``CoreDeviceVideoDisplayMode=DisplayByID`` target display.
        :param timeout: Negotiation timeout in seconds.
        :param client_session_id: Stable UUID identifying this session. A fresh UUID
                                  is generated when omitted.
        :return: Response dict with ``connection`` (carries ``sender`` port + full
                 ``streamConfig``) and ``negotiatorAnswer``.
        """
        if client_session_id is None:
            client_session_id = uuid.uuid4()
        call_id = new_call_id()
        session_id = random.randint(0, 0xFFFFFFFF)
        negotiator_offer = build_negotiator_offer_video(call_id=call_id, session_id=session_id)
        request = {
            "clientSupportedFeatures": XpcUInt64Type(_CLIENT_SUPPORTED_FEATURES),
            "direction": "output",
            "negotiatorOffer": negotiator_offer,
            "options": {
                "AVCMediaStreamNegotiatorAccessNetworkType": {"int": XpcInt64Type(_DEFAULT_ACCESS_NETWORK_TYPE)},
                "AVCMediaStreamNegotiatorTransportProtocolType": {
                    "int": XpcInt64Type(_DEFAULT_TRANSPORT_PROTOCOL_TYPE)
                },
                "CoreDeviceVideoDisplayMode": {"string": "DisplayByID"},
                "VideoStreamForDisplayID": {"int": XpcInt64Type(display_id)},
                "avcMediaStreamOptionClientSessionID": {"uuid": client_session_id},
            },
            "receiverIP": receiver_ip,
            "receiverPort": XpcUInt64Type(receiver_port),
            "senderIP": sender_ip,
            "timeout": XpcUInt64Type(timeout),
            "type": "video",
        }
        return await self.invoke(
            "com.apple.coredevice.feature.startmediastream",
            request,
            action_identifier="com.apple.coredevice.action.mediastreamstart",
        )

    async def start_audio_stream(
        self,
        receiver_ip: str,
        receiver_port: int,
        sender_ip: str,
        timeout: int = 20,
        client_session_id: Optional[uuid.UUID] = None,
    ) -> dict:
        """Start an RTP audio stream of the device's system audio output.

        Xcode's Mirror pairs an audio stream with the video stream using the
        SAME ``client_session_id`` — pass the value you used for the video
        start to keep them grouped on the device side.

        :param receiver_ip: Host IPv6 address where the device should send
                            RTP/RTCP audio packets.
        :param receiver_port: Host UDP port (must already be bound).
        :param sender_ip: Device's IPv6 address (the RSD tunnel peer).
        :param timeout: Negotiation timeout in seconds.
        :param client_session_id: Shared session UUID; a fresh one is
                                  generated when omitted.
        :return: Response dict with ``connection`` (carries ``sender`` port,
                 ``source.audioSystemOutput`` marker, full ``streamConfig``
                 — ``RxPayloadType=101``, ``AudioStreamMode=8``) and
                 ``negotiatorAnswer``.
        """
        if client_session_id is None:
            client_session_id = uuid.uuid4()
        call_id = new_call_id()
        session_id = random.randint(0, 0xFFFFFFFF)
        negotiator_offer = build_negotiator_offer_audio(call_id=call_id, session_id=session_id)
        request = {
            "clientSupportedFeatures": XpcUInt64Type(_CLIENT_SUPPORTED_FEATURES),
            "direction": "output",
            "negotiatorOffer": negotiator_offer,
            "options": {
                "AVCMediaStreamNegotiatorAccessNetworkType": {"int": XpcInt64Type(_DEFAULT_ACCESS_NETWORK_TYPE)},
                "AVCMediaStreamNegotiatorTransportProtocolType": {
                    "int": XpcInt64Type(_DEFAULT_TRANSPORT_PROTOCOL_TYPE)
                },
                "avcMediaStreamOptionClientSessionID": {"uuid": client_session_id},
            },
            "receiverIP": receiver_ip,
            "receiverPort": XpcUInt64Type(receiver_port),
            "senderIP": sender_ip,
            "timeout": XpcUInt64Type(timeout),
            "type": "audio",
        }
        return await self.invoke(
            "com.apple.coredevice.feature.startmediastream",
            request,
            action_identifier="com.apple.coredevice.action.mediastreamstart",
        )

    async def stop_media_stream(self, client_session_id: uuid.UUID) -> dict:
        """Stop an active media stream.

        Empirically the device closes the RemoteXPC channel immediately as part
        of processing the stop (we observe ``IncompleteReadError: 0 bytes read
        on a total of 9 expected bytes`` from the response wait). That looks
        like an error but is actually the stop succeeding — there's no response
        payload to return because the channel is gone. Treat it as success.
        """
        from asyncio import IncompleteReadError

        try:
            return await self.invoke(
                "com.apple.coredevice.feature.stopmediastream",
                {"avcMediaStreamOptionClientSessionID": {"uuid": client_session_id}},
                action_identifier="com.apple.coredevice.action.mediastreamstop",
            )
        except (IncompleteReadError, ConnectionResetError, BrokenPipeError):
            return {"stopped": True}
