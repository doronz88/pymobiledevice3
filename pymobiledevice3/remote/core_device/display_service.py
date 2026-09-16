import random
import uuid
from typing import Any, Optional

from pymobiledevice3.exceptions import CoreDeviceError
from pymobiledevice3.remote.core_device.core_device_service import CoreDeviceService
from pymobiledevice3.remote.core_device.media_stream_offer import (
    build_negotiator_offer_audio,
    build_negotiator_offer_video,
    new_call_id,
)
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.xpc_message import XpcInt64Type, XpcUInt64Type

# CoreDevice error code ``dtremotedisplayd`` returns when a foreground app
# (Camera, Voice Memos, ...) already holds the camera or microphone. iOS refuses
# to start a mirroring session while those sensors are in use; this is expected
# and matches Xcode's Device Hub, which raises the same conflict.
MEDIA_IN_USE_ERROR_CODE = 9022

# Apple documents the identical conflict for Device Hub.
CAMERA_MIC_CONFLICT_DOC_URL = (
    "https://developer.apple.com/documentation/xcode/interacting-with-your-app-in-device-hub"
    "#Handle-camera-and-microphone-access-conflicts-on-physical-devices"
)

# Actionable, single-line message for the camera/microphone-in-use case.
MEDIA_IN_USE_MESSAGE = (
    "The device's camera or microphone is in use by another app (e.g. Camera or Voice Memos). "
    "Quit that app on the device, then retry — screen mirroring cannot start while a "
    f"foreground app holds those sensors. See {CAMERA_MIC_CONFLICT_DOC_URL}"
)


def is_media_in_use_error(exc: BaseException) -> bool:
    """True if *exc* is CoreDevice's "camera or microphone is in use" rejection (code 9022)."""
    return isinstance(exc, CoreDeviceError) and exc.code == MEDIA_IN_USE_ERROR_CODE


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

    async def get_media_support_info(self) -> dict[str, Any]:
        """Return the device's supported media-stream features and AVC framework version."""
        return await self.invoke(
            "com.apple.coredevice.feature.getmediasupportinfo",
            {},
            action_identifier="com.apple.coredevice.action.mediastreamgetsupportinfo",
        )

    async def get_media_stream_server_status(self) -> dict[str, Any]:
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
        *,
        allow_rtcp_fb: bool = False,
        ltrp_enabled: bool = False,
        fec_enabled: bool = True,
        tiles_per_frame: int = 1,
        hevc_features: Optional[str] = None,
        avc_features: Optional[str] = None,
    ) -> dict[str, Any]:
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
        :param allow_rtcp_fb: Set the protobuf-level ``allowRTCPFB`` flag. Default
                              ``False``; shows no observable effect in the device's
                              ``streamConfig`` answer but kept as an opt-in knob in
                              case it changes internal encoder behaviour.
        :param ltrp_enabled: Set the protobuf-level ``ltrpEnabled`` flag. Default
                             ``False`` -- the device honours the request (confirmed
                             by ``IsltrpEnabled: false`` in the answer's
                             streamConfig), and LTRP-off eliminates mid-stream
                             tearing under UDP loss. Apple's captured Xcode offer
                             used ``True``; opt back in if you suspect a regression.
        :param hevc_features: Override the feature-list string declared in the
                              PT=123 codec bank (``None`` keeps the module default).
        :param avc_features: Override the feature-list string declared in the
                             PT=100 codec bank, the one the device actually
                             negotiates (``None`` keeps the module default; see
                             ``media_stream_offer._DEFAULT_AVC_FEATURES`` for
                             why ``VRAE:0`` must stay out of it).
        :return: Response dict with ``connection`` (carries ``sender`` port + full
                 ``streamConfig``) and ``negotiatorAnswer``.
        """
        if client_session_id is None:
            client_session_id = uuid.uuid4()
        call_id = new_call_id()
        session_id = random.randint(0, 0xFFFFFFFF)
        offer_kwargs: dict[str, Any] = {}
        if hevc_features is not None:
            offer_kwargs["hevc_features"] = hevc_features
        if avc_features is not None:
            offer_kwargs["avc_features"] = avc_features
        negotiator_offer = build_negotiator_offer_video(
            call_id=call_id,
            session_id=session_id,
            allow_rtcp_fb=allow_rtcp_fb,
            ltrp_enabled=ltrp_enabled,
            fec_enabled=fec_enabled,
            tiles_per_frame=tiles_per_frame,
            **offer_kwargs,
        )
        request: dict[str, Any] = {
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
    ) -> dict[str, Any]:
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
        request: dict[str, Any] = {
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

    async def stop_media_stream(
        self, *, stop_all: bool = True, identifiers: Optional[list[int]] = None
    ) -> dict[str, Any]:
        """Stop media-stream session(s) on the device.

        The wire payload is CoreDevice's ``StopRequest`` — mined from the DDI as
        ``StopRequest(stopAll: Bool, identifiers: [UInt32]?)``. The previous
        ``{avcMediaStreamOptionClientSessionID: <uuid>}`` payload never decoded
        to a ``StopRequest``, so the daemon rejected it outright.

        This request MUST be the only reply-bearing request on its RemoteXPC
        connection — see :meth:`stop_all_streams` for why a second one is fatal.
        Prefer that classmethod; call this instance method directly only on a
        connection that has issued no earlier ``send_receive_request``.

        :param stop_all: Stop every session (the whole media-stream server).
        :param identifiers: Stop only these stream tokens; ignored when empty.
        """
        from asyncio import IncompleteReadError

        request: dict[str, Any] = {"stopAll": stop_all}
        if identifiers:
            request["identifiers"] = [XpcUInt64Type(i) for i in identifiers]
        try:
            return await self.invoke(
                "com.apple.coredevice.feature.stopmediastream",
                request,
                action_identifier="com.apple.coredevice.action.mediastreamstop",
            )
        except (IncompleteReadError, ConnectionResetError, BrokenPipeError):
            # Defensive: a device already tearing the tunnel down can close the
            # channel before replying. The stop itself still took effect.
            return {"stopped": True}

    @classmethod
    async def stop_all_streams(cls, rsd: RemoteServiceDiscoveryService) -> dict[str, Any]:
        """Tear down every media-stream session, on a FRESH connection.

        The stop MUST be the only reply-bearing request on its RemoteXPC
        connection. A second reply-bearing request on any single connection
        makes the device's ``dtremotedisplayd`` fatally assert (``Attempted to
        send non-reply msg N on the reply channel``) and ``SIGABRT`` *before* it
        runs its teardown — ``stopRemoteObservation``, releasing the audit
        activity assertion, and stopping the screen-sharing indicator. That
        leaves the device "observed remotely" with its camera and microphone
        blocked until it reboots. Reusing the connection that issued the stream
        ``start`` is exactly that fatal second request, so the stop always runs
        on a brand-new connection whose sole request is the stop itself.
        """
        async with cls(rsd) as svc:
            return await svc.stop_media_stream(stop_all=True)
