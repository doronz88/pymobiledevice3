import asyncio
import contextlib
from base64 import b64decode, b64encode
from datetime import datetime
from io import BytesIO

from PIL import Image


class ScreenCast:
    def __init__(self, target, format_: str, quality: int, max_width: int, max_height: int):
        """
        :param pymobiledevice3.services.web_protocol.cdp_target.CdpTarget target:
        :param format_: Image compression format. Allowed values: jpeg, png.
        :param quality: Compression quality from range [0..100].
        :param max_width: Maximum screenshot width.
        :param max_height: Maximum screenshot height.
        """
        self.target = target
        self.format_ = format_
        self.quality = quality
        self.max_width = max_width
        self.max_height = max_height
        self.frames_acked = []
        self.frame_id = 1
        self.frame_interval = 250
        self.device_width = 0
        self.device_height = 0
        self.page_scale_factor = 0
        self._run = True
        self.recording_task = None  # type: asyncio.Task | None

    @property
    def scale(self) -> float:
        """The amount screen pixels in one devtools pixel."""
        real_height = self.device_height * self.page_scale_factor
        real_width = self.device_width * self.page_scale_factor
        return min(self.max_height / real_height, self.max_width / real_width, 1) * self.page_scale_factor

    @property
    def scaled_width(self) -> int:
        """Width of screenshot after scaling."""
        return int(self.scale * self.device_width)

    @property
    def scaled_height(self) -> int:
        """Height of screenshot after scaling."""
        return int(self.scale * self.device_height)

    async def start(self, message_id: int):
        """
        Start sending screenshots to the devtools.
        :param message_id: Message id to use when requesting WIR data concerning the screencast.
        """
        device_size = await self.target.evaluate_and_result(
            message_id,
            (
                '(window.innerWidth > 0 ? window.innerWidth : screen.width) + "," + '
                '(window.innerHeight > 0 ? window.innerHeight : screen.height) + "," + '
                "window.devicePixelRatio"
            ),
        )
        self.device_width, self.device_height, self.page_scale_factor = list(map(int, device_size.split(",")))
        self._run = True
        self.recording_task = asyncio.create_task(self.recording_loop(message_id))

    async def stop(self):
        """Stop sending screenshots to the devtools."""
        self._run = False
        self.recording_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self.recording_task
        self.recording_task = None

    def ack(self, frame_id: int):
        """Handle acknowledgement for screencast frames."""
        self.frames_acked.append(frame_id)

    def resize_jpeg(self, data: str) -> str:
        """
        Resize a screenshot to fit the devtools requested size.
        :param data: Base64 of JPEG data.
        :return: Base 64 of resized JPEG data.
        """
        resized_img = Image.open(BytesIO(b64decode(data)))
        resized_img = resized_img.resize((self.scaled_width, self.scaled_height), Image.ANTIALIAS)
        resized_img = resized_img.convert("RGB")
        resized = BytesIO()
        resized_img.save(resized, format="jpeg", quality="maximum")
        return b64encode(resized.getvalue()).decode()

    async def get_offsets(self, message_id: int):
        """
        Get the offset of the screenshot from the start of the page.
        :param message_id: Message id to use when requesting WIR data concerning the screencast.
        :return: Tuple of (offsetTop, pageXOffset, pageYOffset).
        :rtype: tuple
        """
        frame_size = await self.target.evaluate_and_result(
            message_id, 'window.document.body.offsetTop + "," + window.pageXOffset + "," + window.pageYOffset'
        )
        if frame_size is None or not isinstance(frame_size, str):
            return 0, 0, 0
        return tuple(map(int, frame_size.split(",")))

    async def recording_loop(self, message_id):
        """
        Fetch screenshots and send to devtools.
        :param message_id: Message id to use when requesting WIR data concerning the screencast.
        """
        while self._run:
            await asyncio.sleep(self.frame_interval / 1000)
            if self.frame_id > 1 and (self.frame_id - 1) not in self.frames_acked:
                continue
            self.frame_id += 1
            offset_top, scroll_offset_x, scroll_offset_y = await self.get_offsets(message_id)
            event = await self.target.send_message_with_result(
                message_id,
                "Page.snapshotRect",
                {
                    "x": 0,
                    "y": 0,
                    "width": self.device_width,
                    "height": self.device_height,
                    "coordinateSystem": "Viewport",
                },
            )
            data = event["result"]["dataURL"]
            data = data[data.find("base64,") + 7 :]
            await self.target.output_queue.put({
                "method": "Page.screencastFrame",
                "params": {
                    "data": self.resize_jpeg(data),
                    "sessionId": self.frame_id - 1,
                    "metadata": {
                        "pageScaleFactor": self.page_scale_factor,
                        "offsetTop": offset_top,
                        "deviceWidth": self.scaled_width,
                        "deviceHeight": self.scaled_height,
                        "scrollOffsetX": scroll_offset_x,
                        "scrollOffsetY": scroll_offset_y,
                        "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f"),
                    },
                },
            })
