import asyncio
from functools import partial
from typing import TYPE_CHECKING, Any

from pymobiledevice3.exceptions import WirError

if TYPE_CHECKING:
    from pymobiledevice3.services.webinspector import Application, Page, WebinspectorService


class SessionProtocol:
    def __init__(
        self,
        inspector: "WebinspectorService",
        id_: str,
        app: "Application",
        page: "Page",
        method_prefix: str = "Automation",
    ):
        """
        :param pymobiledevice3.services.webinspector.WebinspectorService inspector:
        """
        self.app = app
        self.page = page
        self.inspector = inspector
        self.id_ = id_
        self.method_prefix = method_prefix
        self._wir_messages_id = 1

    async def send_command(self, method: str, **kwargs: Any):
        wir_id = self._wir_messages_id
        self._wir_messages_id += 1
        await self.inspector.send_socket_data(
            self.id_,
            self.app.id_,
            self.page.id_,
            {
                "method": f"{self.method_prefix}.{method}" if self.method_prefix else method,
                "params": kwargs,
                "id": wir_id,
            },
        )
        return wir_id

    async def get_response(self, wir_id: int):
        response = await self.wait_for_message(wir_id)
        if "result" in response:
            return response["result"]
        elif "error" in response:
            raise WirError(response["error"]["message"])
        raise WirError(f"Unknown response: {response}")

    async def send_receive(self, method: str, wait_for_response: bool = True, **kwargs: Any):
        wir_id = await self.send_command(method, **kwargs)
        if wait_for_response:
            return await self.get_response(wir_id)
        else:
            return wir_id

    async def wait_for_message(self, id_: int):
        while id_ not in self.inspector.wir_message_results:
            await asyncio.sleep(0)
        return self.inspector.wir_message_results.pop(id_)

    async def sync_send_receive(self, method: str, wait_for_response: bool = True, **kwargs: Any):
        return await self.send_receive(method, wait_for_response, **kwargs)

    def __getattr__(self, item: str):
        return partial(self.sync_send_receive, method=item)
