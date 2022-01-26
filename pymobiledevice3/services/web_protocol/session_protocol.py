import asyncio
from functools import partial

from pymobiledevice3.exceptions import WirError


class SessionProtocol:
    def __init__(self, inspector, id_, app, page, method_prefix='Automation'):
        """
        :param pymobiledevice3.services.webinspector.WebinspectorService inspector:
        """
        self.app = app
        self.page = page
        self.inspector = inspector
        self.id_ = id_
        self.method_prefix = method_prefix
        self._wir_messages_id = 1

    async def send_command(self, method, **kwargs):
        wir_id = self._wir_messages_id
        self._wir_messages_id += 1
        await self.inspector.send_socket_data(self.id_, self.app.id_, self.page.id_, {
            'method': f'{self.method_prefix}.{method}' if self.method_prefix else method,
            'params': kwargs,
            'id': wir_id,
        })
        return wir_id

    async def get_response(self, wir_id):
        response = await self.wait_for_message(wir_id)
        if 'result' in response:
            return response['result']
        elif 'error' in response:
            raise WirError(response['error']['message'])

    async def send_receive(self, method, wait_for_response=True, **kwargs):
        wir_id = await self.send_command(method, **kwargs)
        if wait_for_response:
            return await self.get_response(wir_id)
        else:
            return wir_id

    async def wait_for_message(self, id_):
        while id_ not in self.inspector.wir_message_results:
            await asyncio.sleep(0)
        return self.inspector.wir_message_results.pop(id_)

    def sync_send_receive(self, method, wait_for_response=True, **kwargs):
        return self.inspector.await_(self.send_receive(method, wait_for_response, **kwargs))

    def __getattr__(self, item):
        return partial(self.sync_send_receive, method=item)
