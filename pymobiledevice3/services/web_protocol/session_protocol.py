from functools import partial

from pymobiledevice3.exceptions import WirError


class SessionProtocol:
    def __init__(self, inspector, id_, app, page):
        self.app = app
        self.page = page
        self.inspector = inspector
        self.id_ = id_
        self._wir_messages_id = 1

    def send_command(self, method, **kwargs):
        wir_id = self._wir_messages_id
        self._wir_messages_id += 1
        self.inspector.forward_socket_data(self.id_, self.app.id_, self.page.id_, {
            'method': f'Automation.{method}',
            'params': kwargs,
            'id': wir_id,
        })
        return wir_id

    def get_response(self, wir_id):
        response = self.wait_for_message(wir_id)
        if 'result' in response:
            return response['result']
        elif 'error' in response:
            raise WirError(response['error']['message'])

    def send_receive(self, method, wait_for_response=True, **kwargs):
        wir_id = self.send_command(method, **kwargs)
        if wait_for_response:
            return self.get_response(wir_id)
        else:
            return wir_id

    def wait_for_message(self, id_):
        while id_ not in self.inspector.wir_message_results:
            self.inspector.flush_input()
        return self.inspector.wir_message_results.pop(id_)

    def __getattr__(self, item):
        return partial(self.send_receive, method=item)
