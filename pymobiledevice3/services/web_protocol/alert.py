class Alert:
    def __init__(self, session):
        """
        :param pymobiledevice3.services.web_protocol.automation_session.AutomationSession session: Automation session.
        """
        self.session = session

    def accept(self):
        """ Accepts the alert available. """
        self.session.protocol.acceptCurrentJavaScriptDialog(browsingContextHandle=self.session.top_level_handle)

    def dismiss(self):
        """ Dismisses the alert available. """
        self.session.protocol.dismissCurrentJavaScriptDialog(browsingContextHandle=self.session.top_level_handle)

    def send_keys(self, text: str):
        """
        Send Keys to the Alert.
        :param text: Text to send to prompts.
        """
        self.session.protocol.setUserInputForCurrentJavaScriptPrompt(
            browsingContextHandle=self.session.top_level_handle, userInput=text
        )

    @property
    def text(self) -> str:
        """ Gets the text of the Alert. """
        resp = self.session.protocol.messageOfCurrentJavaScriptDialog(
            browsingContextHandle=self.session.top_level_handle
        )
        return resp['message']
