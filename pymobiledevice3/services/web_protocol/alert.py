class Alert:
    def __init__(self, session):
        """
        :param pymobiledevice3.services.web_protocol.automation_session.AutomationSession session: Automation session.
        """
        self.session = session

    def accept(self):
        """Accepts the alert available."""
        self.session.accept_current_javascript_dialog()

    def dismiss(self):
        """Dismisses the alert available."""
        self.session.dismiss_current_javascript_dialog()

    def send_keys(self, text: str):
        """
        Send Keys to the Alert.
        :param text: Text to send to prompts.
        """
        self.session.set_user_input_for_current_javascript_prompt(text)

    @property
    def text(self) -> str:
        """Gets the text of the Alert."""
        return self.session.message_of_current_javascript_dialog()
