class Alert:
    def __init__(self, session):
        """
        :param pymobiledevice3.services.web_protocol.automation_session.AutomationSession session: Automation session.
        """
        self.session = session

    async def accept(self):
        """Accepts the alert available."""
        await self.session.accept_current_javascript_dialog()

    async def dismiss(self):
        """Dismisses the alert available."""
        await self.session.dismiss_current_javascript_dialog()

    async def send_keys(self, text: str):
        """
        Send Keys to the Alert.
        :param text: Text to send to prompts.
        """
        await self.session.set_user_input_for_current_javascript_prompt(text)

    @property
    async def text(self) -> str:
        """Gets the text of the Alert."""
        return await self.session.message_of_current_javascript_dialog()
