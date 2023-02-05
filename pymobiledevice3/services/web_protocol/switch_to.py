from pymobiledevice3.services.web_protocol.alert import Alert
from pymobiledevice3.services.web_protocol.automation_session import By
from pymobiledevice3.services.web_protocol.element import WebElement


class SwitchTo:
    def __init__(self, session):
        """
        :param pymobiledevice3.services.web_protocol.automation_session.AutomationSession session: Automation session.
        """
        self.session = session

    @property
    def active_element(self) -> WebElement:
        """ Returns the element with focus, or BODY if nothing has focus. """
        self.session.wait_for_navigation_to_complete()
        elem = self.session.evaluate_js_function('function() { return document.activeElement; }', include_frame=False)
        return WebElement(self.session, elem)

    @property
    def alert(self) -> Alert:
        """ Switches focus to an alert on the page. """
        return Alert(self.session)

    def default_content(self):
        """ Switch focus to the default frame. """
        self.session.switch_to_browsing_context('')

    def frame(self, frame_reference):
        """
        Switches focus to the specified frame, by index, name, or web element.
        :param frame_reference: The name of the window to switch to, an integer representing the index,
                                or a web element that is an (i)frame to switch to.
        """
        if isinstance(frame_reference, int) or isinstance(frame_reference, WebElement):
            frame = frame_reference
        elif isinstance(frame_reference, str):
            elem = self.session.find_elements(By.ID, frame_reference)
            if elem is None:
                elem = self.session.find_elements(By.NAME, frame_reference)
            frame = WebElement(self.session, elem)
        else:
            raise ValueError()

        self.session.wait_for_navigation_to_complete()
        if isinstance(frame, int):
            self.session.switch_to_frame(frame_ordinal=frame)
        else:
            self.session.switch_to_frame(frame_handle=frame)

    def new_window(self, type_=''):
        """ Switches to a new top-level browsing context. """
        self.session.switch_to_window(self.session.create_window(type_))

    def parent_frame(self):
        """
        Switches focus to the parent context. If the current context is the top
        level browsing context, the context remains unchanged.
        """
        self.session.wait_for_navigation_to_complete()
        self.session.switch_to_browsing_context_frame(self.session.top_level_handle,
                                                      self.session.current_parent_handle)
        self.session.switch_to_browsing_context(self.session.current_parent_handle)

    def window(self, window_name):
        """ Switches focus to the specified window. """
        self.session.switch_to_window(window_name)
