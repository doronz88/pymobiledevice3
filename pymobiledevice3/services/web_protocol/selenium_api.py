from abc import ABC, abstractmethod
from base64 import b64decode
from typing import Any, List, Optional

from pymobiledevice3.services.web_protocol.automation_session import By


class SeleniumApi(ABC):
    @abstractmethod
    def find_element(self, by: By = By.ID, value: str = None) -> Optional[Any]:
        pass

    @abstractmethod
    def find_elements(self, by: By = By.ID, value: str = None) -> List[Optional[Any]]:
        pass

    @property
    @abstractmethod
    def screenshot_as_base64(self) -> str:
        pass

    def find_element_by_class_name(self, name: str) -> Optional[Any]:
        return self.find_element(By.CLASS_NAME, name)

    def find_element_by_css_selector(self, css_selector: str) -> Optional[Any]:
        return self.find_element(By.CSS_SELECTOR, css_selector)

    def find_element_by_id(self, id_: str) -> Optional[Any]:
        return self.find_element(value=id_)

    def find_element_by_link_text(self, link_text: str) -> Optional[Any]:
        return self.find_element(By.LINK_TEXT, link_text)

    def find_element_by_name(self, name: str) -> Optional[Any]:
        return self.find_element(By.NAME, name)

    def find_element_by_partial_link_text(self, link_text: str) -> Optional[Any]:
        return self.find_element(By.PARTIAL_LINK_TEXT, link_text)

    def find_element_by_tag_name(self, name: str) -> Optional[Any]:
        return self.find_element(By.TAG_NAME, name)

    def find_element_by_xpath(self, xpath: str) -> Optional[Any]:
        return self.find_element(By.XPATH, xpath)

    def find_elements_by_class_name(self, name: str) -> List[Optional[Any]]:
        return self.find_elements(By.CLASS_NAME, name)

    def find_elements_by_css_selector(self, css_selector: str) -> List[Optional[Any]]:
        return self.find_elements(By.CSS_SELECTOR, css_selector)

    def find_elements_by_id(self, id_: str) -> List[Optional[Any]]:
        return self.find_elements(value=id_)

    def find_elements_by_link_text(self, link_text: str) -> List[Optional[Any]]:
        return self.find_elements(By.LINK_TEXT, link_text)

    def find_elements_by_name(self, name: str) -> List[Optional[Any]]:
        return self.find_elements(By.NAME, name)

    def find_elements_by_partial_link_text(self, link_text: str) -> List[Optional[Any]]:
        return self.find_elements(By.PARTIAL_LINK_TEXT, link_text)

    def find_elements_by_tag_name(self, name: str) -> List[Optional[Any]]:
        return self.find_elements(By.TAG_NAME, name)

    def find_elements_by_xpath(self, xpath: str) -> List[Optional[Any]]:
        return self.find_elements(By.XPATH, xpath)

    def screenshot(self, filename: str) -> bool:
        png = self.screenshot_as_png()
        try:
            with open(filename, 'wb') as f:
                f.write(png)
        except IOError:
            return False
        return True

    def screenshot_as_png(self) -> bytes:
        return b64decode(self.screenshot_as_base64.encode('ascii'))

    def get_screenshot_as_base64(self) -> str:
        return self.screenshot_as_base64

    def get_screenshot_as_file(self, filename: str) -> bool:
        return self.screenshot(filename)

    def get_screenshot_as_png(self) -> bytes:
        return self.screenshot_as_png()

    def save_screenshot(self, filename: str) -> bool:
        return self.screenshot(filename)
