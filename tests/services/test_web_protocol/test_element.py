from pymobiledevice3.services.web_protocol.automation_session import By
from pymobiledevice3.services.web_protocol.driver import WebDriver
from tests.services.test_web_protocol.common import LINK_HTML


async def test_tag_name(webdriver: WebDriver) -> None:
    await webdriver.execute_script(f"""document.getElementsByTagName('body')[0].innerHTML = '{LINK_HTML}'; """)
    element = await webdriver.find_element(By.ID, "id_of_link")
    assert await element.tag_name == "a"
