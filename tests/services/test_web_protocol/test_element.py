from pymobiledevice3.services.web_protocol.automation_session import By
from tests.services.test_web_protocol.common import LINK_HTML


def test_tag_name(webdriver):
    webdriver.execute_script(f'''document.getElementsByTagName('body')[0].innerHTML = '{LINK_HTML}'; ''')
    element = webdriver.find_element(By.ID, 'id_of_link')
    assert 'a' == element.tag_name
