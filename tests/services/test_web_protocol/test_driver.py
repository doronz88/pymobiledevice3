from pymobiledevice3.services.web_protocol.driver import By
from tests.services.test_web_protocol.common import LINK_HTML


def test_back(webdriver):
    webdriver.get('https://www.google.com')
    webdriver.get('https://www.github.com')
    webdriver.back()
    assert webdriver.current_url.rstrip('/') == 'https://www.google.com'


def test_current_url(webdriver):
    assert not webdriver.current_url
    url = 'https://www.google.com'
    webdriver.get(url)
    assert webdriver.current_url.rstrip('/') == url


def test_forward(webdriver):
    webdriver.get('https://www.google.com')
    webdriver.get('https://www.github.com')
    webdriver.back()
    webdriver.forward()
    assert webdriver.current_url.rstrip('/') == 'https://www.github.com'


def test_find_element(webdriver):
    webdriver.execute_script(f'''document.getElementsByTagName('body')[0].innerHTML = '{LINK_HTML}'; ''')
    by_id = webdriver.find_element(By.ID, 'id_of_link')
    by_xpath = webdriver.find_element(By.XPATH, '/html/body/a')
    by_link_text = webdriver.find_element(By.LINK_TEXT, 'the text obviously')
    by_partial_link_text = webdriver.find_element(By.PARTIAL_LINK_TEXT, 'obviously')
    by_name = webdriver.find_element(By.NAME, 'name_of_link')
    by_tag = webdriver.find_element(By.TAG_NAME, 'a')
    by_class = webdriver.find_element(By.CLASS_NAME, 'link-class')
    by_css = webdriver.find_element(By.CSS_SELECTOR, '.link-class')
    assert by_id == by_xpath == by_link_text == by_partial_link_text == by_name == by_tag == by_class == by_css
    assert by_id is not None
