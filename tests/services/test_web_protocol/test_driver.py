from pymobiledevice3.services.web_protocol.driver import By
from tests.services.test_web_protocol.common import LINK_HTML


async def test_back(webdriver):
    await webdriver.get("https://www.google.com")
    await webdriver.get("https://github.com")
    await webdriver.back()
    assert (await webdriver.current_url).rstrip("/") == "https://www.google.com"


async def test_current_url(webdriver):
    assert not await webdriver.current_url
    url = "https://www.google.com"
    await webdriver.get(url)
    assert (await webdriver.current_url).rstrip("/") == url


async def test_forward(webdriver):
    await webdriver.get("https://www.google.com")
    await webdriver.get("https://github.com")
    await webdriver.back()
    await webdriver.forward()
    assert (await webdriver.current_url).rstrip("/") == "https://github.com"


async def test_find_element(webdriver):
    await webdriver.execute_script(f"""document.getElementsByTagName('body')[0].innerHTML = '{LINK_HTML}'; """)
    by_id = await webdriver.find_element(By.ID, "id_of_link")
    by_xpath = await webdriver.find_element(By.XPATH, "/html/body/a")
    by_link_text = await webdriver.find_element(By.LINK_TEXT, "the text obviously")
    by_partial_link_text = await webdriver.find_element(By.PARTIAL_LINK_TEXT, "obviously")
    by_name = await webdriver.find_element(By.NAME, "name_of_link")
    by_tag = await webdriver.find_element(By.TAG_NAME, "a")
    by_class = await webdriver.find_element(By.CLASS_NAME, "link-class")
    by_css = await webdriver.find_element(By.CSS_SELECTOR, ".link-class")
    assert by_id == by_xpath == by_link_text == by_partial_link_text == by_name == by_tag == by_class == by_css
    assert by_id is not None
