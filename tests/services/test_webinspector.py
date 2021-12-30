import time

from pymobiledevice3.services.webinspector import WebinspectorService, SAFARI


def test_opening_app(lockdown):
    inspector = WebinspectorService(lockdown=lockdown)
    with inspector.connect():
        safari = inspector.open_app(SAFARI)
        time.sleep(1)  # Best effort
        inspector.flush_input()
        pages = inspector.get_open_pages()
    assert safari.name in pages
    assert pages[safari.name]
