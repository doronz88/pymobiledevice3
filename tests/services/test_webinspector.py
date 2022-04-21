from pymobiledevice3.services.webinspector import WebinspectorService, SAFARI


def test_opening_app(lockdown):
    inspector = WebinspectorService(lockdown=lockdown)
    inspector.connect()
    safari = inspector.open_app(SAFARI)
    pages = inspector.get_open_pages()
    # Might take a while to update.
    if safari.name not in pages:
        inspector.flush_input(1)
    pages = inspector.get_open_pages()
    try:
        assert safari.name in pages
        assert pages[safari.name]
    finally:
        inspector.close()
