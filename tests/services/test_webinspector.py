from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.webinspector import SAFARI, WebinspectorService

TIMEOUT = 10


async def testp_opening_app(lockdown: LockdownClient) -> None:
    inspector = WebinspectorService(lockdown=lockdown)
    await inspector.connect(timeout=TIMEOUT)
    safari = await inspector.open_app(SAFARI)
    pages = await inspector.get_open_pages()
    # Might take a while to update.
    if safari.name not in pages:
        await inspector.flush_input(1)
    pages = await inspector.get_open_pages()
    try:
        assert safari.name in pages
        assert pages[safari.name]
    finally:
        await inspector.close()
