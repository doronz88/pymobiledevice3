from pymobiledevice3.services.installation_proxy import InstallationProxyService


def test_get_apps(lockdown):
    with InstallationProxyService(lockdown=lockdown) as installation_proxy:
        apps = installation_proxy.get_apps()
        assert len(apps) > 1
