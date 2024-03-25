from pymobiledevice3.services.installation_proxy import InstallationProxyService


def test_get_apps(lockdown):
    with InstallationProxyService(lockdown=lockdown) as installation_proxy:
        apps = installation_proxy.get_apps()
        assert len(apps) > 1


def test_get_system_apps(lockdown):
    with InstallationProxyService(lockdown=lockdown) as installation_proxy:
        app_types = set(
            [app['ApplicationType'] for app in installation_proxy.get_apps(application_type='System').values()])
        assert len(app_types) == 1
        assert app_types.pop() == 'System'
