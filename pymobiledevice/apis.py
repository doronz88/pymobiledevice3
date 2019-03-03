#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# vim: fenc=utf-8
# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
#
#

"""
File name: apis.py
Author: dhilipsiva <dhilipsiva@gmail.com>
Date created: 2016-06-19
"""

from os import path
# from pprint import pprint


def get_lockdown_and_service(udid):
    from pymobiledevice.lockdown import LockdownClient
    lockdown = LockdownClient(udid)
    service = lockdown.startService("com.apple.mobile.installation_proxy")
    return lockdown, service


def run_command(service, uuid, cmd):
    service.sendPlist(cmd)
    z = service.recvPlist()
    while 'PercentComplete' in z:
        if not z:
            break
        if z.get("Status") == "Complete":
            return z.get("Status")
        z = service.recvPlist()
    service.close()
    return z


def install_ipa(uuid, ipa_path):
    """
    docstring for install_ipa
    """
    from pymobiledevice.afc import AFCClient
    lockdown, service = get_lockdown_and_service(uuid)
    afc = AFCClient(lockdown=lockdown)
    afc.set_file_contents(
        path.basename(ipa_path), open(ipa_path, "rb").read())
    cmd = {"Command": "Install", "PackagePath": path.basename(ipa_path)}
    return run_command(service, uuid, cmd)


def uninstall_ipa(uuid, bundle_id):
    lockdown, service = get_lockdown_and_service(uuid)
    cmd = {"Command": "Uninstall", "ApplicationIdentifier": bundle_id}
    return run_command(service, uuid, cmd)


def list_ipas(uuid):
    lockdown, service = get_lockdown_and_service(uuid)
    cmd = {"Command": "Lookup"}
    result = run_command(service, uuid, cmd)
    apps_details = result.get("LookupResult")
    apps = []
    for app in apps_details:
        if apps_details[app]['ApplicationType'] == 'User':
            apps.append(app)
    return apps
