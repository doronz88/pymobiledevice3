from lockdown import LockdownClient
from pprint import pprint
from afc import AFCClient, AFCShell
from optparse import OptionParser
import os

def house_arrest(lockdown, applicationId):
    try:
        mis = lockdown.startService("com.apple.mobile.house_arrest")
    except:
        lockdown = LockdownClient()
        mis = lockdown.startService("com.apple.mobile.house_arrest")

    if mis == None:
        return
    mis.sendPlist({"Command": "VendDocuments", "Identifier": applicationId})
    res = mis.recvPlist()
    #pprint(res)
    error = res.get("Error")
    if error: 
        print res["Error"]
        return None
    return AFCClient(lockdown, service=mis)

def house_arrest_shell(lockdown, applicationId):
    afc =  house_arrest(lockdown, applicationId)
    AFCShell(afc=afc).cmdloop()
    #print afc.read_directory("/")

    
"""
"Install"
"Upgrade"
"Uninstall"
"Lookup"
"Browse"
"Archive"
"Restore"
"RemoveArchive"
"LookupArchives"
"CheckCapabilitiesMatch"

installd
if stat("/var/mobile/tdmtanf") => "TDMTANF Bypass" => SignerIdentity bypass
"""

def mobile_install_old(lockdown):
    mci = lockdown.startService("com.apple.mobile.installation_proxy")
   
    #print mci.sendPlist({"Command":"Archive","ApplicationIdentifier": "com.joystickgenerals.STActionPig"})
    print mci.sendPlist({"Command":"Install",
                         #"ApplicationIdentifier": "com.gotohack.JBChecker",
                         "PackagePath": "test.ipa"})
    
    while True:
        z =  mci.recvPlist()
        if not z:
            break
        pprint(z)

def mobile_install(lockdown,ipaPath):
    #Start afc service & upload ipa    
    afc = AFCClient(lockdown)
    afc.set_file_contents("/" + os.path.basename(ipaPath), open(ipaPath,'rb').read())
    mci = lockdown.startService("com.apple.mobile.installation_proxy")
    #print mci.sendPlist({"Command":"Archive","ApplicationIdentifier": "com.joystickgenerals.STActionPig"})
    mci.sendPlist({"Command":"Install",
                         #"ApplicationIdentifier": "com.gotohack.JBChecker",
                         "PackagePath": os.path.basename(ipaPath)})
    while True:
        z =  mci.recvPlist()
        if not z:
            break
        completion = z.get('PercentComplete')
        if completion:
            print 'Installing, %s: %s %% Complete' % (ipaPath, z['PercentComplete'])
        if z.get('Status') == 'Complete':
            print "Installation %s\n" % z['Status']
            break

def list_apps(lockdown):
    mci = lockdown.startService("com.apple.mobile.installation_proxy")
    #print 
    mci.sendPlist({"Command":"Lookup"})
    res = mci.recvPlist()
    for app in res["LookupResult"].values():
        if app.get("ApplicationType") != "System":
            print app["CFBundleIdentifier"], "=>", app.get("Container")
        else:
            print app["CFBundleIdentifier"], "=>", app.get("CFBundleDisplayName")


def get_apps_BundleID(lockdown,appType="User"):
    appList = []
    mci = lockdown.startService("com.apple.mobile.installation_proxy")
    mci.sendPlist({"Command":"Lookup"})
    res = mci.recvPlist()
    for app in res["LookupResult"].values():
        if app.get("ApplicationType")  == appType:
	        appList.append(app["CFBundleIdentifier"])
        #else: #FIXME
        #    appList.append(app["CFBundleIdentifier"])
    mci.close()
    #pprint(appList)
    return appList


if __name__ == "__main__":
    parser = OptionParser(usage="%prog")
    parser.add_option("-l", "--list", dest="list", action="store_true", default=False,
                  help="List installed applications (non system apps)")
    parser.add_option("-a", "--app", dest="app", action="store", default=None, 
                  metavar="FILE", help="Access application files with AFC")
    parser.add_option("-i", "--install", dest="installapp", action="store", default=None, 
                  metavar="FILE", help="Install an application package")
     
    (options, args) = parser.parse_args()
    if options.list:
        lockdown = LockdownClient()
        list_apps(lockdown)
    elif options.app:
        lockdown = LockdownClient()
        house_arrest_shell(lockdown, options.app)
    elif options.installapp:
        lockdown = LockdownClient()
        mobile_install(lockdown, options.installapp)
    else:
        parser.print_help()

