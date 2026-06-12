from pymobiledevice3.services.installation_proxy import InstallationProxyService


def test_apps_audit_empty_response() -> None:
    audit = InstallationProxyService.audit_apps({})

    assert audit == {
        "app_count": 0,
        "application_types": {},
        "background_modes": {},
        "findings": [],
        "flags": {
            "has_app_clips": False,
            "has_beta_apps": False,
            "has_debuggable_apps": False,
            "has_demoted_apps": False,
            "has_file_sharing_enabled_apps": False,
            "has_non_app_store_user_apps": False,
            "has_placeholder_apps": False,
            "has_user_apps": False,
        },
        "privacy_usage_descriptions": {},
        "signer_identities": {},
        "apps": [],
    }


def test_apps_audit_summarizes_apps_without_raw_paths_or_entitlements() -> None:
    audit = InstallationProxyService.audit_apps({
        "com.example.store": {
            "ApplicationType": "User",
            "CFBundleDisplayName": "Store App",
            "CFBundleIdentifier": "com.example.store",
            "CFBundleShortVersionString": "1.2.3",
            "CFBundleURLTypes": [
                {
                    "CFBundleURLName": "example",
                    "CFBundleURLSchemes": ["storeapp", "storeapp-auth"],
                },
            ],
            "CFBundleVersion": "123",
            "Container": "/private/var/mobile/Containers/Data/Application/store",
            "Entitlements": {
                "application-identifier": "TEAMID.com.example.store",
                "com.apple.developer.associated-domains": ["applinks:example.invalid"],
                "com.apple.security.application-groups": ["group.com.example.store"],
                "keychain-access-groups": ["TEAMID.com.example.store"],
            },
            "NSCameraUsageDescription": "camera",
            "NSLocationWhenInUseUsageDescription": "location",
            "Path": "/private/var/containers/Bundle/Application/store/Store.app",
            "SignerIdentity": "Apple iPhone OS Application Signing",
            "UIBackgroundModes": ["location", "fetch"],
            "UIFileSharingEnabled": True,
        },
        "com.example.enterprise": {
            "ApplicationType": "User",
            "CFBundleDisplayName": "Enterprise App",
            "CFBundleIdentifier": "com.example.enterprise",
            "Entitlements": {
                "beta-reports-active": True,
                "get-task-allow": True,
            },
            "IsAppClip": True,
            "IsDemotedApp": True,
            "IsPlaceholder": True,
            "SignerIdentity": "iPhone Distribution: Example Corp",
        },
        "com.apple.system": {
            "ApplicationType": "System",
            "CFBundleDisplayName": "System App",
            "CFBundleIdentifier": "com.apple.system",
        },
    })

    assert audit["app_count"] == 3
    assert audit["application_types"] == {"System": 1, "User": 2}
    assert audit["background_modes"] == {"fetch": 1, "location": 1}
    assert audit["privacy_usage_descriptions"] == {"camera": 1, "location": 1}
    assert audit["signer_identities"] == {
        "Apple iPhone OS Application Signing": 1,
        "iPhone Distribution: Example Corp": 1,
    }
    assert audit["flags"] == {
        "has_app_clips": True,
        "has_beta_apps": True,
        "has_debuggable_apps": True,
        "has_demoted_apps": True,
        "has_file_sharing_enabled_apps": True,
        "has_non_app_store_user_apps": True,
        "has_placeholder_apps": True,
        "has_user_apps": True,
    }
    assert [finding["category"] for finding in audit["findings"]] == [
        "placeholder",
        "demoted",
        "app_clip",
        "beta",
        "debuggable",
        "non_app_store_signer",
        "file_sharing_enabled",
    ]
    assert audit["apps"] == [
        {
            "application_type": "System",
            "bundle_identifier": "com.apple.system",
            "display_name": "System App",
        },
        {
            "application_type": "User",
            "bundle_identifier": "com.example.enterprise",
            "display_name": "Enterprise App",
            "entitlements": {
                "beta_reports_active": True,
                "get_task_allow": True,
            },
            "is_app_clip": True,
            "is_demoted": True,
            "is_placeholder": True,
            "signer_identity": "iPhone Distribution: Example Corp",
        },
        {
            "application_type": "User",
            "background_modes": ["fetch", "location"],
            "bundle_identifier": "com.example.store",
            "display_name": "Store App",
            "entitlements": {
                "application_group_count": 1,
                "associated_domain_count": 1,
                "keychain_access_group_count": 1,
            },
            "file_sharing_enabled": True,
            "privacy_usage_descriptions": ["camera", "location"],
            "short_version": "1.2.3",
            "signer_identity": "Apple iPhone OS Application Signing",
            "url_scheme_count": 2,
            "version": "123",
        },
    ]

    audit_text = str(audit)
    assert "/private/var/" not in audit_text
    assert "TEAMID.com.example.store" not in audit_text
    assert "applinks:example.invalid" not in audit_text
    assert "group.com.example.store" not in audit_text
    assert "storeapp-auth" not in audit_text


def test_apps_audit_uses_mapping_key_when_bundle_identifier_is_missing() -> None:
    audit = InstallationProxyService.audit_apps({
        "com.example.missing": {
            "ApplicationType": "User",
            "CFBundleDisplayName": "Missing Identifier",
        },
    })

    assert audit["apps"] == [
        {
            "application_type": "User",
            "bundle_identifier": "com.example.missing",
            "display_name": "Missing Identifier",
        },
    ]
