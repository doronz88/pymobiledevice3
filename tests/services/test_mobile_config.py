from pymobiledevice3.services.mobile_config import MobileConfigService


def test_profile_audit_empty_response() -> None:
    audit = MobileConfigService.audit_profile_list({
        "OrderedIdentifiers": [],
        "ProfileManifest": {},
        "ProfileMetadata": {},
        "Status": "Acknowledged",
    })

    assert audit == {
        "findings": [],
        "flags": {
            "has_certificates": False,
            "has_dns_settings": False,
            "has_global_http_proxy": False,
            "has_mdm": False,
            "has_removal_disallowed_profiles": False,
            "has_restrictions": False,
            "has_root_certificates": False,
            "has_vpn": False,
            "has_web_content_filter": False,
            "has_wifi": False,
        },
        "payload_count": 0,
        "payload_types": {},
        "profile_count": 0,
        "profiles": [],
    }


def test_profile_audit_summarizes_profile_payloads_without_raw_content() -> None:
    audit = MobileConfigService.audit_profile_list({
        "OrderedIdentifiers": ["com.example.profile"],
        "ProfileManifest": {},
        "ProfileMetadata": {
            "com.example.profile": {
                "PayloadContent": [
                    {
                        "PayloadDisplayName": "Management",
                        "PayloadIdentifier": "com.example.profile.mdm",
                        "PayloadType": "com.apple.mdm",
                        "PayloadUUID": "payload-1",
                        "PayloadVersion": 1,
                        "ServerURL": "https://mdm.example.invalid",
                    },
                    {
                        "PayloadDisplayName": "Root CA",
                        "PayloadIdentifier": "com.example.profile.root",
                        "PayloadType": "com.apple.security.root",
                        "PayloadUUID": "payload-2",
                        "PayloadVersion": 1,
                        "PayloadContent": b"certificate-bytes",
                    },
                    {
                        "IPSec": {
                            "AuthenticationMethod": "SharedSecret",
                            "SharedSecret": "secret",
                        },
                        "PayloadDisplayName": "VPN",
                        "PayloadIdentifier": "com.example.profile.vpn",
                        "PayloadType": "com.apple.vpn.managed",
                        "PayloadUUID": "payload-3",
                        "PayloadVersion": 1,
                    },
                ],
                "PayloadDisplayName": "Example Profile",
                "PayloadIdentifier": "com.example.profile",
                "PayloadOrganization": "Example Org",
                "PayloadRemovalDisallowed": True,
                "PayloadType": "Configuration",
                "PayloadUUID": "profile-uuid",
                "PayloadVersion": 1,
            },
        },
        "Status": "Acknowledged",
    })

    assert audit["profile_count"] == 1
    assert audit["payload_count"] == 3
    assert audit["payload_types"] == {
        "com.apple.mdm": 1,
        "com.apple.security.root": 1,
        "com.apple.vpn.managed": 1,
    }
    assert audit["flags"]["has_certificates"] is True
    assert audit["flags"]["has_mdm"] is True
    assert audit["flags"]["has_removal_disallowed_profiles"] is True
    assert audit["flags"]["has_root_certificates"] is True
    assert audit["flags"]["has_vpn"] is True
    assert [finding["category"] for finding in audit["findings"]] == [
        "mdm",
        "root_certificate",
        "vpn",
    ]
    assert audit["profiles"] == [
        {
            "display_name": "Example Profile",
            "identifier": "com.example.profile",
            "organization": "Example Org",
            "payload_count": 3,
            "payload_types": [
                "com.apple.mdm",
                "com.apple.security.root",
                "com.apple.vpn.managed",
            ],
            "payloads": [
                {
                    "display_name": "Management",
                    "identifier": "com.example.profile.mdm",
                    "type": "com.apple.mdm",
                    "uuid": "payload-1",
                    "version": 1,
                },
                {
                    "display_name": "Root CA",
                    "identifier": "com.example.profile.root",
                    "type": "com.apple.security.root",
                    "uuid": "payload-2",
                    "version": 1,
                },
                {
                    "display_name": "VPN",
                    "identifier": "com.example.profile.vpn",
                    "type": "com.apple.vpn.managed",
                    "uuid": "payload-3",
                    "version": 1,
                },
            ],
            "removal_disallowed": True,
            "uuid": "profile-uuid",
            "version": 1,
        },
    ]

    audit_text = str(audit)
    assert "certificate-bytes" not in audit_text
    assert "ServerURL" not in audit_text
    assert "SharedSecret" not in audit_text
    assert "secret" not in audit_text


def test_profile_audit_uses_manifest_payloads_when_metadata_has_no_payload_content() -> None:
    audit = MobileConfigService.audit_profile_list({
        "OrderedIdentifiers": [],
        "ProfileManifest": {
            "com.example.wifi": {
                "PayloadContent": [
                    {
                        "PayloadIdentifier": "com.example.wifi.payload",
                        "PayloadType": "com.apple.wifi.managed",
                    },
                ],
            },
        },
        "ProfileMetadata": {
            "com.example.wifi": {
                "PayloadDisplayName": "Wi-Fi Profile",
                "PayloadIdentifier": "com.example.wifi",
                "PayloadType": "Configuration",
            },
        },
        "Status": "Acknowledged",
    })

    assert audit["flags"]["has_wifi"] is True
    assert audit["payload_types"] == {"com.apple.wifi.managed": 1}
    assert audit["profiles"][0]["payloads"] == [
        {
            "identifier": "com.example.wifi.payload",
            "type": "com.apple.wifi.managed",
        },
    ]
