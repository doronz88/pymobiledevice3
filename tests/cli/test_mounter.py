import pytest

from pymobiledevice3.cli.mounter import sanitize_version


@pytest.mark.parametrize('version, sanitized', [
    ('14.5', '14.5'),
    ('14.5.1', '14.5'),
    ('0.0', '0.0'),
    ('9999.9999', '9999.9999'),
    ('9999.9999.9999', '9999.9999'),
])
def test_sanitize_version(version, sanitized):
    assert sanitize_version(version) == sanitized
