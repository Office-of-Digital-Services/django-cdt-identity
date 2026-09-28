import importlib

from importlib.metadata import PackageNotFoundError


def test_version():
    from cdt_identity import VERSION

    assert VERSION != ""


def test_version_when_package_is_not_installed(mocker):
    mocker.patch("importlib.metadata.version", side_effect=PackageNotFoundError)

    import cdt_identity

    try:
        importlib.reload(cdt_identity)

        assert cdt_identity.VERSION == ""
    finally:
        mocker.stopall()
        importlib.reload(cdt_identity)
