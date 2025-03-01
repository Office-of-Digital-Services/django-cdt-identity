from cdt_identity import urls, views


def test_endpoints_view():
    for endpoint in urls.endpoints:
        assert hasattr(views, endpoint)
