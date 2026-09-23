from django.core.management import call_command


def test_subapp_urls_registered_properly():
    """Confirm that subapp OAuth URLs are being registered with a nested namespace."""

    urls = call_command("show_urls")
    patterns = [
        [
            "/subapp/oauth/authorize",
            "cdt_identity.views.authorize",
            "subapp:cdt:authorize",
        ],
        [
            "/subapp/oauth/cancel",
            "cdt_identity.views.cancel",
            "subapp:cdt:cancel",
        ],
        [
            "/subapp/oauth/failure_to_proof",
            "cdt_identity.views.failure_to_proof",
            "subapp:cdt:failure_to_proof",
        ],
        [
            "/subapp/oauth/login",
            "cdt_identity.views.login",
            "subapp:cdt:login",
        ],
        [
            "/subapp/oauth/logout",
            "cdt_identity.views.logout",
            "subapp:cdt:logout",
        ],
        [
            "/subapp/oauth/post_logout",
            "cdt_identity.views.post_logout",
            "subapp:cdt:post_logout",
        ],
    ]
    for pattern in patterns:
        assert "\t".join(pattern) in urls
