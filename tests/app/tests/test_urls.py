from django.core.management import call_command


def test_app_urls_registered_properly():
    """Confirm that app-specific OAuth URLs are being registered with a nested namespace."""

    urls = call_command("show_urls")
    patterns = [
        [
            "/app/oauth/authorize",
            "cdt_identity.views.authorize",
            "app:cdt:authorize",
        ],
        [
            "/app/oauth/cancel",
            "cdt_identity.views.cancel",
            "app:cdt:cancel",
        ],
        [
            "/app/oauth/failure_to_proof",
            "cdt_identity.views.failure_to_proof",
            "app:cdt:failure_to_proof",
        ],
        [
            "/app/oauth/login",
            "cdt_identity.views.login",
            "app:cdt:login",
        ],
        [
            "/app/oauth/logout",
            "cdt_identity.views.logout",
            "app:cdt:logout",
        ],
        [
            "/app/oauth/post_logout",
            "cdt_identity.views.post_logout",
            "app:cdt:post_logout",
        ],
    ]
    for pattern in patterns:
        assert "\t".join(pattern) in urls
