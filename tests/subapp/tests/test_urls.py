from django.core.management import call_command


def test_subapp_urls_registered_properly():
    """Confirm that subapp OAuth URLs are being registered with a nested namespace."""

    assert (
        "/subapp/\ttests.subapp.urls.index\tsubapp:index\n/subapp/oauth/authorize\tcdt_identity.views.authorize\tsubapp:cdt:authorize\n/subapp/oauth/cancel\tcdt_identity.views.cancel\tsubapp:cdt:cancel\n/subapp/oauth/failure_to_proof\tcdt_identity.views.failure_to_proof\tsubapp:cdt:failure_to_proof\n/subapp/oauth/login\tcdt_identity.views.login\tsubapp:cdt:login\n/subapp/oauth/logout\tcdt_identity.views.logout\tsubapp:cdt:logout\n/subapp/oauth/post_logout\tcdt_identity.views.post_logout\tsubapp:cdt:post_logout"  # noqa: E501
        in call_command("show_urls")
    )
