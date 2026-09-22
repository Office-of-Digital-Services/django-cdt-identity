from django.http import HttpRequest, JsonResponse
from django.urls import path, include
from django.utils.timezone import now

from cdt_identity import views
from cdt_identity.routes import Routes


def index(request: HttpRequest):
    data = {"status": "OK", "timestamp": now().isoformat(sep=" ", timespec="seconds"), "app": "tests.subapp"}
    return JsonResponse(data)


app_name = "subapp"

oauth_patterns = [
    path(Routes.login, views.login, name=Routes.login),
    path(Routes.authorize, views.authorize, name=Routes.authorize),
    path(Routes.cancel, views.cancel, name=Routes.cancel),
    path(Routes.failure_to_proof, views.failure_to_proof, name=Routes.failure_to_proof),
    path(Routes.logout, views.logout, name=Routes.logout),
    path(Routes.post_logout, views.post_logout, name=Routes.post_logout),
]

urlpatterns = [
    # /subapp/
    path("", index, name="index"),
    #
    # This results in OAuth URLs in the form `subapp/oauth/*` with names of `subapp:cdt:*`
    path("oauth/", include((oauth_patterns, "cdt"), namespace="cdt")),
]
