from django.http import HttpRequest, JsonResponse
from django.urls import path, include
from django.utils.timezone import now


def index(request: HttpRequest):
    data = {"status": "OK", "timestamp": now().isoformat(sep=" ", timespec="seconds")}
    return JsonResponse(data)


urlpatterns = [
    path("", index, name="index"),
    path("oauth/", include("cdt_identity.urls")),
]
