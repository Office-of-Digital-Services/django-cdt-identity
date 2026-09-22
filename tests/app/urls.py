from django.http import HttpRequest, JsonResponse
from django.urls import path
from django.utils.timezone import now


def index(request: HttpRequest):
    data = {"status": "OK", "timestamp": now().isoformat(sep=" ", timespec="seconds"), "app": "tests.app"}
    return JsonResponse(data)


urlpatterns = [
    path("", index, name="index"),
]
