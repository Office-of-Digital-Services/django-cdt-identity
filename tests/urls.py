from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("app/", include("tests.app.urls")),
    path("oauth/", include("cdt_identity.urls")),
]
