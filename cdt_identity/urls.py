from django.urls import path

from . import views
from .routes import Routes

app_name = "cdt"

endpoints = [
    Routes.authorize,
    Routes.cancel,
    Routes.failure_to_proof,
    Routes.login,
    Routes.logout,
    Routes.post_logout,
]

urlpatterns = []

for endpoint in endpoints:
    # view functions
    urlpatterns.append(path(endpoint, getattr(views, endpoint), name=endpoint))
