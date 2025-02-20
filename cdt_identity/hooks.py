class DefaultHooks:
    """Default hooks implementation.

    Consumers can override hooks as needed by implementing a new class that inherits from `DefaultHooks`,
    then overriding the `hooks` parameter when registering URLs for this app:

        ```
        # file: urls.py

        from django.urls import include, path
        from cdt_identity.hooks import DefaultHooks

        class CustomHooks(DefaultHooks):
            # override hook @classmethods as needed
            pass

        urlpatterns = [
            # other paths...
            path("prefix/", include("cdt_identity.urls"), {"hooks": CustomHooks}),
        ]
        ```
    """

    pass
