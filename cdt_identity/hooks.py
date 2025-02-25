import functools
import logging

from django.http import HttpRequest, HttpResponse


logger = logging.getLogger(__name__)


def log_hook_call(hook_func):
    """
    Decorator that logs a debug message with the hook function's name before executing it.

    Args:
        hook_func (function): The hook function to decorate.

    Returns:
        function: The decorated hook function.
    """

    @functools.wraps(hook_func)
    def wrapper(*args, **kwargs):
        logger.debug(f"{hook_func.__name__} hook called")
        return hook_func(*args, **kwargs)

    return wrapper


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

    @classmethod
    @log_hook_call
    def pre_login(cls, request: HttpRequest) -> None:
        """
        Hook method that runs before initiating login with the Identity Gateway.

        Default Behavior:
        - No operation is performed.

        Consumers can override this method to execute custom logic before login.

        Args:
            request (HttpRequest): The incoming Django request object.
        """
        pass

    @classmethod
    @log_hook_call
    def post_login(cls, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """
        Hook method that runs after a successful login with the Identity Gateway.

        Default behavior:
        - No operation is performed; returns the HttpResponse unchanged.

        Consumers can override this method to perform additional processing on the response.

        Args:
            request (HttpRequest): The Django request object.
            response (HttpResponse): The HttpResponse produced by the login view.

        Returns:
            HttpResponse: The potentially modified response.
        """
        return response

    @classmethod
    @log_hook_call
    def cancel_login(cls, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """
        Hook method that runs when login with the Identity Gateway is canceled by the user.

        Default behavior:
        - No operation is performed; returns the HttpResponse unchanged.

        Consumers can override this method to execute custom logic on cancel.

        Args:
            request (HttpRequest): The Django request object.
            response (HttpResponse): The HttpResponse produced by the cancel view.

        Returns:
            HttpResponse: The potentially modified response.
        """
        return response

    @classmethod
    @log_hook_call
    def pre_logout(cls, request: HttpRequest) -> None:
        """
        Hook method that runs before initiating logout with the Identity Gateway.

        Default behavior:
        - No operation is performed.

        Consumers can override this method to execute custom logic before logout.

        Args:
            request (HttpRequest): The incoming Django request object.
        """
        pass

    @classmethod
    @log_hook_call
    def post_logout(cls, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """Hook method that runs when logout with the Identity Gateway is complete.

        Default behavior:
        - No operation is performed; returns the HttpResponse unchanged.

        Consumers can override this method to execute custom logic on completion.

        Args:
            request (HttpRequest): The Django request object.
            response (HttpResponse): The HttpResponse produced by the post_logout view.

        Returns:
            response (HttpResponse): The potentially modified response.
        """
        return response
