import functools
from enum import StrEnum, auto
import logging

from django.http import HttpRequest, HttpResponse, HttpResponseServerError

from cdt_identity import claims, models


logger = logging.getLogger(__name__)


class Operation(StrEnum):
    INIT = auto()
    AUTHORIZE_REDIRECT = auto()
    AUTHORIZE_ACCESS_TOKEN = auto()
    LOAD_SERVER_METADATA = auto()


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


def text_response(content: str) -> HttpResponse:
    """Create an HttpResponse with content_type=text/plain."""
    return HttpResponse(content, content_type="text/plain")


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
    def post_login(cls, request: HttpRequest) -> None:
        """
        Hook method that runs after a successful login with the Identity Gateway.

        Default behavior:
        - No operation is performed.

        Consumers can override this method to execute custom logic after login.

        Args:
            request (HttpRequest): The Django request object.
        """
        pass

    @classmethod
    @log_hook_call
    def cancel_login(cls, request: HttpRequest) -> HttpResponse:
        """
        Hook method that runs when login with the Identity Gateway is canceled by the user.

        Default behavior:
        - Returns a plaintext HttpResponse indicating login cancellation.

        Consumers can override this method to execute custom logic on cancel.

        Args:
            request (HttpRequest): The Django request object.

        Returns:
            HttpResponse: The response to login cancellation.
        """
        return text_response("Login was cancelled.")

    @classmethod
    @log_hook_call
    def pre_authorize(cls, request: HttpRequest) -> None:
        """
        Hook method that runs before attempting token authorization with the Identity Gateway.

        Default Behavior:
        - No operation is performed.

        Consumers can override this method to execute custom logic before authorization.

        Args:
            request (HttpRequest): The incoming Django request object.
        """
        pass

    @classmethod
    @log_hook_call
    def post_authorize(cls, request: HttpRequest) -> None:
        """
        Hook method that runs after token authorization with the Identity Gateway.

        Default Behavior:
        - No operation is performed.

        Consumers can override this method to execute custom logic after authorization.

        Args:
            request (HttpRequest): The incoming Django request object.
        """
        pass

    @classmethod
    @log_hook_call
    def pre_claims_verification(cls, request: HttpRequest, claims_request: models.ClaimsVerificationRequest) -> None:
        """
        Hook method that runs before initiating claims verification of the Identity Gateway's response.

        Default Behavior:
        - No operation is performed.

        Consumers can override this method to execute custom logic before claims verification.

        Args:
            request (HttpRequest): The incoming Django request object.
            claims_request (ClaimsVerificationRequest): The configuration used for claims verification.
        """
        pass

    @classmethod
    @log_hook_call
    def claims_verified_eligible(
        cls, request: HttpRequest, claims_request: models.ClaimsVerificationRequest, claims_result: claims.ClaimsResult
    ) -> HttpResponse:
        """
        Hook method that runs on successful eligibility verification of the Identity Gateway's response.

        Default Behavior:
        - An `HttpResponse` is generated, indicating successful eligibility verification.

        Consumers can override this method to execute custom logic after claims verification.

        Args:
            request (HttpRequest): The incoming Django request object.
            claims_request (ClaimsVerificationRequest): The configuration used for claims verification.
            claims_result (ClaimsResult): The result of claims verification.

        Returns:
            response (HttpResponse): An appropriate response to eligibility being verified.
        """
        return text_response("Claims were verified for eligibility.")

    @classmethod
    @log_hook_call
    def claims_verified_not_eligible(
        cls, request: HttpRequest, claims_request: models.ClaimsVerificationRequest, claims_result: claims.ClaimsResult
    ) -> HttpResponse:
        """
        Hook method that runs on unsuccessful eligibility verification of the Identity Gateway's response.

        Default Behavior:
        - An `HttpResponse` is generated, indicating an unsuccessful eligibility verification.

        Consumers can override this method to execute custom logic after claims verification.

        Args:
            request (HttpRequest): The incoming Django request object.
            claims_request (ClaimsVerificationRequest): The configuration used for claims verification.
            claims_result (ClaimsResult): The result of claims verification.

        Returns:
            response (HttpResponse): An appropriate response to eligibility not being verified.
        """
        return text_response("Claims were not verified for eligibility.")

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
    def post_logout(cls, request: HttpRequest) -> HttpResponse:
        """Hook method that runs when logout with the Identity Gateway is complete.

        Default behavior:
        - An `HttpResponse` is generated, indicating logout was successful.

        Consumers can override this method to execute custom logic on logout completion.

        Args:
            request (HttpRequest): The Django request object.

        Returns:
            response (HttpResponse): An appropriate response to logout completion.
        """
        return text_response("Logout complete.")

    @classmethod
    @log_hook_call
    def system_error(cls, request: HttpRequest, exception: Exception, operation: Operation) -> HttpResponse:
        """Hook method that runs when an exception occurs.

        Default behavior:
        - An `HttpResponseServerError` is generated, indicating an system error occurred.

        Consumers can override this method to execute custom logic to handle system errors.

        Args:
            request (HttpRequest): The Django request object.
            exception (Exception): The exception that was raised.
            operation (Operation): The operation that was being attempted when the error occurred.

        Returns:
            response (HttpResponse): An appropriate response to the exception being raised.
        """
        logger.error("A system error occurred.", exc_info=exception)
        return HttpResponseServerError("A system error occurred.")
