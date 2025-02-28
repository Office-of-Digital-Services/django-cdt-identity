import logging

from django.http import HttpRequest, HttpResponse
import pytest

from cdt_identity.claims import ClaimsResult
from cdt_identity.hooks import log_hook_call, text_response, DefaultHooks
from cdt_identity.models import ClaimsVerificationRequest


@log_hook_call
def dummy_hook(x):
    return x * 2


def test_log_hook_call_decorator_logs_debug(caplog):
    """Test that the log_hook_call decorator logs a debug message with the hook function's name."""
    with caplog.at_level(logging.DEBUG):
        result = dummy_hook(3)

    assert any("dummy_hook hook called" in record.message for record in caplog.records)
    assert result == 6


def test_text_response():
    content = "this is content"

    response = text_response(content)

    assert isinstance(response, HttpResponse)
    assert response.status_code == 200
    assert response.content.decode() == content


@pytest.mark.parametrize(
    "hook_func,args",
    [
        (DefaultHooks.pre_login, (HttpRequest(),)),
        (DefaultHooks.post_login, (HttpRequest(), HttpResponse())),
        (DefaultHooks.cancel_login, (HttpRequest(), HttpResponse())),
        (DefaultHooks.pre_authorize, (HttpRequest(),)),
        (DefaultHooks.post_authorize, (HttpRequest(),)),
        (DefaultHooks.pre_claims_verification, (HttpRequest(), ClaimsVerificationRequest())),
        (DefaultHooks.claims_verified_eligible, (HttpRequest(), ClaimsVerificationRequest(), ClaimsResult())),
        (DefaultHooks.claims_verified_not_eligible, (HttpRequest(), ClaimsVerificationRequest(), ClaimsResult())),
        (DefaultHooks.pre_logout, (HttpRequest(),)),
        (DefaultHooks.post_logout, (HttpRequest(), HttpResponse())),
        (DefaultHooks.system_error, (HttpRequest(), Exception())),
    ],
)
def test_hook_logging(caplog, hook_func, args):
    """
    Test that the hook logs the expected debug message.
    """
    with caplog.at_level(logging.DEBUG):
        hook_func(*args)

    assert any(f"{hook_func.__name__} hook called" in record.message for record in caplog.records)


def test_post_login():
    request, response = HttpRequest(), HttpResponse()

    result = DefaultHooks.post_login(request, response)

    assert result == response


def test_cancel_login():
    request, response = HttpRequest(), HttpResponse()

    result = DefaultHooks.cancel_login(request, response)

    assert result == response


def test_claims_verified_eligible(assert_response):
    response = DefaultHooks.claims_verified_eligible(HttpRequest(), ClaimsVerificationRequest(), ClaimsResult())

    assert_response(response, status_code=200, content="Claims were verified for eligibility.")


def test_claims_verified_not_eligible(assert_response):
    response = DefaultHooks.claims_verified_not_eligible(HttpRequest(), ClaimsVerificationRequest(), ClaimsResult())

    assert_response(response, status_code=200, content="Claims were not verified for eligibility.")


def test_post_logout():
    request, response = HttpRequest(), HttpResponse()

    result = DefaultHooks.post_logout(request, response)

    assert result == response


def test_system_error(caplog, assert_response):
    request, exception = HttpRequest(), Exception("Exception occurred.")

    with caplog.at_level(logging.ERROR):
        response = DefaultHooks.system_error(request, exception)

    assert_response(response, status_code=500, content="A system error occurred.")
    assert any("A system error occurred." in record.message for record in caplog.records)
    assert any("Exception occurred." in record.exc_text for record in caplog.records)
