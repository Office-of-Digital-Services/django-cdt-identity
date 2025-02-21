import logging

from cdt_identity.hooks import log_hook_call


@log_hook_call
def dummy_hook(x):
    return x * 2


def test_log_hook_call_decorator_logs_debug(caplog):
    """Test that the log_hook_call decorator logs a debug message with the hook function's name."""
    with caplog.at_level(logging.DEBUG):
        result = dummy_hook(3)

    assert any("dummy_hook hook called" in record.message for record in caplog.records)
    assert result == 6
