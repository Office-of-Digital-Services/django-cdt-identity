from uuid import uuid4

import pytest

from django.core.exceptions import ValidationError
from django.db import IntegrityError

from cdt_identity.models import IdentityGatewayConfig


@pytest.fixture
def config_data():
    return {
        "client_name": "test-client",
        "client_id": str(uuid4()),
        "authority": "https://auth.example.com",
        "scheme": "bearer",
    }


@pytest.mark.django_db
def test_create(config_data):
    client = IdentityGatewayConfig.objects.create(**config_data)

    assert client.client_name == config_data["client_name"]
    assert client.client_id == config_data["client_id"]
    assert client.authority == config_data["authority"]
    assert client.scheme == config_data["scheme"]


@pytest.mark.django_db
def test_client_name_unique(config_data):
    IdentityGatewayConfig.objects.create(**config_data)

    with pytest.raises(IntegrityError):
        IdentityGatewayConfig.objects.create(**config_data)


@pytest.mark.django_db
def test_str_representation(config_data):
    client = IdentityGatewayConfig.objects.create(**config_data)
    assert str(client) == config_data["client_name"]


@pytest.mark.django_db
def test_invalid_client_name(config_data):
    config_data["client_name"] = "invalid with spaces"
    with pytest.raises(ValidationError):
        client = IdentityGatewayConfig(**config_data)
        client.full_clean()


@pytest.mark.django_db
@pytest.mark.parametrize(
    "field_name,max_length",
    [
        ("authority", 100),
        ("scheme", 100),
    ],
)
def test_max_length(config_data, field_name, max_length):
    config_data[field_name] = "x" * (max_length + 1)
    with pytest.raises(ValidationError):
        client = IdentityGatewayConfig(**config_data)
        client.full_clean()
