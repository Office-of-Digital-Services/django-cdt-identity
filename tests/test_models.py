from uuid import uuid4

from django.core.exceptions import ValidationError
from django.db import IntegrityError
import pytest

from cdt_identity.models import ClaimsVerificationRequest, IdentityGatewayConfig


@pytest.mark.django_db
class TestClaimsVerificationRequest:

    @pytest.fixture
    def config_data(self):
        return {
            "system_name": "test-name",
            "scopes": "one two",
            "eligibility_claim": "test-claim",
            "extra_claims": "three four five",
            "scheme": "bearer-override",
        }

    def test_create(self, config_data):
        req = ClaimsVerificationRequest.objects.create(**config_data)

        assert req.system_name == config_data["system_name"]
        assert req.scopes == config_data["scopes"]
        assert req.eligibility_claim == config_data["eligibility_claim"]
        assert req.extra_claims == config_data["extra_claims"]
        assert req.scheme == config_data["scheme"]

    @pytest.mark.parametrize(
        "field_name,max_length",
        [
            ("system_name", 50),
            ("scopes", 200),
            ("eligibility_claim", 50),
            ("extra_claims", 200),
            ("scheme", 50),
        ],
    )
    def test_max_length(self, config_data, field_name, max_length):
        config_data[field_name] = "x" * (max_length + 1)
        with pytest.raises(ValidationError):
            req = ClaimsVerificationRequest(**config_data)
            req.full_clean()

    @pytest.mark.parametrize(
        "field_name",
        [
            "system_name",
            "scopes",
            "eligibility_claim",
        ],
    )
    def test_not_blank(self, config_data, field_name):
        config_data[field_name] = ""
        with pytest.raises(ValidationError):
            req = ClaimsVerificationRequest(**config_data)
            req.full_clean()

    @pytest.mark.parametrize(
        "field_name,default",
        [
            ("extra_claims", ""),
            ("scheme", ""),
        ],
    )
    def test_default(self, config_data, field_name, default):
        config_data.pop(field_name)
        req = ClaimsVerificationRequest.objects.create(**config_data)

        assert getattr(req, field_name) == default

    @pytest.mark.parametrize(
        "eligibility_claim,extra_claims,expected",
        [
            ("   claim1   ", "", "claim1"),
            ("claim1", "    claim2   ", "claim1 claim2"),
            ("claim1", "claim2 claim3", "claim1 claim2 claim3"),
        ],
    )
    def test_claims_props(self, eligibility_claim, extra_claims, expected):
        req = ClaimsVerificationRequest.objects.create(eligibility_claim=eligibility_claim, extra_claims=extra_claims)

        assert req.claims == expected
        assert req.claims_list == expected.split(" ")

    def test_str(self, config_data):
        req = ClaimsVerificationRequest(**config_data)

        assert str(req) == config_data["system_name"]


@pytest.mark.django_db
class TestIdentityGatewayConfig:
    @pytest.fixture
    def config_data(self):
        return {
            "client_name": "test-client",
            "client_id": str(uuid4()),
            "authority": "https://auth.example.com",
            "scheme": "bearer",
        }

    def test_create(self, config_data):
        client = IdentityGatewayConfig.objects.create(**config_data)

        assert client.client_name == config_data["client_name"]
        assert client.client_id == config_data["client_id"]
        assert client.authority == config_data["authority"]
        assert client.scheme == config_data["scheme"]

    def test_client_name_unique(self, config_data):
        IdentityGatewayConfig.objects.create(**config_data)

        with pytest.raises(IntegrityError):
            IdentityGatewayConfig.objects.create(**config_data)

    def test_str_representation(self, config_data):
        client = IdentityGatewayConfig.objects.create(**config_data)
        assert str(client) == config_data["client_name"]

    def test_invalid_client_name(self, config_data):
        config_data["client_name"] = "invalid with spaces"
        with pytest.raises(ValidationError):
            client = IdentityGatewayConfig(**config_data)
            client.full_clean()

    @pytest.mark.parametrize(
        "field_name,max_length",
        [
            ("authority", 100),
            ("scheme", 100),
        ],
    )
    def test_max_length(self, config_data, field_name, max_length):
        config_data[field_name] = "x" * (max_length + 1)
        with pytest.raises(ValidationError):
            client = IdentityGatewayConfig(**config_data)
            client.full_clean()
