from dataclasses import asdict
import logging

from django.http import HttpRequest

from .claims import ClaimsResult
from .models import ClaimsVerificationRequest, IdentityGatewayConfig


logger = logging.getLogger(__name__)


class Session:

    _keys_client = "cdt_idg_client"
    _keys_request = "cdt_idg_request"
    _keys_result = "cdt_idg_result"

    def __init__(
        self,
        request: HttpRequest,
        reset: bool = False,
        client_config: IdentityGatewayConfig = None,
        claims_request: ClaimsVerificationRequest = None,
        claims_result: ClaimsResult = None,
    ):
        """Initialize a new CDT Identity Gateway session wrapper for this request."""

        self.request = request
        self.session = request.session

        if reset:
            self.client_config = None
            self.claims_request = None
            self.claims_result = ClaimsResult()
        if client_config:
            self.client_config = client_config
        if claims_request:
            self.claims_request = claims_request
        if claims_result:
            self.claims_result = claims_result

    @property
    def client_config(self) -> IdentityGatewayConfig:
        val = self.session.get(self._keys_client)
        return IdentityGatewayConfig.objects.filter(pk=val).first()

    @client_config.setter
    def client_config(self, value: IdentityGatewayConfig) -> None:
        if value:
            self.session[self._keys_client] = str(value.id)
        else:
            self.session[self._keys_client] = None

    @property
    def claims_request(self) -> ClaimsVerificationRequest:
        val = self.session.get(self._keys_request)
        return ClaimsVerificationRequest.objects.filter(pk=val).first()

    @claims_request.setter
    def claims_request(self, value: ClaimsVerificationRequest) -> None:
        if value:
            self.session[self._keys_request] = str(value.id)
        else:
            self.session[self._keys_request] = None

    @property
    def claims_result(self) -> ClaimsResult:
        val = self.session.get(self._keys_result, {})
        return ClaimsResult(**val)

    @claims_result.setter
    def claims_result(self, value: ClaimsResult) -> None:
        self.session[self._keys_result] = asdict(value)

    def has_verified_claims(self):
        """Return True if this session has any verified claims. False otherwise."""
        return bool(self.claims_result) and bool(self.claims_result.verified)

    def has_verified_eligibility(self):
        """Return True if this session has the verified eligibility claim. False otherwise."""
        try:
            return self.has_verified_claims() and self.claims_request.eligibility_claim in self.claims_result
        except Exception:
            return False
