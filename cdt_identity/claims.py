from dataclasses import dataclass, field
import logging

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ClaimsResult:
    verified: dict[str, str | bool] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)

    def __contains__(self, claim: str):
        """Check if a claim is in the processed claims."""
        return claim in self.verified

    def __getitem__(self, claim: str):
        """Allow dictionary-style access to claims."""
        return self.verified[claim]

    def get(self, claim: str, default=None):
        """Return the value for claim if the claim was processed, else default."""
        return self.verified.get(claim, default)


class ClaimsParser:

    @staticmethod
    def parse(userinfo: dict, expected_claims: list[str]) -> ClaimsResult:
        """Parse expected claims from the userinfo dict.

        - Boolean claims look like `{ "claim": "1" | "0" }` or `{ "claim": "true" }`
        - Value claims look like `{ "claim": "value" }`
        """
        claims = {}
        errors = {}

        for claim in expected_claims:
            claim_value = userinfo.get(claim)
            if not claim_value:
                logger.warning(f"userinfo did not contain claim: {claim}")
            try:
                claim_value = int(claim_value)
            except (TypeError, ValueError):
                pass
            if isinstance(claim_value, int):
                if claim_value == 1:
                    # a value of 1 means True
                    claims[claim] = True
                elif claim_value >= 10:
                    # values greater than 10 indicate an error condition
                    errors[claim] = claim_value
            elif isinstance(claim_value, str):
                if claim_value.lower() == "true":
                    # any form of the value "true" means True
                    claims[claim] = True
                elif claim_value.lower() != "false":
                    # if userinfo contains claim and the value is not "false", store the value
                    claims[claim] = claim_value

        return ClaimsResult(verified=claims, errors=errors)
