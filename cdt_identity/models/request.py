from uuid import uuid4

from django.db import models


class ClaimsVerificationRequest(models.Model):
    """Model for Identity Gateway claims verification request."""

    id = models.UUIDField(
        primary_key=True,
        default=uuid4,
        editable=False,
    )
    system_name = models.SlugField(
        help_text="A short label for this request within the configuration system.",
        max_length=50,
        unique=True,
    )
    scopes = models.CharField(
        help_text="A space-separated list of identifiers used to specify what information is being requested.",
        max_length=200,
    )
    eligibility_claim = models.CharField(
        help_text="The claim that is used to verify eligibility.",
        max_length=50,
    )
    extra_claims = models.CharField(
        blank=True,
        default="",
        help_text="(Optional) A space-separated list of any additional claims.",
        max_length=200,
    )
    scheme = models.CharField(
        blank=True,
        default="",
        help_text="(Optional) The authentication scheme to use instead of that configured by an IdentityGatewayConnection.",
        max_length=50,
    )

    @property
    def all_claims(self):
        claims = (self.eligibility_claim.strip(), self.extra_claims.strip())
        return " ".join(claims).strip()

    def __str__(self):
        return self.system_name
