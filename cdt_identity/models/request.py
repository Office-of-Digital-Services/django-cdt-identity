from django.db import models

from cdt_identity.routes import Routes


class ClaimsVerificationRequest(models.Model):
    """Model for Identity Gateway claims verification request."""

    id = models.AutoField(
        primary_key=True,
    )
    scopes = models.CharField(
        help_text="A space-separated list of identifiers used to specify what information is being requested",
        max_length=200,
    )
    eligibility_claim = models.CharField(
        help_text="The claim that is used to verify eligibility",
        max_length=50,
    )
    extra_claims = models.CharField(
        blank=True,
        default="",
        help_text="(Optional) A space-separated list of any additional claims",
        max_length=200,
    )
    scheme = models.CharField(
        blank=True,
        default="",
        help_text="(Optional) The authentication scheme to use instead of that configured by an IdentityGatewayConnection.",
        max_length=50,
    )
    redirect_fail = models.CharField(
        default=Routes.route_verify_fail,
        help_text="A Django route in the form of app:endpoint to redirect to after an unsuccessful claims check",
        max_length=50,
    )
    redirect_success = models.CharField(
        default=Routes.route_verify_success,
        help_text="A Django route in the form of app:endpoint to redirect to after a successful claims check",
        max_length=50,
    )
    redirect_post_logout = models.CharField(
        default=Routes.route_post_logout,
        help_text="A Django route in the form of app:endpoint to redirect to after a successful log out",
        max_length=50,
    )

    @property
    def all_claims(self):
        claims = (self.eligibility_claim.strip(), self.extra_claims.strip())
        return " ".join(claims).strip()
