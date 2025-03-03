from uuid import uuid4

from django.db import models


class IdentityGatewayConfig(models.Model):
    """Model for Identity Gateway client configuration."""

    id = models.UUIDField(
        primary_key=True,
        default=uuid4,
        editable=False,
    )
    client_name = models.SlugField(
        help_text="The name of this Identity Gateway client",
        unique=True,
    )
    client_id = models.UUIDField(
        help_text="The client ID for this Identity Gateway client",
    )
    authority = models.URLField(
        help_text="The fully qualified HTTPS domain name for the authority server",
    )
    scheme = models.CharField(
        help_text="The default authentication scheme for connections to the authority server",
        max_length=100,
    )

    def __str__(self):
        return self.client_name
