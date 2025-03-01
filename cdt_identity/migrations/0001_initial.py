# Generated by Django 5.1.6 on 2025-03-01 00:29

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="IdentityGatewayConfig",
            fields=[
                ("id", models.AutoField(primary_key=True, serialize=False)),
                ("client_name", models.SlugField(help_text="The name of this Identity Gateway client", unique=True)),
                ("client_id", models.UUIDField(help_text="The client ID for this Identity Gateway client")),
                ("authority", models.URLField(help_text="The fully qualified HTTPS domain name for the authority server")),
                (
                    "scheme",
                    models.CharField(
                        help_text="The default authentication scheme for connections to the authority server", max_length=100
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="ClaimsVerificationRequest",
            fields=[
                ("id", models.AutoField(primary_key=True, serialize=False)),
                (
                    "scopes",
                    models.CharField(
                        help_text="A space-separated list of identifiers used to specify what information is being requested",
                        max_length=200,
                    ),
                ),
                (
                    "eligibility_claim",
                    models.CharField(help_text="The claim that is used to verify eligibility", max_length=50),
                ),
                (
                    "extra_claims",
                    models.CharField(
                        blank=True,
                        default="",
                        help_text="(Optional) A space-separated list of any additional claims",
                        max_length=200,
                    ),
                ),
                (
                    "scheme",
                    models.CharField(
                        blank=True,
                        default="",
                        help_text="(Optional) The authentication scheme to use instead of that configured by an IdentityGatewayConnection.",  # noqa: E501
                        max_length=50,
                    ),
                ),
            ],
        ),
    ]
