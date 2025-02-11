# Generated by Django 5.1.6 on 2025-02-11 15:43

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
    ]
