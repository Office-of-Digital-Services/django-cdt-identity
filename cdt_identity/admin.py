from django.contrib import admin

from .models import IdentityGatewayConfig, ClaimsVerificationRequest


@admin.register(IdentityGatewayConfig)
class IdentityGatewayConfigAdmin(admin.ModelAdmin):
    list_display = ("client_name", "authority", "scheme")


@admin.register(ClaimsVerificationRequest)
class ClaimsVerificationRequestAdmin(admin.ModelAdmin):
    list_display = ("system_name", "scopes", "eligibility_claim", "extra_claims", "scheme")
