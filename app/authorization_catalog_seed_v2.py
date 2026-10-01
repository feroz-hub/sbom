"""Frozen V2 control-plane boundary. Never import live permission constants here."""

TENANT_CONFIGURATION_PERMISSIONS_V2 = frozenset({
    "tenant:ai:read", "tenant:ai:update", "tenant:ai:test",
    "tenant:lifecycle-provider:read", "tenant:lifecycle-provider:update",
    "tenant:lifecycle-provider:test", "tenant:lifecycle-provider:sync",
})

PLATFORM_ADMIN_PERMISSIONS_V2 = frozenset(
    {
        "platform:admin",
        "platform:tenant:read",
        "platform:tenant:create",
        "platform:tenant:update_status",
        "platform:tenant:bootstrap_admin",
        "platform:tenant:recover_admin",
        "platform:administrator:read",
        "platform:administrator:grant",
        "platform:administrator:revoke",
        "platform:authorization:read",
        "platform:authorization:manage",
        "platform:health:read",
        "platform:ai:read",
        "platform:ai:update",
        "platform:ai:test",
        "platform:lifecycle-provider:read",
        "platform:lifecycle-provider:update",
        "platform:lifecycle-provider:test",
        "platform:lifecycle-provider:sync",
    }
)
