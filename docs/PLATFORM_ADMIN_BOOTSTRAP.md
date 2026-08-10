# Platform Administrator bootstrap

The initial Platform Administrator is created only through the explicit
operator command below. Application startup and first login never run this
workflow.

Use the authoritative HCL.CS issuer and subject whenever possible:

```bash
AUTH_ENABLED=true DATABASE_URL='<secret-injected-database-url>' \
python scripts/bootstrap_platform_admin.py \
  --issuer 'https://identity.example.internal' \
  --subject 'exact-immutable-subject' \
  --change-reference 'CHANGE-1234' \
  --confirm BOOTSTRAP_PLATFORM_ADMIN
```

Alternative exact selectors are `--user-id`, `--employee-id`, or `--email`.
Employee ID and email must resolve to exactly one existing local user. A
subject supplied without `--issuer` uses the deprecated exact
`external_iam_user_id` compatibility selector.

The target must already be active and email verified. The operation is
idempotent for the selected administrator and is rejected when a different
effective Platform Administrator already exists. It creates no tenant,
membership, or tenant role.
