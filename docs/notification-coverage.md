# Frontend action notification coverage

Audited against `frontend/src` on 2026-07-20. `PARTIAL` means the repository has
some feedback for the workflow but one or more variants still use inline-only
state or have not been migrated to the centralized safe error mapper.

| Module | Action | Success popup | Error popup | Confirmation | Tested |
| --- | --- | ---: | ---: | ---: | ---: |
| Projects | Create | YES | YES | NOT APPLICABLE | YES |
| Projects | Update | YES | YES | NOT APPLICABLE | YES |
| Projects | Delete/archive | YES | YES | YES | YES |
| Products | Create | YES | YES | NOT APPLICABLE | PARTIAL |
| Products | Update | YES | YES | NOT APPLICABLE | PARTIAL |
| Products | Delete | YES | YES | YES | PARTIAL |
| SBOM | Upload/import | YES | YES | NOT APPLICABLE | YES |
| SBOM | Validate | YES | YES | NOT APPLICABLE | PARTIAL |
| SBOM | Convert | YES | YES | NOT APPLICABLE | YES |
| SBOM | Delete/archive | YES | YES | YES | YES |
| Analysis | Start/queue | YES | YES | NOT APPLICABLE | PARTIAL |
| Analysis | Completion | YES | YES | NOT APPLICABLE | YES |
| Analysis | Cancel | NO | NO | NO | NO |
| Findings | Update/bulk update | PARTIAL | PARTIAL | NOT APPLICABLE | PARTIAL |
| VEX | Create/update/delete/import | NO | NO | NO | NO |
| Remediation | Update | PARTIAL | PARTIAL | NOT APPLICABLE | NO |
| Reports | Generate/download | YES | YES | NOT APPLICABLE | PARTIAL |
| Tenant users | Add | YES | YES | NOT APPLICABLE | YES |
| Tenant users | Role/status | YES | YES | YES | YES |
| Tenant users | Remove | YES | YES | YES | YES |
| Platform admins | Grant | YES | YES | NOT APPLICABLE | PARTIAL |
| Platform admins | Revoke | YES | YES | YES | PARTIAL |
| Tenants | Create | YES | YES | NOT APPLICABLE | YES |
| Tenants | Activate | YES | YES | NOT APPLICABLE | YES |
| Tenants | Disable | YES | YES | YES | YES |
| Settings | Schedules | YES | YES | YES | YES |
| Settings | AI/provider configuration | PARTIAL | PARTIAL | PARTIAL | PARTIAL |
| Authentication | OAuth callback failure | NOT APPLICABLE | YES | NOT APPLICABLE | PARTIAL |
| Authentication | Logout/refresh failure | NO | NO | NOT APPLICABLE | NO |

The frontend currently has no dedicated VEX administration surface and no
cancel-analysis mutation. Those rows are deliberately `NO`, not inferred as
covered from backend endpoints.
