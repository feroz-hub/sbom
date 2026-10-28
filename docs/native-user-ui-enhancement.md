# Native user experience enhancement

Branch: `feat/native-user-management`.

## Scope and implementation

Authentication and authorization behavior was preserved; changes were limited to the presentation/UI layer.

No backend endpoints, permission checks, database models, migrations, password hashing, JWT handling, OIDC configuration, or HCL.CS integration were changed. Existing unrelated edits to `scripts/dev.py` and `tests/test_dev_launcher.py` were left intact.

The implementation reuses the existing Tailwind theme, HCL colors, Lucide icons, Input, Button, Dialog, ConfirmationDialog, RoleBadges, UserStatusBadge, and ToastProvider. No dependencies were added.

### Files created

- `frontend/src/components/auth/NativeAuthLayout.tsx`: responsive shared branding and authentication layout.
- `frontend/src/components/auth/PasswordField.tsx`: labeled password control with accessible visibility toggle.
- `frontend/src/components/admin/UserActionsMenu.tsx`: keyboard-accessible per-user action disclosure.
- `frontend/src/components/admin/NativeUsers.module.css`: scoped administration controls, detail sections, and responsive table styles.
- `frontend/src/components/auth/NativeAuthForm.test.tsx`: sign-in contract, errors, pending state, provider configuration, and accessibility tests.
- `frontend/src/components/admin/UserActionsMenu.test.tsx`: action focus, Escape, and selection regression test.

### Files modified

- `frontend/src/app/native-sign-in/page.tsx`
- `frontend/src/app/settings/native-users/page.tsx`
- `frontend/src/components/auth/NativeAuthForm.tsx`
- `frontend/src/components/auth/PasswordLifecycleForm.tsx`
- `frontend/src/components/admin/UserLifecycle.tsx`
- `frontend/src/components/admin/NativeUserInviteForm.tsx`
- `frontend/src/components/admin/StatusBadges.tsx`
- `frontend/src/components/admin/TenantSearchSelect.tsx`
- `frontend/src/app/settings/native-users/page.test.tsx`
- `frontend/src/components/auth/PasswordLifecycleForm.test.tsx`
- `frontend/src/components/admin/NativeUserInviteForm.test.tsx`
- `frontend/src/components/admin/UserLifecycle.test.tsx`

### Native sign-in and recovery

Desktop uses a 55/45 branding/form split with HCLTech identity, a blue-to-purple gradient, subtle component graphics, and supply-chain security messaging. Smaller screens stack the panels and shorten the branding content. Inputs and the full-width CTA are 48px high. Password visibility, autocomplete, required fields, loading/disabled states, and safe error copy are present. Activation and password lifecycle pages share the visual treatment. HCL.CS and Microsoft retain their original routes/configuration and existing redirects remain unchanged.

### Native administration

The directory has a clear header and Add User action, styled filters, clear-filter behavior, user initials, status/role badges, a compact actions disclosure, a designed empty state, and explicit pagination counts. Filtering and pagination remain server-side. Platform directory entries continue to include all existing identity providers; they are not silently narrowed to native accounts.

Invitation creation uses the existing dialog with focus management and an invitation form separated into identity and access fields. The existing emailed activation workflow is preserved; no administrator-set password was introduced. Successful creation refreshes the directory. Success notifications use the existing toast system; invitation delivery failures remain visible as warnings.

Details preserve profile editing, tenant role assignment with version checking, tenant membership activation/deactivation, global status controls, unlock, force-password-change, session revocation, and resend activation. Security-sensitive actions retain confirmation dialogs and existing permission gates. Raw backend errors and unnecessary audit actor/tenant IDs are no longer displayed.

### Responsive and accessibility work

Desktop retains the table; tablet hides the created date; mobile displays each row as a compact list card with identity, roles/membership, status, and actions. Labels, status announcements, focus rings, password-toggle labels, accessible action disclosure focus/Escape behavior, and the existing modal focus trap are retained or added. Automated axe checks pass for the sign-in and user details surfaces.

## Verification

- Production build: passed with `NEXT_PUBLIC_API_URL=http://localhost:8000`; no build warnings reported. An initial build without the required URL failed configuration validation.
- ESLint: passed for edited core components and new tests.
- `git diff --check`: passed.
- Focused UI tests: 30 passed across five files, plus the action-menu test passed (31 total).
- Full existing frontend suite: 1,056 passed, eight skipped; 144 test files passed. One suite could not start because `redis-server` is absent (`shared-session-store.test.ts`). New sign-in/menu tests were run separately after that full-suite run.
- Browser: desktop and 390px mobile sign-in inspected; no horizontal overflow. Forgot-password navigation succeeded. No console errors observed on public sign-in/recovery pages.
- Live authenticated administrator actions and real identity-provider sign-in were not exercised in the browser. Their existing route, permission, and mutation tests were retained.
- Native backend/security regression: **223 passed**, covering `test_native_iam*.py` and `test_phase9_role_assignment_security.py`, using a newly created isolated PostgreSQL test database. Three existing Pydantic/Alembic deprecation warnings were reported. The initial default database was absent; a SQLite fallback was unsuitable for this PostgreSQL-oriented suite, so verification was repeated successfully with PostgreSQL.

The implementation was prepared and validated on `feat/native-user-management`.
