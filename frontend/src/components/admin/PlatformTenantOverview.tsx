"use client";

import Link from "next/link";
import { useRef, useState, type ReactNode } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Building2,
  CheckCircle2,
  Clock3,
  Mail,
  ShieldCheck,
  Users,
} from "lucide-react";
import {
  ApiError,
  resendPlatformTenantActivation,
  type TenantSummary,
} from "@/lib/api";
import { useNotifications } from "@/hooks/useNotifications";
import { Alert } from "@/components/ui/Alert";
import { Button } from "@/components/ui/Button";
import { Card, CardContent, CardHeader } from "@/components/ui/Card";
import { ConfirmationDialog } from "@/components/ui/ConfirmationDialog";
import { TenantStatusBadge } from "./StatusBadges";

const navigationClass =
  "inline-flex min-h-10 items-center justify-center gap-2 rounded-lg px-4 py-2 text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2";
const initials = (name: string) =>
  name
    .trim()
    .split(/\s+/)
    .slice(0, 2)
    .map((part) => part[0])
    .join("")
    .toUpperCase();
const dateLabel = (value: string) =>
  Number.isNaN(new Date(value).getTime())
    ? "Not available"
    : new Date(value).toLocaleDateString(undefined, {
        day: "numeric",
        month: "short",
        year: "numeric",
      });

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0 space-y-1.5">
      <dt className="text-xs font-medium text-foreground opacity-70">
        {label}
      </dt>
      <dd className="break-words text-sm font-medium text-foreground">
        {children}
      </dd>
    </div>
  );
}

export function TenantBreadcrumb({ name }: { name?: string }) {
  return (
    <nav aria-label="Breadcrumb">
      <ol className="flex flex-wrap items-center gap-2 text-sm text-foreground opacity-70">
        <li>
          <Link
            className="rounded hover:text-link focus-visible:outline-primary"
            href="/settings/platform"
          >
            Platform
          </Link>
        </li>
        <li aria-hidden="true">/</li>
        <li>
          <Link
            className="rounded hover:text-link focus-visible:outline-primary"
            href="/settings/platform/tenants"
          >
            Tenants
          </Link>
        </li>
        {name && (
          <>
            <li aria-hidden="true">/</li>
            <li
              aria-current="page"
              className="min-w-0 break-words font-medium text-foreground"
            >
              {name}
            </li>
          </>
        )}
      </ol>
    </nav>
  );
}

export function PlatformTenantOverview({
  tenant,
  canResend,
  canManageUsers,
}: {
  tenant: TenantSummary;
  canResend: boolean;
  canManageUsers: boolean;
}) {
  const queryClient = useQueryClient();
  const pending = tenant.status === "PENDING";
  const administrator = tenant.initial_administrator;
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [deliveryStatus, setDeliveryStatus] = useState<string | null>(null);
  const requestInFlight = useRef(false);
  const { showSuccess, showError, showInfo, showWarning } = useNotifications();
  const resend = useMutation({
    mutationFn: () =>
      resendPlatformTenantActivation(Number(tenant.id), administrator!.user_id),
    onSuccess: (result) => {
      void queryClient.invalidateQueries({ queryKey: ["platform-tenant", Number(tenant.id)] });
      void queryClient.invalidateQueries({ queryKey: ["tenant-users", Number(tenant.id)] });
      void queryClient.invalidateQueries({ queryKey: ["tenant-audit-history", Number(tenant.id)] });
      setDeliveryStatus(result.delivery.status);
      setConfirmOpen(false);
      if (result.delivery.status === "SENT")
        showSuccess("Activation email sent successfully.");
      else if (result.delivery.status === "PENDING")
        showInfo("Activation email queued for delivery.");
      else
        showWarning(
          "The activation email could not be confirmed as sent. Please try again later or contact your administrator.",
        );
    },
    onError: (error) =>
      showError(
        error instanceof ApiError && error.status === 429
          ? "Please wait before requesting another activation email."
          : "Unable to resend activation. Please try again or check the account in user management.",
      ),
    onSettled: () => {
      requestInFlight.current = false;
    },
  });
  const allowResend =
    pending &&
    Boolean(administrator?.user_id && administrator.email) &&
    canResend;
  const manageHref = pending ? "/settings/users" : "#tenant-users";
  const manageLink = (primary = false) =>
    canManageUsers && (
      <Link
        href={manageHref}
        className={`${navigationClass} ${primary ? "bg-[var(--btn-primary)] text-white shadow-elev-1 hover:bg-[var(--btn-primary-hover)]" : "border border-border bg-surface text-hcl-navy hover:bg-surface-muted"}`}
      >
        <Users size={16} aria-hidden="true" />
        Manage Users
      </Link>
    );
  const resendButton = () =>
    allowResend && (
      <Button
        variant="secondary"
        loading={resend.isPending}
        disabled={resend.isPending}
        onClick={() => setConfirmOpen(true)}
      >
        <Mail size={16} aria-hidden="true" />
        {resend.isPending ? "Resending…" : "Resend Activation"}
      </Button>
    );

  return (
    <>
      <TenantBreadcrumb name={tenant.name} />
      <header className="flex flex-col justify-between gap-6 rounded-xl border border-border bg-surface p-5 shadow-elev-1 sm:p-6 xl:flex-row xl:items-center">
        <div className="min-w-0 flex-1">
          <div className="flex items-start gap-4">
            <span
              aria-hidden="true"
              className="flex h-14 w-14 shrink-0 items-center justify-center rounded-xl bg-surface-muted text-lg font-semibold text-hcl-blue"
            >
              {initials(tenant.name) || <Building2 size={24} />}
            </span>
            <div className="min-w-0">
              <p className="mb-2 text-xs font-semibold uppercase tracking-widest text-foreground opacity-70">
                Tenant administration
              </p>
              <h1 className="break-words text-3xl font-semibold tracking-tight">
                {tenant.name}
              </h1>
              <p className="mt-2 break-all text-sm text-foreground opacity-70">
                {tenant.slug}
              </p>
            </div>
          </div>
          <div className="mt-5">
            <TenantStatusBadge status={tenant.status} />
          </div>
        </div>
        <div className="flex flex-col gap-3 sm:flex-row xl:shrink-0">
          {manageLink(true)}
          {resendButton()}
        </div>
      </header>

      {pending && (
        <Alert variant="info" title="Tenant activation pending">
          This tenant will remain unavailable to tenant users until the initial
          Tenant Administrator activates their account.
        </Alert>
      )}
      {tenant.status === "DISABLED" && (
        <Alert variant="warning" title="Tenant access disabled">
          Tenant users cannot access this workspace while it is disabled.
          Memberships and assigned roles are retained.
        </Alert>
      )}

      <section aria-labelledby="tenant-overview-heading">
        <Card>
          <CardHeader>
            <h2 id="tenant-overview-heading" className="text-lg font-semibold">
              Tenant Overview
            </h2>
          </CardHeader>
          <CardContent className="!py-6">
            <dl className="grid gap-x-8 gap-y-6 sm:grid-cols-2 lg:grid-cols-3">
              <Field label="Tenant name">{tenant.name}</Field>
              <Field label="Tenant slug">{tenant.slug}</Field>
              <Field label="Status">
                <TenantStatusBadge status={tenant.status} />
              </Field>
              {administrator && (
                <>
                  <Field label="Initial administrator">
                    {administrator.display_name || "Name not available"}
                  </Field>
                  <Field label="Administrator email">
                    {administrator.email || "Not available"}
                  </Field>
                </>
              )}
              {tenant.created_at && (
                <Field label="Created">{dateLabel(tenant.created_at)}</Field>
              )}
              {typeof tenant.member_count === "number" && (
                <Field label="Users">{tenant.member_count}</Field>
              )}
            </dl>
          </CardContent>
        </Card>
      </section>

      <div className="grid items-stretch gap-6 lg:grid-cols-2">
        <section aria-labelledby="initial-admin-heading">
          <Card className="h-full">
            <CardHeader>
              <h2
                id="initial-admin-heading"
                className="flex items-center gap-2 text-lg font-semibold"
              >
                <ShieldCheck
                  size={19}
                  className="text-hcl-blue"
                  aria-hidden="true"
                />
                Initial Tenant Administrator
              </h2>
            </CardHeader>
            <CardContent className="space-y-6 !py-6">
              {administrator ? (
                <>
                  <div className="flex items-center gap-3">
                    <span
                      aria-hidden="true"
                      className="flex h-12 w-12 shrink-0 items-center justify-center rounded-full bg-surface-muted text-sm font-semibold text-hcl-blue"
                    >
                      {initials(
                        administrator.display_name ||
                          administrator.email ||
                          "?",
                      )}
                    </span>
                    <div className="min-w-0">
                      <p className="break-words font-semibold">
                        {administrator.display_name || "Name not available"}
                      </p>
                      <p className="mt-1 break-all text-sm text-foreground opacity-70">
                        {administrator.email || "Email not available"}
                      </p>
                    </div>
                  </div>
                  <p className="text-sm leading-6 text-foreground opacity-70">
                    Assigned as Tenant Administrator during initial setup.
                    Current access is controlled by the user&apos;s account and
                    tenant membership.
                  </p>
                </>
              ) : (
                <p className="text-sm text-foreground opacity-70">
                  Initial administrator information is not available for this
                  tenant.
                </p>
              )}
              {!!tenant.current_administrators?.length && (
                <div>
                  <h3 className="mb-2 text-xs font-medium text-foreground opacity-70">
                    Current Tenant Administrators
                  </h3>
                  <ul className="space-y-2 text-sm">
                    {tenant.current_administrators.map((admin) => (
                      <li className="break-words" key={admin.user_id}>
                        {admin.display_name ||
                          admin.email ||
                          "Name not available"}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {manageLink()}
            </CardContent>
          </Card>
        </section>
        <section aria-labelledby="activation-heading">
          <Card className="h-full">
            <CardHeader>
              <h2
                id="activation-heading"
                className="flex items-center gap-2 text-lg font-semibold"
              >
                <Mail size={19} className="text-hcl-blue" aria-hidden="true" />
                Tenant activation
              </h2>
            </CardHeader>
            <CardContent className="space-y-5 !py-6">
              <div className="flex items-start gap-3">
                {pending ? (
                  <Clock3
                    size={20}
                    className="mt-0.5 shrink-0 text-amber-700"
                    aria-hidden="true"
                  />
                ) : (
                  <CheckCircle2
                    size={20}
                    className="mt-0.5 shrink-0 text-foreground opacity-70"
                    aria-hidden="true"
                  />
                )}
                <div>
                  <h3 className="text-sm font-semibold">
                    {pending
                      ? "Waiting for administrator activation"
                      : tenant.status === "ACTIVE"
                        ? "Tenant is active"
                        : "Tenant is disabled"}
                  </h3>
                  <p className="mt-2 text-sm leading-6 text-foreground opacity-70">
                    {pending
                      ? "The tenant becomes active when its initial Tenant Administrator completes account activation. Resending replaces the previous activation link."
                      : "Tenant access is managed through memberships and assigned roles. Review lifecycle controls below to change availability."}
                  </p>
                </div>
              </div>
              {pending && administrator?.email && (
                <dl>
                  <Field label="Recipient">{administrator.email}</Field>
                </dl>
              )}
              {deliveryStatus && (
                <p
                  role="status"
                  className="rounded-lg bg-surface-muted p-3 text-sm"
                >
                  {deliveryStatus === "SENT"
                    ? "Invitation status: Sent"
                    : deliveryStatus === "PENDING"
                      ? "Invitation status: Queued for delivery"
                      : "Invitation delivery could not be confirmed."}
                </p>
              )}
              {resendButton()}
              {pending && !canResend && (
                <p className="text-xs leading-5 text-foreground opacity-70">
                  Contact a platform administrator with user invitation
                  permissions to resend activation.
                </p>
              )}
            </CardContent>
          </Card>
        </section>
      </div>
      <ConfirmationDialog
        open={confirmOpen}
        title="Resend activation email?"
        description={`A new activation email will be sent to ${administrator?.display_name || "the initial Tenant Administrator"} (${administrator?.email || ""}). The previous activation link will stop working.`}
        confirmLabel={resend.isPending ? "Resending" : "Resend activation"}
        danger={false}
        loading={resend.isPending}
        onClose={() => {
          if (!resend.isPending) setConfirmOpen(false);
        }}
        onConfirm={() => {
          if (!allowResend || requestInFlight.current) return;
          requestInFlight.current = true;
          resend.mutate();
        }}
      />
    </>
  );
}

export function TenantDetailSkeleton() {
  return (
    <main
      className="mx-auto max-w-[1360px] space-y-6 p-4 sm:p-8"
      aria-busy="true"
    >
      <p role="status" className="text-sm text-foreground opacity-70">
        Loading tenant details…
      </p>
      <div aria-hidden="true" className="space-y-6 motion-safe:animate-pulse">
        <div className="h-5 w-52 rounded bg-surface-muted" />
        <Card className="space-y-4 p-6">
          <div className="h-8 w-2/3 rounded bg-surface-muted" />
          <div className="h-4 w-1/3 rounded bg-surface-muted" />
          <div className="h-7 w-36 rounded-full bg-surface-muted" />
        </Card>
        <Card className="grid grid-cols-2 gap-6 p-6">
          {Array.from({ length: 6 }, (_, index) => (
            <div key={index} className="h-12 rounded bg-surface-muted" />
          ))}
        </Card>
        <div className="grid gap-6 lg:grid-cols-2">
          <Card className="h-64">{null}</Card>
          <Card className="h-64">{null}</Card>
        </div>
      </div>
    </main>
  );
}
