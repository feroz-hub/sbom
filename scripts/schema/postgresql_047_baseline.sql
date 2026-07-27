--
-- PostgreSQL database dump
--

-- Dumped from database version 14.18 (Homebrew)
-- Dumped by pg_dump version 14.18 (Homebrew)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: ai_credential_audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ai_credential_audit_log (
    id integer NOT NULL,
    user_id character varying(128),
    action character varying(48) NOT NULL,
    target_kind character varying(24) NOT NULL,
    target_id integer,
    provider_name character varying(32),
    detail character varying(240),
    created_at character varying NOT NULL
);


--
-- Name: ai_credential_audit_log_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ai_credential_audit_log_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ai_credential_audit_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ai_credential_audit_log_id_seq OWNED BY public.ai_credential_audit_log.id;


--
-- Name: ai_fix_batch; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ai_fix_batch (
    id character varying(36) NOT NULL,
    run_id integer NOT NULL,
    status character varying(24) NOT NULL,
    scope_label character varying(120),
    scope_json json,
    finding_ids_json json NOT NULL,
    provider_name character varying(64) NOT NULL,
    total integer NOT NULL,
    cached_count integer NOT NULL,
    generated_count integer NOT NULL,
    failed_count integer NOT NULL,
    cost_usd double precision NOT NULL,
    started_at character varying,
    completed_at character varying,
    created_at character varying NOT NULL,
    last_error character varying(240),
    is_active boolean DEFAULT true NOT NULL,
    deactivated_at timestamp with time zone,
    deactivated_by character varying(128),
    tenant_id integer NOT NULL
);


--
-- Name: ai_fix_cache; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ai_fix_cache (
    cache_key character varying(64) NOT NULL,
    vuln_id character varying(64) NOT NULL,
    component_name character varying(255) NOT NULL,
    component_version character varying(128) NOT NULL,
    prompt_version character varying(32) NOT NULL,
    schema_version integer NOT NULL,
    remediation_prose json NOT NULL,
    upgrade_command json NOT NULL,
    decision_recommendation json NOT NULL,
    overall_confidence character varying(16),
    provider_used character varying(32) NOT NULL,
    model_used character varying(96) NOT NULL,
    total_cost_usd double precision NOT NULL,
    generated_at character varying NOT NULL,
    expires_at character varying NOT NULL,
    last_accessed_at character varying NOT NULL
);


--
-- Name: ai_provider_config; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ai_provider_config (
    provider_name character varying(32) NOT NULL,
    enabled boolean,
    default_model character varying(96),
    base_url character varying(256),
    max_concurrent integer,
    rate_per_minute double precision,
    notes text,
    updated_at character varying,
    updated_by character varying
);


--
-- Name: ai_provider_credential; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ai_provider_credential (
    id integer NOT NULL,
    provider_name character varying(32) NOT NULL,
    label character varying(64) NOT NULL,
    api_key_encrypted text,
    base_url character varying(512),
    default_model character varying(128),
    tier character varying(16) NOT NULL,
    is_default boolean NOT NULL,
    is_fallback boolean NOT NULL,
    enabled boolean NOT NULL,
    cost_per_1k_input_usd double precision NOT NULL,
    cost_per_1k_output_usd double precision NOT NULL,
    is_local boolean NOT NULL,
    max_concurrent integer,
    rate_per_minute double precision,
    created_at character varying NOT NULL,
    updated_at character varying NOT NULL,
    last_test_at character varying,
    last_test_success boolean,
    last_test_error text
);


--
-- Name: ai_provider_credential_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ai_provider_credential_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ai_provider_credential_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ai_provider_credential_id_seq OWNED BY public.ai_provider_credential.id;


--
-- Name: ai_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ai_settings (
    id integer NOT NULL,
    feature_enabled boolean NOT NULL,
    kill_switch_active boolean NOT NULL,
    budget_per_request_usd double precision NOT NULL,
    budget_per_scan_usd double precision NOT NULL,
    budget_daily_usd double precision NOT NULL,
    updated_at character varying NOT NULL,
    updated_by_user_id character varying,
    CONSTRAINT ck_ai_settings_ck_ai_settings_singleton CHECK ((id = 1))
);


--
-- Name: ai_usage_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ai_usage_log (
    id integer NOT NULL,
    request_id character varying(64) NOT NULL,
    provider character varying(32) NOT NULL,
    model character varying(96) NOT NULL,
    purpose character varying(48) NOT NULL,
    finding_cache_key character varying(64),
    input_tokens integer NOT NULL,
    output_tokens integer NOT NULL,
    cost_usd double precision NOT NULL,
    latency_ms integer NOT NULL,
    cache_hit boolean NOT NULL,
    error text,
    created_at character varying NOT NULL,
    tenant_id integer NOT NULL
);


--
-- Name: ai_usage_log_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ai_usage_log_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ai_usage_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ai_usage_log_id_seq OWNED BY public.ai_usage_log.id;


--
-- Name: analysis_finding; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.analysis_finding (
    id integer NOT NULL,
    analysis_run_id integer NOT NULL,
    component_id integer,
    vuln_id character varying(255) NOT NULL,
    source character varying(128),
    title character varying,
    description text,
    severity character varying(16),
    score double precision,
    vector text,
    published_on character varying,
    reference_url text,
    cwe text,
    cpe character varying,
    component_name text,
    component_version text,
    fixed_versions text,
    attack_vector character varying(64),
    cvss_version character varying(16),
    aliases text,
    match_reason character varying(255),
    matched_range text,
    match_confidence double precision,
    match_strategy character varying(64),
    is_active boolean DEFAULT true NOT NULL,
    deactivated_at timestamp with time zone,
    deactivated_by character varying(128),
    tenant_id integer NOT NULL
);


--
-- Name: analysis_finding_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.analysis_finding_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: analysis_finding_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.analysis_finding_id_seq OWNED BY public.analysis_finding.id;


--
-- Name: analysis_run; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.analysis_run (
    id integer NOT NULL,
    sbom_id integer NOT NULL,
    project_id integer,
    product_id integer,
    run_status character varying NOT NULL,
    sbom_name character varying,
    source character varying NOT NULL,
    trigger_source character varying(32) DEFAULT 'unknown'::character varying NOT NULL,
    started_on character varying NOT NULL,
    completed_on character varying NOT NULL,
    duration_ms integer NOT NULL,
    total_components integer NOT NULL,
    components_with_cpe integer NOT NULL,
    total_findings integer NOT NULL,
    critical_count integer NOT NULL,
    high_count integer NOT NULL,
    medium_count integer NOT NULL,
    low_count integer NOT NULL,
    unknown_count integer NOT NULL,
    query_error_count integer NOT NULL,
    raw_report text,
    is_active boolean DEFAULT true NOT NULL,
    deactivated_at timestamp with time zone,
    deactivated_by character varying(128),
    tenant_id integer NOT NULL
);


--
-- Name: analysis_run_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.analysis_run_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: analysis_run_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.analysis_run_id_seq OWNED BY public.analysis_run.id;


--
-- Name: analysis_schedule; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.analysis_schedule (
    id integer NOT NULL,
    scope character varying(16) NOT NULL,
    project_id integer,
    product_id integer,
    sbom_id integer,
    cadence character varying(16) NOT NULL,
    cron_expression character varying(128),
    day_of_week integer,
    day_of_month integer,
    hour_utc integer NOT NULL,
    timezone character varying(64) NOT NULL,
    enabled boolean NOT NULL,
    next_run_at character varying,
    last_run_at character varying,
    last_run_status character varying(16),
    last_run_id integer,
    consecutive_failures integer NOT NULL,
    min_gap_minutes integer NOT NULL,
    created_on character varying,
    created_by character varying,
    modified_on character varying,
    modified_by character varying,
    is_active boolean DEFAULT true NOT NULL,
    deactivated_at timestamp with time zone,
    deactivated_by character varying(128),
    tenant_id integer NOT NULL,
    CONSTRAINT ck_analysis_schedule_ck_analysis_schedule_cadence CHECK (((cadence)::text = ANY (ARRAY[('DAILY'::character varying)::text, ('WEEKLY'::character varying)::text, ('BIWEEKLY'::character varying)::text, ('MONTHLY'::character varying)::text, ('QUARTERLY'::character varying)::text, ('CUSTOM'::character varying)::text]))),
    CONSTRAINT ck_analysis_schedule_ck_analysis_schedule_dom_range CHECK (((day_of_month IS NULL) OR ((day_of_month >= 1) AND (day_of_month <= 28)))),
    CONSTRAINT ck_analysis_schedule_ck_analysis_schedule_dow_range CHECK (((day_of_week IS NULL) OR ((day_of_week >= 0) AND (day_of_week <= 6)))),
    CONSTRAINT ck_analysis_schedule_ck_analysis_schedule_hour_range CHECK (((hour_utc >= 0) AND (hour_utc <= 23))),
    CONSTRAINT ck_analysis_schedule_ck_analysis_schedule_scope CHECK (((scope)::text = ANY (ARRAY[('PROJECT'::character varying)::text, ('PRODUCT'::character varying)::text, ('SBOM'::character varying)::text]))),
    CONSTRAINT ck_analysis_schedule_ck_analysis_schedule_target CHECK (((((scope)::text = 'PROJECT'::text) AND (project_id IS NOT NULL) AND (product_id IS NULL) AND (sbom_id IS NULL)) OR (((scope)::text = 'PRODUCT'::text) AND (product_id IS NOT NULL) AND (project_id IS NULL) AND (sbom_id IS NULL)) OR (((scope)::text = 'SBOM'::text) AND (sbom_id IS NOT NULL) AND (project_id IS NULL) AND (product_id IS NULL))))
);


--
-- Name: analysis_schedule_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.analysis_schedule_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: analysis_schedule_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.analysis_schedule_id_seq OWNED BY public.analysis_schedule.id;


--
-- Name: audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_log (
    id integer NOT NULL,
    user_id character varying(128),
    action character varying(128) NOT NULL,
    target_kind character varying(128) NOT NULL,
    target_id integer,
    detail text,
    metadata_json json,
    user_ref_id integer,
    entity_type character varying(128),
    entity_id character varying(128),
    old_value json,
    new_value json,
    ip_address character varying(64),
    user_agent text,
    created_at character varying NOT NULL,
    tenant_id integer NOT NULL
);


--
-- Name: audit_log_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.audit_log_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: audit_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.audit_log_id_seq OWNED BY public.audit_log.id;


--
-- Name: authorization_audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.authorization_audit_log (
    id integer NOT NULL,
    actor_user_id integer,
    target_user_id integer,
    target_membership_id integer,
    tenant_id integer,
    action character varying(128) NOT NULL,
    outcome character varying(16) NOT NULL,
    old_value json,
    new_value json,
    correlation_id character varying(128),
    detail character varying(240),
    created_at timestamp with time zone NOT NULL,
    CONSTRAINT ck_authorization_audit_log_authorization_audit_outcome CHECK (((outcome)::text = ANY (ARRAY[('SUCCESS'::character varying)::text, ('DENIED'::character varying)::text, ('FAILED'::character varying)::text])))
);


--
-- Name: authorization_audit_log_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.authorization_audit_log_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: authorization_audit_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.authorization_audit_log_id_seq OWNED BY public.authorization_audit_log.id;


--
-- Name: compare_cache; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.compare_cache (
    cache_key character varying(64) NOT NULL,
    run_a_id integer NOT NULL,
    run_b_id integer NOT NULL,
    payload json NOT NULL,
    computed_at character varying NOT NULL,
    expires_at character varying NOT NULL,
    schema_version integer NOT NULL,
    tenant_id integer NOT NULL
);


--
-- Name: component_lifecycle_cache; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_lifecycle_cache (
    id integer NOT NULL,
    lookup_key character varying,
    normalized_name character varying NOT NULL,
    normalized_version character varying,
    ecosystem character varying,
    purl character varying,
    cpe character varying,
    lifecycle_status character varying,
    eos_date character varying,
    eol_date character varying,
    eof_date character varying,
    deprecated boolean,
    unsupported boolean,
    maintenance_status character varying,
    latest_version character varying,
    latest_supported_version character varying,
    recommended_version character varying,
    recommendation text,
    source_name character varying,
    source_url character varying,
    evidence_json json,
    confidence character varying,
    checked_at character varying NOT NULL,
    expires_at character varying NOT NULL,
    is_stale boolean NOT NULL
);


--
-- Name: component_lifecycle_cache_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.component_lifecycle_cache_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: component_lifecycle_cache_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.component_lifecycle_cache_id_seq OWNED BY public.component_lifecycle_cache.id;


--
-- Name: component_lifecycle_override_audit; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_lifecycle_override_audit (
    id integer NOT NULL,
    component_id integer NOT NULL,
    old_value_json json,
    new_value_json json,
    reason text NOT NULL,
    evidence_url character varying,
    changed_by character varying,
    changed_at character varying NOT NULL,
    tenant_id integer NOT NULL
);


--
-- Name: component_lifecycle_override_audit_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.component_lifecycle_override_audit_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: component_lifecycle_override_audit_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.component_lifecycle_override_audit_id_seq OWNED BY public.component_lifecycle_override_audit.id;


--
-- Name: cve_cache; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cve_cache (
    cve_id character varying(32) NOT NULL,
    payload json NOT NULL,
    sources_used character varying(128) NOT NULL,
    fetched_at character varying NOT NULL,
    expires_at character varying NOT NULL,
    fetch_error text,
    schema_version integer NOT NULL
);


--
-- Name: cves; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cves (
    cve_id text NOT NULL,
    last_modified timestamp with time zone NOT NULL,
    published timestamp with time zone NOT NULL,
    vuln_status text NOT NULL,
    description_en text,
    score_v40 double precision,
    score_v31 double precision,
    score_v2 double precision,
    severity_text character varying(32),
    vector_string text,
    aliases jsonb DEFAULT '[]'::jsonb NOT NULL,
    cpe_match jsonb DEFAULT '[]'::jsonb NOT NULL,
    "references" jsonb DEFAULT '[]'::jsonb NOT NULL,
    data jsonb NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: email_verification_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.email_verification_tokens (
    id integer NOT NULL,
    user_id integer NOT NULL,
    token_hash character varying(64) NOT NULL,
    email_snapshot character varying(320) NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    invalidated_at timestamp with time zone,
    invalidation_reason character varying(64),
    created_at timestamp with time zone NOT NULL,
    created_by_ip_hash character varying(64),
    consumed_by_ip_hash character varying(64),
    correlation_id character varying(128),
    delivery_status character varying(16) NOT NULL,
    delivery_attempted_at timestamp with time zone,
    delivery_error_code character varying(64),
    CONSTRAINT ck_email_verification_tokens_ck_email_verification_toke_1c56 CHECK (((consumed_at IS NULL) OR (consumed_at >= created_at))),
    CONSTRAINT ck_email_verification_tokens_ck_email_verification_toke_39e0 CHECK (((delivery_status)::text = ANY (ARRAY[('PENDING'::character varying)::text, ('SENT'::character varying)::text, ('FAILED'::character varying)::text, ('SKIPPED'::character varying)::text]))),
    CONSTRAINT ck_email_verification_tokens_ck_email_verification_toke_46d4 CHECK ((expires_at > created_at)),
    CONSTRAINT ck_email_verification_tokens_ck_email_verification_toke_d99d CHECK (((invalidated_at IS NULL) OR (invalidated_at >= created_at)))
);


--
-- Name: email_verification_tokens_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.email_verification_tokens_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: email_verification_tokens_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.email_verification_tokens_id_seq OWNED BY public.email_verification_tokens.id;


--
-- Name: epss_score; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.epss_score (
    cve_id character varying NOT NULL,
    epss double precision NOT NULL,
    percentile double precision,
    score_date character varying,
    refreshed_at character varying NOT NULL
);


--
-- Name: iam_users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.iam_users (
    id integer NOT NULL,
    external_iam_user_id character varying(255) NOT NULL,
    email character varying(320),
    display_name character varying(255),
    status character varying(32) NOT NULL,
    last_login_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    external_issuer character varying(512),
    external_subject character varying(255),
    employee_id character varying(128),
    user_principal_name character varying(320),
    department character varying(255),
    email_verified boolean DEFAULT false NOT NULL,
    email_verified_at timestamp with time zone,
    verification_required boolean DEFAULT true NOT NULL,
    last_claim_sync_at timestamp with time zone,
    CONSTRAINT ck_iam_users_email_verification_timestamp CHECK (((email_verified = false) OR (email_verified_at IS NOT NULL))),
    CONSTRAINT ck_iam_users_external_issuer_not_blank CHECK (((external_issuer IS NULL) OR (length(TRIM(BOTH FROM external_issuer)) > 0))),
    CONSTRAINT ck_iam_users_external_subject_not_blank CHECK (((external_subject IS NULL) OR (length(TRIM(BOTH FROM external_subject)) > 0))),
    CONSTRAINT ck_iam_users_iam_user_status CHECK (((status)::text = ANY (ARRAY[('ACTIVE'::character varying)::text, ('PENDING'::character varying)::text, ('DISABLED'::character varying)::text])))
);


--
-- Name: iam_users_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.iam_users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: iam_users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.iam_users_id_seq OWNED BY public.iam_users.id;


--
-- Name: kev_vulnerabilities; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.kev_vulnerabilities (
    cve_id character varying(32) NOT NULL,
    vendor_project character varying(255),
    product character varying(255),
    vulnerability_name text,
    date_added character varying(10),
    short_description text,
    required_action text,
    due_date character varying(10),
    known_ransomware_campaign_use character varying(32),
    notes text,
    cwes json,
    catalog_version character varying(32),
    catalog_date_released character varying(64),
    refreshed_at character varying NOT NULL,
    first_seen_at character varying,
    updated_at character varying
);


--
-- Name: lifecycle_provider_configs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.lifecycle_provider_configs (
    id integer NOT NULL,
    provider_key character varying(64) NOT NULL,
    display_name character varying(128) NOT NULL,
    provider_type character varying(64) NOT NULL,
    enabled boolean NOT NULL,
    priority integer NOT NULL,
    base_url character varying(512),
    feed_urls_json json,
    config_json json,
    timeout_seconds integer NOT NULL,
    max_retries integer NOT NULL,
    circuit_breaker_enabled boolean NOT NULL,
    cache_ttl_known_days integer,
    cache_ttl_unknown_hours integer,
    cache_ttl_failure_minutes integer,
    cache_ttl_deprecated_days integer,
    last_success_at character varying,
    last_failure_at character varying,
    last_failure_message text,
    health_status character varying(32) NOT NULL,
    created_at character varying NOT NULL,
    updated_at character varying NOT NULL,
    updated_by_user_id integer,
    CONSTRAINT ck_lifecycle_provider_configs_ck_lifecycle_provider_con_1000 CHECK (((max_retries >= 0) AND (max_retries <= 10))),
    CONSTRAINT ck_lifecycle_provider_configs_ck_lifecycle_provider_con_5331 CHECK (((timeout_seconds >= 1) AND (timeout_seconds <= 60))),
    CONSTRAINT ck_lifecycle_provider_configs_ck_lifecycle_provider_con_a0a3 CHECK (((health_status)::text = ANY (ARRAY[('healthy'::character varying)::text, ('degraded'::character varying)::text, ('disabled'::character varying)::text, ('unknown'::character varying)::text]))),
    CONSTRAINT ck_lifecycle_provider_configs_ck_lifecycle_provider_con_ef01 CHECK (((priority >= 1) AND (priority <= 1000)))
);


--
-- Name: lifecycle_provider_configs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.lifecycle_provider_configs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: lifecycle_provider_configs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.lifecycle_provider_configs_id_seq OWNED BY public.lifecycle_provider_configs.id;


--
-- Name: lifecycle_provider_secrets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.lifecycle_provider_secrets (
    id integer NOT NULL,
    provider_key character varying(64) NOT NULL,
    secret_name character varying(64) NOT NULL,
    encrypted_value text NOT NULL,
    value_preview character varying(64),
    created_at character varying NOT NULL,
    updated_at character varying NOT NULL,
    updated_by_user_id integer
);


--
-- Name: lifecycle_provider_secrets_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.lifecycle_provider_secrets_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: lifecycle_provider_secrets_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.lifecycle_provider_secrets_id_seq OWNED BY public.lifecycle_provider_secrets.id;


--
-- Name: lifecycle_vendor_records; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.lifecycle_vendor_records (
    id integer NOT NULL,
    vendor_name character varying(128) NOT NULL,
    product_name character varying(255) NOT NULL,
    product_aliases_json json,
    ecosystem character varying(64),
    version_pattern character varying(128),
    version_start character varying(64),
    version_end character varying(64),
    lifecycle_status character varying(64) NOT NULL,
    maintenance_status character varying(128),
    eol_date character varying,
    eos_date character varying,
    eof_date character varying,
    deprecated boolean NOT NULL,
    unsupported boolean NOT NULL,
    latest_supported_version character varying(128),
    recommended_version character varying(128),
    evidence_url character varying(512),
    evidence_json json,
    confidence character varying(32) NOT NULL,
    enabled boolean NOT NULL,
    created_at character varying NOT NULL,
    updated_at character varying NOT NULL,
    updated_by_user_id integer
);


--
-- Name: lifecycle_vendor_records_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.lifecycle_vendor_records_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: lifecycle_vendor_records_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.lifecycle_vendor_records_id_seq OWNED BY public.lifecycle_vendor_records.id;


--
-- Name: nvd_lookup_cache; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.nvd_lookup_cache (
    id integer NOT NULL,
    lookup_type character varying(16) NOT NULL,
    identifier character varying(2048) NOT NULL,
    identifier_hash character varying(64) NOT NULL,
    status character varying(16) NOT NULL,
    response_json json,
    http_status integer,
    error_message text,
    checked_at character varying NOT NULL,
    expires_at character varying NOT NULL,
    created_at character varying NOT NULL,
    updated_at character varying NOT NULL
);


--
-- Name: nvd_lookup_cache_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.nvd_lookup_cache_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: nvd_lookup_cache_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.nvd_lookup_cache_id_seq OWNED BY public.nvd_lookup_cache.id;


--
-- Name: nvd_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.nvd_settings (
    id integer NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    api_endpoint text DEFAULT 'https://services.nvd.nist.gov/rest/json/cves/2.0'::text NOT NULL,
    api_key_ciphertext bytea,
    download_feeds_enabled boolean DEFAULT false NOT NULL,
    page_size integer DEFAULT 2000 NOT NULL,
    window_days integer DEFAULT 119 NOT NULL,
    min_freshness_hours integer DEFAULT 24 NOT NULL,
    last_modified_utc timestamp with time zone,
    last_successful_sync_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_nvd_settings_min_freshness_nonneg CHECK ((min_freshness_hours >= 0)),
    CONSTRAINT ck_nvd_settings_page_size_range CHECK (((page_size >= 1) AND (page_size <= 2000))),
    CONSTRAINT ck_nvd_settings_singleton CHECK ((id = 1)),
    CONSTRAINT ck_nvd_settings_window_days_range CHECK (((window_days >= 1) AND (window_days <= 119)))
);


--
-- Name: nvd_settings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.nvd_settings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: nvd_settings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.nvd_settings_id_seq OWNED BY public.nvd_settings.id;


--
-- Name: nvd_sync_runs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.nvd_sync_runs (
    id bigint NOT NULL,
    run_kind character varying(16) NOT NULL,
    window_start timestamp with time zone NOT NULL,
    window_end timestamp with time zone NOT NULL,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    finished_at timestamp with time zone,
    status character varying(16) DEFAULT 'running'::character varying NOT NULL,
    upserted_count integer DEFAULT 0 NOT NULL,
    error_message text,
    CONSTRAINT ck_nvd_sync_runs_kind CHECK (((run_kind)::text = ANY ((ARRAY['bootstrap'::character varying, 'incremental'::character varying])::text[]))),
    CONSTRAINT ck_nvd_sync_runs_status CHECK (((status)::text = ANY ((ARRAY['running'::character varying, 'success'::character varying, 'failed'::character varying, 'aborted'::character varying])::text[])))
);


--
-- Name: nvd_sync_runs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.nvd_sync_runs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: nvd_sync_runs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.nvd_sync_runs_id_seq OWNED BY public.nvd_sync_runs.id;


--
-- Name: platform_user_roles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.platform_user_roles (
    id integer NOT NULL,
    user_id integer NOT NULL,
    role character varying(64) NOT NULL,
    status character varying(32) NOT NULL,
    created_by_user_id integer,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT ck_platform_user_roles_platform_user_role CHECK (((role)::text = 'PLATFORM_ADMIN'::text)),
    CONSTRAINT ck_platform_user_roles_platform_user_role_status CHECK (((status)::text = ANY (ARRAY[('ACTIVE'::character varying)::text, ('DISABLED'::character varying)::text])))
);


--
-- Name: platform_user_roles_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.platform_user_roles_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: platform_user_roles_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.platform_user_roles_id_seq OWNED BY public.platform_user_roles.id;


--
-- Name: products; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.products (
    id integer NOT NULL,
    project_id integer NOT NULL,
    name character varying(255) NOT NULL,
    normalized_name character varying(255) NOT NULL,
    slug character varying(255) NOT NULL,
    description text,
    product_key character varying(128),
    vendor character varying(255),
    category character varying(128),
    status character varying(32) DEFAULT 'active'::character varying NOT NULL,
    latest_version character varying(128),
    metadata_json json,
    created_by character varying(128),
    created_at character varying NOT NULL,
    updated_at character varying,
    deleted_at character varying,
    is_active boolean DEFAULT true NOT NULL,
    deactivated_at timestamp with time zone,
    deactivated_by character varying(128),
    tenant_id integer NOT NULL
);


--
-- Name: products_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.products_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: products_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.products_id_seq OWNED BY public.products.id;


--
-- Name: projects; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.projects (
    id integer NOT NULL,
    project_name character varying NOT NULL,
    project_details character varying,
    project_status integer NOT NULL,
    created_on character varying,
    created_by character varying,
    modified_on character varying,
    modified_by character varying,
    is_active boolean DEFAULT true NOT NULL,
    deactivated_at timestamp with time zone,
    deactivated_by character varying(128),
    tenant_id integer NOT NULL
);


--
-- Name: projects_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.projects_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: projects_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.projects_id_seq OWNED BY public.projects.id;


--
-- Name: run_cache; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.run_cache (
    id integer NOT NULL,
    run_json text NOT NULL,
    created_on character varying,
    source character varying,
    sbom_id integer,
    tenant_id integer NOT NULL
);


--
-- Name: run_cache_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.run_cache_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: run_cache_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.run_cache_id_seq OWNED BY public.run_cache.id;


--
-- Name: sbom_analysis_report; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sbom_analysis_report (
    id integer NOT NULL,
    sbom_ref_id integer,
    sbom_result character varying,
    project_id character varying,
    created_on character varying,
    analysis_details text,
    reference_source character varying,
    sbom_analysis_level integer,
    is_active boolean DEFAULT true NOT NULL,
    deactivated_at timestamp with time zone,
    deactivated_by character varying(128),
    tenant_id integer NOT NULL
);


--
-- Name: sbom_analysis_report_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sbom_analysis_report_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sbom_analysis_report_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sbom_analysis_report_id_seq OWNED BY public.sbom_analysis_report.id;


--
-- Name: sbom_component; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sbom_component (
    id integer NOT NULL,
    sbom_id integer NOT NULL,
    bom_ref character varying,
    component_type character varying,
    component_group character varying,
    name character varying NOT NULL,
    version character varying,
    purl character varying,
    cpe character varying,
    cpe_source character varying(32),
    supplier character varying,
    scope character varying,
    created_on character varying,
    ecosystem character varying,
    original_name character varying,
    normalized_name character varying,
    original_version character varying,
    normalized_version character varying,
    normalized_ecosystem character varying,
    original_purl character varying,
    normalized_purl character varying,
    purl_type character varying,
    purl_namespace character varying,
    purl_name character varying,
    purl_version character varying,
    purl_qualifiers_json json,
    purl_subpath character varying,
    normalized_cpes json,
    primary_cpe character varying,
    cpe_evidence_json json,
    normalized_supplier character varying,
    normalized_package_key character varying,
    canonical_identity_confidence character varying,
    license character varying,
    hashes text,
    lifecycle_status character varying,
    eos_date character varying,
    eol_date character varying,
    eof_date character varying,
    is_deprecated boolean,
    deprecated boolean,
    unsupported boolean,
    maintenance_status character varying,
    latest_version character varying,
    latest_supported_version character varying,
    recommended_version character varying,
    lifecycle_recommendation text,
    lifecycle_source character varying,
    lifecycle_source_url character varying,
    lifecycle_confidence character varying,
    lifecycle_checked_at character varying,
    lifecycle_evidence_json json,
    lifecycle_is_stale boolean NOT NULL,
    lifecycle_manual_override boolean NOT NULL,
    normalized_component_key character varying,
    dedupe_canonical_id character varying,
    dedupe_group_id character varying,
    is_duplicate boolean NOT NULL,
    duplicate_of_component_id integer,
    dedupe_reason character varying,
    dedupe_confidence character varying,
    normalization_notes_json json,
    dedupe_evidence_json json,
    is_active boolean DEFAULT true NOT NULL,
    deactivated_at timestamp with time zone,
    deactivated_by character varying(128),
    tenant_id integer NOT NULL
);


--
-- Name: sbom_component_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sbom_component_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sbom_component_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sbom_component_id_seq OWNED BY public.sbom_component.id;


--
-- Name: sbom_source; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sbom_source (
    id integer NOT NULL,
    sbom_name character varying NOT NULL,
    sbom_data text,
    sbom_type integer,
    projectid integer,
    product_id integer,
    created_on character varying,
    sbom_version character varying,
    created_by character varying,
    productver character varying,
    modified_on character varying,
    modified_by character varying,
    parent_id integer,
    change_summary character varying,
    completeness_score double precision,
    completeness_report json,
    dedupe_report_json json,
    product_name character varying,
    description character varying,
    status character varying(24) DEFAULT 'validated'::character varying NOT NULL,
    failed_stage character varying(32),
    validation_errors json,
    error_count integer DEFAULT 0 NOT NULL,
    warning_count integer DEFAULT 0 NOT NULL,
    validated_at character varying,
    original_format character varying(32),
    current_format character varying(32),
    converted_from_format character varying(32),
    source_sbom_id integer,
    converted_sbom_id integer,
    conversion_status character varying(32),
    conversion_warnings_json json,
    conversion_report_json json,
    converted_at character varying,
    converted_by character varying,
    enrichment_status character varying(32),
    conversion_started_at character varying,
    conversion_completed_at character varying,
    enrichment_started_at character varying,
    enrichment_completed_at character varying,
    conversion_error text,
    enrichment_error text,
    component_extraction_status character varying(32),
    component_extraction_error text,
    component_extraction_attempted_at character varying,
    component_extraction_completed_at character varying,
    is_active boolean DEFAULT true NOT NULL,
    deactivated_at timestamp with time zone,
    deactivated_by character varying(128),
    tenant_id integer NOT NULL
);


--
-- Name: sbom_source_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sbom_source_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sbom_source_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sbom_source_id_seq OWNED BY public.sbom_source.id;


--
-- Name: sbom_type; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sbom_type (
    id integer NOT NULL,
    typename character varying NOT NULL,
    type_details character varying,
    created_on character varying,
    created_by character varying,
    modified_on character varying,
    modified_by character varying
);


--
-- Name: sbom_type_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sbom_type_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sbom_type_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sbom_type_id_seq OWNED BY public.sbom_type.id;


--
-- Name: sbom_validation_session_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sbom_validation_session_events (
    id integer NOT NULL,
    session_id character varying(36) NOT NULL,
    event_type character varying(64) NOT NULL,
    actor_user_id character varying(128),
    "timestamp" character varying NOT NULL,
    summary text,
    before_hash character varying(64),
    after_hash character varying(64),
    metadata_json json,
    tenant_id integer NOT NULL
);


--
-- Name: sbom_validation_session_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sbom_validation_session_events_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sbom_validation_session_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sbom_validation_session_events_id_seq OWNED BY public.sbom_validation_session_events.id;


--
-- Name: sbom_validation_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sbom_validation_sessions (
    id character varying(36) NOT NULL,
    project_id integer,
    user_id character varying(128),
    original_filename character varying(255),
    sbom_name character varying(255),
    sbom_type integer,
    content_type character varying(255),
    file_size_bytes integer,
    sha256 character varying(64),
    original_size_bytes integer,
    original_sha256 character varying(64),
    stored_size_bytes integer,
    stored_sha256 character varying(64),
    storage_backend character varying(32),
    detected_format character varying(64),
    detected_version character varying(64),
    detection_confidence double precision,
    detection_evidence_json json,
    raw_content_text text,
    raw_content_blob bytea,
    raw_storage_path character varying(1024),
    sanitized_content text,
    current_content text,
    repair_content_text text,
    repair_content_blob bytea,
    repair_storage_path character varying(1024),
    validation_status character varying(32) DEFAULT 'failed'::character varying NOT NULL,
    validation_errors_json json,
    stage_results_json json,
    latest_error_report_json json,
    total_lines integer,
    is_large_file boolean DEFAULT false NOT NULL,
    full_editor_allowed boolean DEFAULT true NOT NULL,
    can_edit boolean DEFAULT true NOT NULL,
    can_ai_fix boolean DEFAULT true NOT NULL,
    security_blocked_reason text,
    content_sha256 character varying(64),
    created_at character varying NOT NULL,
    updated_at character varying NOT NULL,
    expires_at character varying NOT NULL,
    imported_sbom_id integer,
    tenant_id integer NOT NULL
);


--
-- Name: source_response_cache; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.source_response_cache (
    source character varying(32) NOT NULL,
    component_key character varying(512) NOT NULL,
    payload json NOT NULL,
    fetched_at character varying NOT NULL,
    expires_at character varying NOT NULL
);


--
-- Name: tenant_users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant_users (
    id integer NOT NULL,
    tenant_id integer NOT NULL,
    user_id integer NOT NULL,
    role character varying(64) NOT NULL,
    status character varying(32) NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT ck_tenant_users_tenant_user_role CHECK (((role)::text = ANY (ARRAY[('TENANT_ADMIN'::character varying)::text, ('SECURITY_ANALYST'::character varying)::text, ('DEVELOPER'::character varying)::text, ('VIEWER'::character varying)::text]))),
    CONSTRAINT ck_tenant_users_tenant_user_status CHECK (((status)::text = ANY (ARRAY[('ACTIVE'::character varying)::text, ('PENDING'::character varying)::text, ('DISABLED'::character varying)::text])))
);


--
-- Name: tenant_users_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.tenant_users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: tenant_users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.tenant_users_id_seq OWNED BY public.tenant_users.id;


--
-- Name: tenants; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenants (
    id integer NOT NULL,
    name character varying(255) NOT NULL,
    slug character varying(128) NOT NULL,
    external_iam_tenant_id character varying(255) NOT NULL,
    status character varying(32) NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT ck_tenants_tenant_status CHECK (((status)::text = ANY (ARRAY[('ACTIVE'::character varying)::text, ('PENDING'::character varying)::text, ('DISABLED'::character varying)::text])))
);


--
-- Name: tenants_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.tenants_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: tenants_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.tenants_id_seq OWNED BY public.tenants.id;


--
-- Name: vex_documents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vex_documents (
    id integer NOT NULL,
    sbom_id integer NOT NULL,
    source_type character varying NOT NULL,
    format character varying,
    author character varying,
    source_url character varying,
    discovery_evidence_json json,
    last_refresh_status character varying,
    provider_errors_json json,
    uploaded_by character varying,
    uploaded_at character varying NOT NULL,
    raw_document_json json,
    validation_status character varying NOT NULL,
    tenant_id integer NOT NULL
);


--
-- Name: vex_documents_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.vex_documents_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: vex_documents_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.vex_documents_id_seq OWNED BY public.vex_documents.id;


--
-- Name: vex_override_audit; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vex_override_audit (
    id integer NOT NULL,
    component_id integer NOT NULL,
    vulnerability_id character varying NOT NULL,
    old_value_json json,
    new_value_json json,
    reason text NOT NULL,
    evidence_url character varying,
    changed_by character varying,
    changed_at character varying NOT NULL,
    tenant_id integer NOT NULL
);


--
-- Name: vex_override_audit_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.vex_override_audit_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: vex_override_audit_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.vex_override_audit_id_seq OWNED BY public.vex_override_audit.id;


--
-- Name: vex_statements; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vex_statements (
    id integer NOT NULL,
    vex_document_id integer,
    sbom_id integer NOT NULL,
    component_id integer,
    vulnerability_id character varying NOT NULL,
    cve_id character varying,
    status character varying NOT NULL,
    justification text,
    impact_statement text,
    action_statement text,
    fixed_version character varying,
    mitigation text,
    source_name character varying,
    source_url character varying,
    confidence character varying,
    evidence_json json,
    created_at character varying NOT NULL,
    tenant_id integer NOT NULL
);


--
-- Name: vex_statements_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.vex_statements_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: vex_statements_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.vex_statements_id_seq OWNED BY public.vex_statements.id;


--
-- Name: vulnerability_remediation; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vulnerability_remediation (
    id integer NOT NULL,
    project_id integer NOT NULL,
    vuln_id character varying NOT NULL,
    component_name character varying NOT NULL,
    component_version character varying NOT NULL,
    fixed_version character varying,
    status character varying NOT NULL,
    owner character varying,
    due_date character varying,
    resolution_date character varying,
    fix_notes text,
    created_on character varying NOT NULL,
    updated_on character varying NOT NULL,
    tenant_id integer NOT NULL
);


--
-- Name: vulnerability_remediation_audit; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vulnerability_remediation_audit (
    id integer NOT NULL,
    remediation_id integer NOT NULL,
    project_id integer NOT NULL,
    vuln_id character varying NOT NULL,
    component_name character varying NOT NULL,
    component_version character varying NOT NULL,
    old_status character varying,
    new_status character varying NOT NULL,
    changed_by character varying(128),
    changed_at character varying NOT NULL,
    note text,
    tenant_id integer NOT NULL
);


--
-- Name: vulnerability_remediation_audit_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.vulnerability_remediation_audit_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: vulnerability_remediation_audit_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.vulnerability_remediation_audit_id_seq OWNED BY public.vulnerability_remediation_audit.id;


--
-- Name: vulnerability_remediation_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.vulnerability_remediation_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: vulnerability_remediation_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.vulnerability_remediation_id_seq OWNED BY public.vulnerability_remediation.id;


--
-- Name: ai_credential_audit_log id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ai_credential_audit_log ALTER COLUMN id SET DEFAULT nextval('public.ai_credential_audit_log_id_seq'::regclass);


--
-- Name: ai_provider_credential id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ai_provider_credential ALTER COLUMN id SET DEFAULT nextval('public.ai_provider_credential_id_seq'::regclass);


--
-- Name: ai_usage_log id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ai_usage_log ALTER COLUMN id SET DEFAULT nextval('public.ai_usage_log_id_seq'::regclass);


--
-- Name: analysis_finding id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analysis_finding ALTER COLUMN id SET DEFAULT nextval('public.analysis_finding_id_seq'::regclass);


--
-- Name: analysis_run id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analysis_run ALTER COLUMN id SET DEFAULT nextval('public.analysis_run_id_seq'::regclass);


--
-- Name: analysis_schedule id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analysis_schedule ALTER COLUMN id SET DEFAULT nextval('public.analysis_schedule_id_seq'::regclass);


--
-- Name: audit_log id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log ALTER COLUMN id SET DEFAULT nextval('public.audit_log_id_seq'::regclass);


--
-- Name: authorization_audit_log id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_audit_log ALTER COLUMN id SET DEFAULT nextval('public.authorization_audit_log_id_seq'::regclass);


--
-- Name: component_lifecycle_cache id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_lifecycle_cache ALTER COLUMN id SET DEFAULT nextval('public.component_lifecycle_cache_id_seq'::regclass);


--
-- Name: component_lifecycle_override_audit id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_lifecycle_override_audit ALTER COLUMN id SET DEFAULT nextval('public.component_lifecycle_override_audit_id_seq'::regclass);


--
-- Name: email_verification_tokens id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_verification_tokens ALTER COLUMN id SET DEFAULT nextval('public.email_verification_tokens_id_seq'::regclass);


--
-- Name: iam_users id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.iam_users ALTER COLUMN id SET DEFAULT nextval('public.iam_users_id_seq'::regclass);


--
-- Name: lifecycle_provider_configs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lifecycle_provider_configs ALTER COLUMN id SET DEFAULT nextval('public.lifecycle_provider_configs_id_seq'::regclass);


--
-- Name: lifecycle_provider_secrets id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lifecycle_provider_secrets ALTER COLUMN id SET DEFAULT nextval('public.lifecycle_provider_secrets_id_seq'::regclass);


--
-- Name: lifecycle_vendor_records id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lifecycle_vendor_records ALTER COLUMN id SET DEFAULT nextval('public.lifecycle_vendor_records_id_seq'::regclass);


--
-- Name: nvd_lookup_cache id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.nvd_lookup_cache ALTER COLUMN id SET DEFAULT nextval('public.nvd_lookup_cache_id_seq'::regclass);


--
-- Name: nvd_settings id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.nvd_settings ALTER COLUMN id SET DEFAULT nextval('public.nvd_settings_id_seq'::regclass);


--
-- Name: nvd_sync_runs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.nvd_sync_runs ALTER COLUMN id SET DEFAULT nextval('public.nvd_sync_runs_id_seq'::regclass);


--
-- Name: platform_user_roles id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_user_roles ALTER COLUMN id SET DEFAULT nextval('public.platform_user_roles_id_seq'::regclass);


--
-- Name: products id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.products ALTER COLUMN id SET DEFAULT nextval('public.products_id_seq'::regclass);


--
-- Name: projects id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.projects ALTER COLUMN id SET DEFAULT nextval('public.projects_id_seq'::regclass);


--
-- Name: run_cache id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.run_cache ALTER COLUMN id SET DEFAULT nextval('public.run_cache_id_seq'::regclass);


--
-- Name: sbom_analysis_report id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sbom_analysis_report ALTER COLUMN id SET DEFAULT nextval('public.sbom_analysis_report_id_seq'::regclass);


--
-- Name: sbom_component id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sbom_component ALTER COLUMN id SET DEFAULT nextval('public.sbom_component_id_seq'::regclass);


--
-- Name: sbom_source id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sbom_source ALTER COLUMN id SET DEFAULT nextval('public.sbom_source_id_seq'::regclass);


--
-- Name: sbom_type id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sbom_type ALTER COLUMN id SET DEFAULT nextval('public.sbom_type_id_seq'::regclass);


--
-- Name: sbom_validation_session_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sbom_validation_session_events ALTER COLUMN id SET DEFAULT nextval('public.sbom_validation_session_events_id_seq'::regclass);


--
-- Name: tenant_users id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_users ALTER COLUMN id SET DEFAULT nextval('public.tenant_users_id_seq'::regclass);


--
-- Name: tenants id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenants ALTER COLUMN id SET DEFAULT nextval('public.tenants_id_seq'::regclass);


--
-- Name: vex_documents id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vex_documents ALTER COLUMN id SET DEFAULT nextval('public.vex_documents_id_seq'::regclass);


--
-- Name: vex_override_audit id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vex_override_audit ALTER COLUMN id SET DEFAULT nextval('public.vex_override_audit_id_seq'::regclass);


--
-- Name: vex_statements id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vex_statements ALTER COLUMN id SET DEFAULT nextval('public.vex_statements_id_seq'::regclass);


--
-- Name: vulnerability_remediation id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vulnerability_remediation ALTER COLUMN id SET DEFAULT nextval('public.vulnerability_remediation_id_seq'::regclass);


--
-- Name: vulnerability_remediation_audit id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vulnerability_remediation_audit ALTER COLUMN id SET DEFAULT nextval('public.vulnerability_remediation_audit_id_seq'::regclass);


--
-- Name: cves cves_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cves
    ADD CONSTRAINT cves_pkey PRIMARY KEY (cve_id);


--
-- Name: nvd_settings nvd_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.nvd_settings
    ADD CONSTRAINT nvd_settings_pkey PRIMARY KEY (id);


--
-- Name: nvd_sync_runs nvd_sync_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.nvd_sync_runs
    ADD CONSTRAINT nvd_sync_runs_pkey PRIMARY KEY (id);


--
-- Name: ai_credential_audit_log pk_ai_credential_audit_log; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ai_credential_audit_log
    ADD CONSTRAINT pk_ai_credential_audit_log PRIMARY KEY (id);


--
-- Name: ai_fix_batch pk_ai_fix_batch; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ai_fix_batch
    ADD CONSTRAINT pk_ai_fix_batch PRIMARY KEY (id);


--
-- Name: ai_fix_cache pk_ai_fix_cache; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ai_fix_cache
    ADD CONSTRAINT pk_ai_fix_cache PRIMARY KEY (cache_key);


--
-- Name: ai_provider_config pk_ai_provider_config; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ai_provider_config
    ADD CONSTRAINT pk_ai_provider_config PRIMARY KEY (provider_name);


--
-- Name: ai_provider_credential pk_ai_provider_credential; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ai_provider_credential
    ADD CONSTRAINT pk_ai_provider_credential PRIMARY KEY (id);


--
-- Name: ai_settings pk_ai_settings; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ai_settings
    ADD CONSTRAINT pk_ai_settings PRIMARY KEY (id);


--
-- Name: ai_usage_log pk_ai_usage_log; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ai_usage_log
    ADD CONSTRAINT pk_ai_usage_log PRIMARY KEY (id);


--
-- Name: analysis_finding pk_analysis_finding; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analysis_finding
    ADD CONSTRAINT pk_analysis_finding PRIMARY KEY (id);


--
-- Name: analysis_run pk_analysis_run; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analysis_run
    ADD CONSTRAINT pk_analysis_run PRIMARY KEY (id);


--
-- Name: analysis_schedule pk_analysis_schedule; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analysis_schedule
    ADD CONSTRAINT pk_analysis_schedule PRIMARY KEY (id);


--
-- Name: audit_log pk_audit_log; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT pk_audit_log PRIMARY KEY (id);


--
-- Name: authorization_audit_log pk_authorization_audit_log; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_audit_log
    ADD CONSTRAINT pk_authorization_audit_log PRIMARY KEY (id);


--
-- Name: compare_cache pk_compare_cache; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compare_cache
    ADD CONSTRAINT pk_compare_cache PRIMARY KEY (cache_key);


--
-- Name: component_lifecycle_cache pk_component_lifecycle_cache; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_lifecycle_cache
    ADD CONSTRAINT pk_component_lifecycle_cache PRIMARY KEY (id);


--
-- Name: component_lifecycle_override_audit pk_component_lifecycle_override_audit; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_lifecycle_override_audit
    ADD CONSTRAINT pk_component_lifecycle_override_audit PRIMARY KEY (id);


--
-- Name: cve_cache pk_cve_cache; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cve_cache
    ADD CONSTRAINT pk_cve_cache PRIMARY KEY (cve_id);


--
-- Name: email_verification_tokens pk_email_verification_tokens; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_verification_tokens
    ADD CONSTRAINT pk_email_verification_tokens PRIMARY KEY (id);


--
-- Name: epss_score pk_epss_score; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.epss_score
    ADD CONSTRAINT pk_epss_score PRIMARY KEY (cve_id);


--
-- Name: iam_users pk_iam_users; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.iam_users
    ADD CONSTRAINT pk_iam_users PRIMARY KEY (id);


--
-- Name: kev_vulnerabilities pk_kev_vulnerabilities; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.kev_vulnerabilities
    ADD CONSTRAINT pk_kev_vulnerabilities PRIMARY KEY (cve_id);


--
-- Name: lifecycle_provider_configs pk_lifecycle_provider_configs; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lifecycle_provider_configs
    ADD CONSTRAINT pk_lifecycle_provider_configs PRIMARY KEY (id);


--
-- Name: lifecycle_provider_secrets pk_lifecycle_provider_secrets; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lifecycle_provider_secrets
    ADD CONSTRAINT pk_lifecycle_provider_secrets PRIMARY KEY (id);


--
-- Name: lifecycle_vendor_records pk_lifecycle_vendor_records; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lifecycle_vendor_records
    ADD CONSTRAINT pk_lifecycle_vendor_records PRIMARY KEY (id);


--
-- Name: nvd_lookup_cache pk_nvd_lookup_cache; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.nvd_lookup_cache
    ADD CONSTRAINT pk_nvd_lookup_cache PRIMARY KEY (id);


--
-- Name: platform_user_roles pk_platform_user_roles; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_user_roles
    ADD CONSTRAINT pk_platform_user_roles PRIMARY KEY (id);


--
-- Name: products pk_products; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.products
    ADD CONSTRAINT pk_products PRIMARY KEY (id);


--
-- Name: projects pk_projects; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.projects
    ADD CONSTRAINT pk_projects PRIMARY KEY (id);


--
-- Name: run_cache pk_run_cache; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.run_cache
    ADD CONSTRAINT pk_run_cache PRIMARY KEY (id);


--
-- Name: sbom_analysis_report pk_sbom_analysis_report; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sbom_analysis_report
    ADD CONSTRAINT pk_sbom_analysis_report PRIMARY KEY (id);


--
-- Name: sbom_component pk_sbom_component; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sbom_component
    ADD CONSTRAINT pk_sbom_component PRIMARY KEY (id);


--
-- Name: sbom_source pk_sbom_source; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sbom_source
    ADD CONSTRAINT pk_sbom_source PRIMARY KEY (id);


--
-- Name: sbom_type pk_sbom_type; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sbom_type
    ADD CONSTRAINT pk_sbom_type PRIMARY KEY (id);


--
-- Name: sbom_validation_session_events pk_sbom_validation_session_events; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sbom_validation_session_events
    ADD CONSTRAINT pk_sbom_validation_session_events PRIMARY KEY (id);


--
-- Name: sbom_validation_sessions pk_sbom_validation_sessions; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sbom_validation_sessions
    ADD CONSTRAINT pk_sbom_validation_sessions PRIMARY KEY (id);


--
-- Name: source_response_cache pk_source_response_cache; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.source_response_cache
    ADD CONSTRAINT pk_source_response_cache PRIMARY KEY (source, component_key);


--
-- Name: tenant_users pk_tenant_users; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_users
    ADD CONSTRAINT pk_tenant_users PRIMARY KEY (id);


--
-- Name: tenants pk_tenants; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenants
    ADD CONSTRAINT pk_tenants PRIMARY KEY (id);


--
-- Name: vex_documents pk_vex_documents; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vex_documents
    ADD CONSTRAINT pk_vex_documents PRIMARY KEY (id);


--
-- Name: vex_override_audit pk_vex_override_audit; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vex_override_audit
    ADD CONSTRAINT pk_vex_override_audit PRIMARY KEY (id);


--
-- Name: vex_statements pk_vex_statements; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vex_statements
    ADD CONSTRAINT pk_vex_statements PRIMARY KEY (id);


--
-- Name: vulnerability_remediation pk_vulnerability_remediation; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vulnerability_remediation
    ADD CONSTRAINT pk_vulnerability_remediation PRIMARY KEY (id);


--
-- Name: vulnerability_remediation_audit pk_vulnerability_remediation_audit; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vulnerability_remediation_audit
    ADD CONSTRAINT pk_vulnerability_remediation_audit PRIMARY KEY (id);


--
-- Name: ai_provider_credential uq_ai_provider_credential_provider_label; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ai_provider_credential
    ADD CONSTRAINT uq_ai_provider_credential_provider_label UNIQUE (provider_name, label);


--
-- Name: analysis_finding uq_analysis_finding_run_vuln_cpe; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analysis_finding
    ADD CONSTRAINT uq_analysis_finding_run_vuln_cpe UNIQUE (analysis_run_id, vuln_id, cpe);


--
-- Name: component_lifecycle_cache uq_component_lifecycle_cache_identity; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_lifecycle_cache
    ADD CONSTRAINT uq_component_lifecycle_cache_identity UNIQUE (normalized_name, normalized_version, ecosystem, purl);


--
-- Name: email_verification_tokens uq_email_verification_tokens_token_hash; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_verification_tokens
    ADD CONSTRAINT uq_email_verification_tokens_token_hash UNIQUE (token_hash);


--
-- Name: iam_users uq_iam_users_external_iam_user_id; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.iam_users
    ADD CONSTRAINT uq_iam_users_external_iam_user_id UNIQUE (external_iam_user_id);


--
-- Name: iam_users uq_iam_users_external_identity; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.iam_users
    ADD CONSTRAINT uq_iam_users_external_identity UNIQUE (external_issuer, external_subject);


--
-- Name: lifecycle_provider_secrets uq_lifecycle_provider_secret_provider_name; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lifecycle_provider_secrets
    ADD CONSTRAINT uq_lifecycle_provider_secret_provider_name UNIQUE (provider_key, secret_name);


--
-- Name: nvd_lookup_cache uq_nvd_lookup_cache_type_hash; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.nvd_lookup_cache
    ADD CONSTRAINT uq_nvd_lookup_cache_type_hash UNIQUE (lookup_type, identifier_hash);


--
-- Name: products uq_products_tenant_project_slug; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.products
    ADD CONSTRAINT uq_products_tenant_project_slug UNIQUE (tenant_id, project_id, slug);


--
-- Name: projects uq_projects_tenant_name; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.projects
    ADD CONSTRAINT uq_projects_tenant_name UNIQUE (tenant_id, project_name);


--
-- Name: sbom_component uq_sbom_component_fingerprint; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sbom_component
    ADD CONSTRAINT uq_sbom_component_fingerprint UNIQUE (tenant_id, sbom_id, bom_ref, name, version, cpe);


--
-- Name: sbom_source uq_sbom_source_tenant_name_version; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sbom_source
    ADD CONSTRAINT uq_sbom_source_tenant_name_version UNIQUE (tenant_id, sbom_name, sbom_version);


--
-- Name: sbom_type uq_sbom_type_typename; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sbom_type
    ADD CONSTRAINT uq_sbom_type_typename UNIQUE (typename);


--
-- Name: tenant_users uq_tenant_users_tenant_user; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_users
    ADD CONSTRAINT uq_tenant_users_tenant_user UNIQUE (tenant_id, user_id);


--
-- Name: tenants uq_tenants_external_iam_tenant_id; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenants
    ADD CONSTRAINT uq_tenants_external_iam_tenant_id UNIQUE (external_iam_tenant_id);


--
-- Name: tenants uq_tenants_slug; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenants
    ADD CONSTRAINT uq_tenants_slug UNIQUE (slug);


--
-- Name: ix_ai_credential_audit_log_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ai_credential_audit_log_created_at ON public.ai_credential_audit_log USING btree (created_at);


--
-- Name: ix_ai_credential_audit_log_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ai_credential_audit_log_id ON public.ai_credential_audit_log USING btree (id);


--
-- Name: ix_ai_fix_batch_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ai_fix_batch_created_at ON public.ai_fix_batch USING btree (created_at);


--
-- Name: ix_ai_fix_batch_deactivated; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ai_fix_batch_deactivated ON public.ai_fix_batch USING btree (is_active) WHERE (is_active = false);


--
-- Name: ix_ai_fix_batch_run_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ai_fix_batch_run_status ON public.ai_fix_batch USING btree (run_id, status);


--
-- Name: ix_ai_fix_batch_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ai_fix_batch_tenant_id ON public.ai_fix_batch USING btree (tenant_id);


--
-- Name: ix_ai_fix_batch_tenant_identity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ai_fix_batch_tenant_identity ON public.ai_fix_batch USING btree (tenant_id, id);


--
-- Name: ix_ai_fix_cache_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ai_fix_cache_expires_at ON public.ai_fix_cache USING btree (expires_at);


--
-- Name: ix_ai_fix_cache_vuln_component; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ai_fix_cache_vuln_component ON public.ai_fix_cache USING btree (vuln_id, component_name, component_version);


--
-- Name: ix_ai_fix_cache_vuln_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ai_fix_cache_vuln_id ON public.ai_fix_cache USING btree (vuln_id);


--
-- Name: ix_ai_only_one_default; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_ai_only_one_default ON public.ai_provider_credential USING btree (is_default) WHERE (is_default = true);


--
-- Name: ix_ai_only_one_fallback; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_ai_only_one_fallback ON public.ai_provider_credential USING btree (is_fallback) WHERE (is_fallback = true);


--
-- Name: ix_ai_provider_credential_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ai_provider_credential_id ON public.ai_provider_credential USING btree (id);


--
-- Name: ix_ai_provider_credential_provider_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ai_provider_credential_provider_name ON public.ai_provider_credential USING btree (provider_name);


--
-- Name: ix_ai_usage_log_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ai_usage_log_created_at ON public.ai_usage_log USING btree (created_at);


--
-- Name: ix_ai_usage_log_finding_cache_key; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ai_usage_log_finding_cache_key ON public.ai_usage_log USING btree (finding_cache_key);


--
-- Name: ix_ai_usage_log_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ai_usage_log_id ON public.ai_usage_log USING btree (id);


--
-- Name: ix_ai_usage_log_provider; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ai_usage_log_provider ON public.ai_usage_log USING btree (provider);


--
-- Name: ix_ai_usage_log_provider_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ai_usage_log_provider_created ON public.ai_usage_log USING btree (provider, created_at);


--
-- Name: ix_ai_usage_log_purpose; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ai_usage_log_purpose ON public.ai_usage_log USING btree (purpose);


--
-- Name: ix_ai_usage_log_purpose_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ai_usage_log_purpose_created ON public.ai_usage_log USING btree (purpose, created_at);


--
-- Name: ix_ai_usage_log_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ai_usage_log_tenant_id ON public.ai_usage_log USING btree (tenant_id);


--
-- Name: ix_ai_usage_log_tenant_identity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ai_usage_log_tenant_identity ON public.ai_usage_log USING btree (tenant_id, id);


--
-- Name: ix_analysis_finding_analysis_run_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_analysis_finding_analysis_run_id ON public.analysis_finding USING btree (analysis_run_id);


--
-- Name: ix_analysis_finding_component_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_analysis_finding_component_id ON public.analysis_finding USING btree (component_id);


--
-- Name: ix_analysis_finding_cpe; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_analysis_finding_cpe ON public.analysis_finding USING btree (cpe);


--
-- Name: ix_analysis_finding_deactivated; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_analysis_finding_deactivated ON public.analysis_finding USING btree (is_active) WHERE (is_active = false);


--
-- Name: ix_analysis_finding_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_analysis_finding_id ON public.analysis_finding USING btree (id);


--
-- Name: ix_analysis_finding_match_reason; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_analysis_finding_match_reason ON public.analysis_finding USING btree (match_reason);


--
-- Name: ix_analysis_finding_match_strategy; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_analysis_finding_match_strategy ON public.analysis_finding USING btree (match_strategy);


--
-- Name: ix_analysis_finding_run_severity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_analysis_finding_run_severity ON public.analysis_finding USING btree (analysis_run_id, severity);


--
-- Name: ix_analysis_finding_severity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_analysis_finding_severity ON public.analysis_finding USING btree (severity);


--
-- Name: ix_analysis_finding_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_analysis_finding_tenant_id ON public.analysis_finding USING btree (tenant_id);


--
-- Name: ix_analysis_finding_tenant_identity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_analysis_finding_tenant_identity ON public.analysis_finding USING btree (tenant_id, id);


--
-- Name: ix_analysis_finding_vuln_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_analysis_finding_vuln_id ON public.analysis_finding USING btree (vuln_id);


--
-- Name: ix_analysis_run_deactivated; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_analysis_run_deactivated ON public.analysis_run USING btree (is_active) WHERE (is_active = false);


--
-- Name: ix_analysis_run_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_analysis_run_id ON public.analysis_run USING btree (id);


--
-- Name: ix_analysis_run_product_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_analysis_run_product_id ON public.analysis_run USING btree (product_id);


--
-- Name: ix_analysis_run_project_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_analysis_run_project_id ON public.analysis_run USING btree (project_id);


--
-- Name: ix_analysis_run_run_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_analysis_run_run_status ON public.analysis_run USING btree (run_status);


--
-- Name: ix_analysis_run_sbom_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_analysis_run_sbom_id ON public.analysis_run USING btree (sbom_id);


--
-- Name: ix_analysis_run_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_analysis_run_tenant_id ON public.analysis_run USING btree (tenant_id);


--
-- Name: ix_analysis_run_tenant_identity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_analysis_run_tenant_identity ON public.analysis_run USING btree (tenant_id, id);


--
-- Name: ix_analysis_run_trigger_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_analysis_run_trigger_source ON public.analysis_run USING btree (trigger_source);


--
-- Name: ix_analysis_schedule_deactivated; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_analysis_schedule_deactivated ON public.analysis_schedule USING btree (is_active) WHERE (is_active = false);


--
-- Name: ix_analysis_schedule_due; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_analysis_schedule_due ON public.analysis_schedule USING btree (enabled, next_run_at);


--
-- Name: ix_analysis_schedule_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_analysis_schedule_id ON public.analysis_schedule USING btree (id);


--
-- Name: ix_analysis_schedule_next_run_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_analysis_schedule_next_run_at ON public.analysis_schedule USING btree (next_run_at);


--
-- Name: ix_analysis_schedule_product_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_analysis_schedule_product_id ON public.analysis_schedule USING btree (product_id);


--
-- Name: ix_analysis_schedule_project_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_analysis_schedule_project_id ON public.analysis_schedule USING btree (project_id);


--
-- Name: ix_analysis_schedule_sbom_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_analysis_schedule_sbom_id ON public.analysis_schedule USING btree (sbom_id);


--
-- Name: ix_analysis_schedule_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_analysis_schedule_tenant_id ON public.analysis_schedule USING btree (tenant_id);


--
-- Name: ix_analysis_schedule_tenant_identity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_analysis_schedule_tenant_identity ON public.analysis_schedule USING btree (tenant_id, id);


--
-- Name: ix_audit_log_action; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_audit_log_action ON public.audit_log USING btree (action);


--
-- Name: ix_audit_log_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_audit_log_created_at ON public.audit_log USING btree (created_at);


--
-- Name: ix_audit_log_entity_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_audit_log_entity_id ON public.audit_log USING btree (entity_id);


--
-- Name: ix_audit_log_entity_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_audit_log_entity_type ON public.audit_log USING btree (entity_type);


--
-- Name: ix_audit_log_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_audit_log_id ON public.audit_log USING btree (id);


--
-- Name: ix_audit_log_target_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_audit_log_target_id ON public.audit_log USING btree (target_id);


--
-- Name: ix_audit_log_target_kind; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_audit_log_target_kind ON public.audit_log USING btree (target_kind);


--
-- Name: ix_audit_log_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_audit_log_tenant_id ON public.audit_log USING btree (tenant_id);


--
-- Name: ix_audit_log_tenant_identity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_audit_log_tenant_identity ON public.audit_log USING btree (tenant_id, id);


--
-- Name: ix_audit_log_user_ref_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_audit_log_user_ref_id ON public.audit_log USING btree (user_ref_id);


--
-- Name: ix_authorization_audit_log_action; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_authorization_audit_log_action ON public.authorization_audit_log USING btree (action);


--
-- Name: ix_authorization_audit_log_actor_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_authorization_audit_log_actor_user_id ON public.authorization_audit_log USING btree (actor_user_id);


--
-- Name: ix_authorization_audit_log_correlation_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_authorization_audit_log_correlation_id ON public.authorization_audit_log USING btree (correlation_id);


--
-- Name: ix_authorization_audit_log_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_authorization_audit_log_created_at ON public.authorization_audit_log USING btree (created_at);


--
-- Name: ix_authorization_audit_log_outcome; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_authorization_audit_log_outcome ON public.authorization_audit_log USING btree (outcome);


--
-- Name: ix_authorization_audit_log_target_membership_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_authorization_audit_log_target_membership_id ON public.authorization_audit_log USING btree (target_membership_id);


--
-- Name: ix_authorization_audit_log_target_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_authorization_audit_log_target_user_id ON public.authorization_audit_log USING btree (target_user_id);


--
-- Name: ix_authorization_audit_log_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_authorization_audit_log_tenant_id ON public.authorization_audit_log USING btree (tenant_id);


--
-- Name: ix_compare_cache_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_compare_cache_expires_at ON public.compare_cache USING btree (expires_at);


--
-- Name: ix_compare_cache_run_a_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_compare_cache_run_a_id ON public.compare_cache USING btree (run_a_id);


--
-- Name: ix_compare_cache_run_b_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_compare_cache_run_b_id ON public.compare_cache USING btree (run_b_id);


--
-- Name: ix_compare_cache_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_compare_cache_tenant_id ON public.compare_cache USING btree (tenant_id);


--
-- Name: ix_compare_cache_tenant_identity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_compare_cache_tenant_identity ON public.compare_cache USING btree (tenant_id, cache_key);


--
-- Name: ix_component_lifecycle_cache_checked_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_component_lifecycle_cache_checked_at ON public.component_lifecycle_cache USING btree (checked_at);


--
-- Name: ix_component_lifecycle_cache_cpe; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_component_lifecycle_cache_cpe ON public.component_lifecycle_cache USING btree (cpe);


--
-- Name: ix_component_lifecycle_cache_ecosystem; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_component_lifecycle_cache_ecosystem ON public.component_lifecycle_cache USING btree (ecosystem);


--
-- Name: ix_component_lifecycle_cache_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_component_lifecycle_cache_expires_at ON public.component_lifecycle_cache USING btree (expires_at);


--
-- Name: ix_component_lifecycle_cache_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_component_lifecycle_cache_id ON public.component_lifecycle_cache USING btree (id);


--
-- Name: ix_component_lifecycle_cache_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_component_lifecycle_cache_lookup ON public.component_lifecycle_cache USING btree (ecosystem, normalized_name, normalized_version);


--
-- Name: ix_component_lifecycle_cache_lookup_key; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_component_lifecycle_cache_lookup_key ON public.component_lifecycle_cache USING btree (lookup_key);


--
-- Name: ix_component_lifecycle_cache_normalized_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_component_lifecycle_cache_normalized_name ON public.component_lifecycle_cache USING btree (normalized_name);


--
-- Name: ix_component_lifecycle_cache_normalized_version; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_component_lifecycle_cache_normalized_version ON public.component_lifecycle_cache USING btree (normalized_version);


--
-- Name: ix_component_lifecycle_cache_purl; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_component_lifecycle_cache_purl ON public.component_lifecycle_cache USING btree (purl);


--
-- Name: ix_component_lifecycle_override_audit_changed_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_component_lifecycle_override_audit_changed_at ON public.component_lifecycle_override_audit USING btree (changed_at);


--
-- Name: ix_component_lifecycle_override_audit_changed_by; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_component_lifecycle_override_audit_changed_by ON public.component_lifecycle_override_audit USING btree (changed_by);


--
-- Name: ix_component_lifecycle_override_audit_component_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_component_lifecycle_override_audit_component_id ON public.component_lifecycle_override_audit USING btree (component_id);


--
-- Name: ix_component_lifecycle_override_audit_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_component_lifecycle_override_audit_id ON public.component_lifecycle_override_audit USING btree (id);


--
-- Name: ix_component_lifecycle_override_audit_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_component_lifecycle_override_audit_tenant_id ON public.component_lifecycle_override_audit USING btree (tenant_id);


--
-- Name: ix_component_lifecycle_override_audit_tenant_identity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_component_lifecycle_override_audit_tenant_identity ON public.component_lifecycle_override_audit USING btree (tenant_id, id);


--
-- Name: ix_cve_cache_cve_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_cve_cache_cve_id ON public.cve_cache USING btree (cve_id);


--
-- Name: ix_cve_cache_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_cve_cache_expires_at ON public.cve_cache USING btree (expires_at);


--
-- Name: ix_cves_cpe_match_gin; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_cves_cpe_match_gin ON public.cves USING gin (cpe_match jsonb_path_ops);


--
-- Name: ix_cves_last_modified; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_cves_last_modified ON public.cves USING btree (last_modified);


--
-- Name: ix_cves_vuln_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_cves_vuln_status ON public.cves USING btree (vuln_status);


--
-- Name: ix_email_verification_tokens_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_email_verification_tokens_expires_at ON public.email_verification_tokens USING btree (expires_at);


--
-- Name: ix_email_verification_tokens_user_consumed; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_email_verification_tokens_user_consumed ON public.email_verification_tokens USING btree (user_id, consumed_at);


--
-- Name: ix_email_verification_tokens_user_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_email_verification_tokens_user_created ON public.email_verification_tokens USING btree (user_id, created_at);


--
-- Name: ix_email_verification_tokens_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_email_verification_tokens_user_id ON public.email_verification_tokens USING btree (user_id);


--
-- Name: ix_epss_score_cve_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_epss_score_cve_id ON public.epss_score USING btree (cve_id);


--
-- Name: ix_iam_users_email; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_iam_users_email ON public.iam_users USING btree (email);


--
-- Name: ix_iam_users_employee_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_iam_users_employee_id ON public.iam_users USING btree (employee_id);


--
-- Name: ix_iam_users_external_iam_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_iam_users_external_iam_user_id ON public.iam_users USING btree (external_iam_user_id);


--
-- Name: ix_iam_users_user_principal_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_iam_users_user_principal_name ON public.iam_users USING btree (user_principal_name);


--
-- Name: ix_iam_users_verification_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_iam_users_verification_status ON public.iam_users USING btree (verification_required, status);


--
-- Name: ix_kev_vulnerabilities_cve_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_kev_vulnerabilities_cve_id ON public.kev_vulnerabilities USING btree (cve_id);


--
-- Name: ix_kev_vulnerabilities_date_added; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_kev_vulnerabilities_date_added ON public.kev_vulnerabilities USING btree (date_added);


--
-- Name: ix_kev_vulnerabilities_ransomware; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_kev_vulnerabilities_ransomware ON public.kev_vulnerabilities USING btree (known_ransomware_campaign_use);


--
-- Name: ix_lifecycle_provider_configs_enabled_priority; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_lifecycle_provider_configs_enabled_priority ON public.lifecycle_provider_configs USING btree (enabled, priority);


--
-- Name: ix_lifecycle_provider_configs_health_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_lifecycle_provider_configs_health_status ON public.lifecycle_provider_configs USING btree (health_status);


--
-- Name: ix_lifecycle_provider_configs_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_lifecycle_provider_configs_id ON public.lifecycle_provider_configs USING btree (id);


--
-- Name: ix_lifecycle_provider_configs_provider_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_lifecycle_provider_configs_provider_key ON public.lifecycle_provider_configs USING btree (provider_key);


--
-- Name: ix_lifecycle_provider_configs_provider_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_lifecycle_provider_configs_provider_type ON public.lifecycle_provider_configs USING btree (provider_type);


--
-- Name: ix_lifecycle_provider_secrets_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_lifecycle_provider_secrets_id ON public.lifecycle_provider_secrets USING btree (id);


--
-- Name: ix_lifecycle_provider_secrets_provider; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_lifecycle_provider_secrets_provider ON public.lifecycle_provider_secrets USING btree (provider_key);


--
-- Name: ix_lifecycle_provider_secrets_provider_key; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_lifecycle_provider_secrets_provider_key ON public.lifecycle_provider_secrets USING btree (provider_key);


--
-- Name: ix_lifecycle_vendor_records_ecosystem; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_lifecycle_vendor_records_ecosystem ON public.lifecycle_vendor_records USING btree (ecosystem);


--
-- Name: ix_lifecycle_vendor_records_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_lifecycle_vendor_records_enabled ON public.lifecycle_vendor_records USING btree (enabled);


--
-- Name: ix_lifecycle_vendor_records_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_lifecycle_vendor_records_id ON public.lifecycle_vendor_records USING btree (id);


--
-- Name: ix_lifecycle_vendor_records_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_lifecycle_vendor_records_lookup ON public.lifecycle_vendor_records USING btree (enabled, ecosystem, product_name);


--
-- Name: ix_lifecycle_vendor_records_product_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_lifecycle_vendor_records_product_name ON public.lifecycle_vendor_records USING btree (product_name);


--
-- Name: ix_lifecycle_vendor_records_vendor_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_lifecycle_vendor_records_vendor_name ON public.lifecycle_vendor_records USING btree (vendor_name);


--
-- Name: ix_nvd_lookup_cache_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_nvd_lookup_cache_expires_at ON public.nvd_lookup_cache USING btree (expires_at);


--
-- Name: ix_nvd_lookup_cache_identifier; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_nvd_lookup_cache_identifier ON public.nvd_lookup_cache USING btree (identifier);


--
-- Name: ix_nvd_lookup_cache_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_nvd_lookup_cache_status ON public.nvd_lookup_cache USING btree (status);


--
-- Name: ix_nvd_sync_runs_started_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_nvd_sync_runs_started_at ON public.nvd_sync_runs USING btree (started_at);


--
-- Name: ix_platform_user_roles_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_platform_user_roles_status ON public.platform_user_roles USING btree (status);


--
-- Name: ix_platform_user_roles_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_platform_user_roles_user_id ON public.platform_user_roles USING btree (user_id);


--
-- Name: ix_products_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_products_created_at ON public.products USING btree (created_at);


--
-- Name: ix_products_created_by; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_products_created_by ON public.products USING btree (created_by);


--
-- Name: ix_products_deleted_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_products_deleted_at ON public.products USING btree (deleted_at);


--
-- Name: ix_products_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_products_id ON public.products USING btree (id);


--
-- Name: ix_products_product_key; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_products_product_key ON public.products USING btree (product_key);


--
-- Name: ix_products_project_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_products_project_id ON public.products USING btree (project_id);


--
-- Name: ix_products_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_products_status ON public.products USING btree (status);


--
-- Name: ix_products_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_products_tenant_id ON public.products USING btree (tenant_id);


--
-- Name: ix_products_tenant_project; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_products_tenant_project ON public.products USING btree (tenant_id, project_id);


--
-- Name: ix_products_tenant_project_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_products_tenant_project_name ON public.products USING btree (tenant_id, project_id, normalized_name);


--
-- Name: ix_projects_created_by; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_projects_created_by ON public.projects USING btree (created_by);


--
-- Name: ix_projects_deactivated; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_projects_deactivated ON public.projects USING btree (is_active) WHERE (is_active = false);


--
-- Name: ix_projects_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_projects_id ON public.projects USING btree (id);


--
-- Name: ix_projects_project_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_projects_project_name ON public.projects USING btree (project_name);


--
-- Name: ix_projects_tenant_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_projects_tenant_created ON public.projects USING btree (tenant_id, created_on);


--
-- Name: ix_projects_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_projects_tenant_id ON public.projects USING btree (tenant_id);


--
-- Name: ix_projects_tenant_identity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_projects_tenant_identity ON public.projects USING btree (tenant_id, id);


--
-- Name: ix_run_cache_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_run_cache_id ON public.run_cache USING btree (id);


--
-- Name: ix_run_cache_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_run_cache_tenant_id ON public.run_cache USING btree (tenant_id);


--
-- Name: ix_run_cache_tenant_identity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_run_cache_tenant_identity ON public.run_cache USING btree (tenant_id, id);


--
-- Name: ix_sbom_analysis_report_deactivated; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_analysis_report_deactivated ON public.sbom_analysis_report USING btree (is_active) WHERE (is_active = false);


--
-- Name: ix_sbom_analysis_report_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_analysis_report_id ON public.sbom_analysis_report USING btree (id);


--
-- Name: ix_sbom_analysis_report_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_analysis_report_tenant_id ON public.sbom_analysis_report USING btree (tenant_id);


--
-- Name: ix_sbom_analysis_report_tenant_identity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_analysis_report_tenant_identity ON public.sbom_analysis_report USING btree (tenant_id, id);


--
-- Name: ix_sbom_component_bom_ref; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_component_bom_ref ON public.sbom_component USING btree (bom_ref);


--
-- Name: ix_sbom_component_cpe; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_component_cpe ON public.sbom_component USING btree (cpe);


--
-- Name: ix_sbom_component_cpe_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_component_cpe_source ON public.sbom_component USING btree (cpe_source);


--
-- Name: ix_sbom_component_deactivated; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_component_deactivated ON public.sbom_component USING btree (is_active) WHERE (is_active = false);


--
-- Name: ix_sbom_component_dedupe_canonical_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_component_dedupe_canonical_id ON public.sbom_component USING btree (dedupe_canonical_id);


--
-- Name: ix_sbom_component_dedupe_group_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_component_dedupe_group_id ON public.sbom_component USING btree (dedupe_group_id);


--
-- Name: ix_sbom_component_duplicate_of_component_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_component_duplicate_of_component_id ON public.sbom_component USING btree (duplicate_of_component_id);


--
-- Name: ix_sbom_component_ecosystem; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_component_ecosystem ON public.sbom_component USING btree (ecosystem);


--
-- Name: ix_sbom_component_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_component_id ON public.sbom_component USING btree (id);


--
-- Name: ix_sbom_component_lifecycle; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_component_lifecycle ON public.sbom_component USING btree (lifecycle_status, ecosystem);


--
-- Name: ix_sbom_component_lifecycle_checked_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_component_lifecycle_checked_at ON public.sbom_component USING btree (lifecycle_checked_at);


--
-- Name: ix_sbom_component_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_component_name ON public.sbom_component USING btree (name);


--
-- Name: ix_sbom_component_normalized_component_key; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_component_normalized_component_key ON public.sbom_component USING btree (normalized_component_key);


--
-- Name: ix_sbom_component_normalized_ecosystem; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_component_normalized_ecosystem ON public.sbom_component USING btree (normalized_ecosystem);


--
-- Name: ix_sbom_component_normalized_identity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_component_normalized_identity ON public.sbom_component USING btree (normalized_ecosystem, normalized_name, normalized_version);


--
-- Name: ix_sbom_component_normalized_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_component_normalized_name ON public.sbom_component USING btree (normalized_name);


--
-- Name: ix_sbom_component_normalized_package_key; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_component_normalized_package_key ON public.sbom_component USING btree (normalized_package_key);


--
-- Name: ix_sbom_component_normalized_purl; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_component_normalized_purl ON public.sbom_component USING btree (normalized_purl);


--
-- Name: ix_sbom_component_normalized_version; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_component_normalized_version ON public.sbom_component USING btree (normalized_version);


--
-- Name: ix_sbom_component_primary_cpe; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_component_primary_cpe ON public.sbom_component USING btree (primary_cpe);


--
-- Name: ix_sbom_component_sbom_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_component_sbom_id ON public.sbom_component USING btree (sbom_id);


--
-- Name: ix_sbom_component_sbom_is_duplicate; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_component_sbom_is_duplicate ON public.sbom_component USING btree (sbom_id, is_duplicate);


--
-- Name: ix_sbom_component_sbom_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_component_sbom_name ON public.sbom_component USING btree (sbom_id, name);


--
-- Name: ix_sbom_component_sbom_normalized_key; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_component_sbom_normalized_key ON public.sbom_component USING btree (sbom_id, normalized_component_key);


--
-- Name: ix_sbom_component_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_component_tenant_id ON public.sbom_component USING btree (tenant_id);


--
-- Name: ix_sbom_component_tenant_identity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_component_tenant_identity ON public.sbom_component USING btree (tenant_id, id);


--
-- Name: ix_sbom_component_version; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_component_version ON public.sbom_component USING btree (version);


--
-- Name: ix_sbom_source_component_extraction_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_source_component_extraction_status ON public.sbom_source USING btree (component_extraction_status);


--
-- Name: ix_sbom_source_conversion_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_source_conversion_status ON public.sbom_source USING btree (conversion_status);


--
-- Name: ix_sbom_source_converted_from_format; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_source_converted_from_format ON public.sbom_source USING btree (converted_from_format);


--
-- Name: ix_sbom_source_converted_sbom_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_source_converted_sbom_id ON public.sbom_source USING btree (converted_sbom_id);


--
-- Name: ix_sbom_source_created_by; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_source_created_by ON public.sbom_source USING btree (created_by);


--
-- Name: ix_sbom_source_deactivated; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_source_deactivated ON public.sbom_source USING btree (is_active) WHERE (is_active = false);


--
-- Name: ix_sbom_source_enrichment_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_source_enrichment_status ON public.sbom_source USING btree (enrichment_status);


--
-- Name: ix_sbom_source_failed_stage; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_source_failed_stage ON public.sbom_source USING btree (failed_stage);


--
-- Name: ix_sbom_source_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_source_id ON public.sbom_source USING btree (id);


--
-- Name: ix_sbom_source_parent_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_source_parent_id ON public.sbom_source USING btree (parent_id);


--
-- Name: ix_sbom_source_product_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_source_product_id ON public.sbom_source USING btree (product_id);


--
-- Name: ix_sbom_source_sbom_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_source_sbom_name ON public.sbom_source USING btree (sbom_name);


--
-- Name: ix_sbom_source_sbom_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_source_sbom_type ON public.sbom_source USING btree (sbom_type);


--
-- Name: ix_sbom_source_source_sbom_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_source_source_sbom_id ON public.sbom_source USING btree (source_sbom_id);


--
-- Name: ix_sbom_source_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_source_status ON public.sbom_source USING btree (status);


--
-- Name: ix_sbom_source_tenant_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_source_tenant_created ON public.sbom_source USING btree (tenant_id, created_on);


--
-- Name: ix_sbom_source_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_source_tenant_id ON public.sbom_source USING btree (tenant_id);


--
-- Name: ix_sbom_source_tenant_identity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_source_tenant_identity ON public.sbom_source USING btree (tenant_id, id);


--
-- Name: ix_sbom_source_tenant_product; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_source_tenant_product ON public.sbom_source USING btree (tenant_id, product_id);


--
-- Name: ix_sbom_source_tenant_project; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_source_tenant_project ON public.sbom_source USING btree (tenant_id, projectid);


--
-- Name: ix_sbom_type_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_type_id ON public.sbom_type USING btree (id);


--
-- Name: ix_sbom_validation_session_events_actor_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_validation_session_events_actor_user_id ON public.sbom_validation_session_events USING btree (actor_user_id);


--
-- Name: ix_sbom_validation_session_events_event_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_validation_session_events_event_type ON public.sbom_validation_session_events USING btree (event_type);


--
-- Name: ix_sbom_validation_session_events_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_validation_session_events_id ON public.sbom_validation_session_events USING btree (id);


--
-- Name: ix_sbom_validation_session_events_session_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_validation_session_events_session_id ON public.sbom_validation_session_events USING btree (session_id);


--
-- Name: ix_sbom_validation_session_events_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_validation_session_events_tenant_id ON public.sbom_validation_session_events USING btree (tenant_id);


--
-- Name: ix_sbom_validation_session_events_tenant_identity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_validation_session_events_tenant_identity ON public.sbom_validation_session_events USING btree (tenant_id, id);


--
-- Name: ix_sbom_validation_session_events_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_validation_session_events_timestamp ON public.sbom_validation_session_events USING btree ("timestamp");


--
-- Name: ix_sbom_validation_sessions_content_sha256; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_validation_sessions_content_sha256 ON public.sbom_validation_sessions USING btree (content_sha256);


--
-- Name: ix_sbom_validation_sessions_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_validation_sessions_created_at ON public.sbom_validation_sessions USING btree (created_at);


--
-- Name: ix_sbom_validation_sessions_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_validation_sessions_expires_at ON public.sbom_validation_sessions USING btree (expires_at);


--
-- Name: ix_sbom_validation_sessions_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_validation_sessions_id ON public.sbom_validation_sessions USING btree (id);


--
-- Name: ix_sbom_validation_sessions_imported_sbom_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_validation_sessions_imported_sbom_id ON public.sbom_validation_sessions USING btree (imported_sbom_id);


--
-- Name: ix_sbom_validation_sessions_original_sha256; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_validation_sessions_original_sha256 ON public.sbom_validation_sessions USING btree (original_sha256);


--
-- Name: ix_sbom_validation_sessions_project_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_validation_sessions_project_id ON public.sbom_validation_sessions USING btree (project_id);


--
-- Name: ix_sbom_validation_sessions_sha256; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_validation_sessions_sha256 ON public.sbom_validation_sessions USING btree (sha256);


--
-- Name: ix_sbom_validation_sessions_stored_sha256; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_validation_sessions_stored_sha256 ON public.sbom_validation_sessions USING btree (stored_sha256);


--
-- Name: ix_sbom_validation_sessions_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_validation_sessions_tenant_id ON public.sbom_validation_sessions USING btree (tenant_id);


--
-- Name: ix_sbom_validation_sessions_tenant_identity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_validation_sessions_tenant_identity ON public.sbom_validation_sessions USING btree (tenant_id, id);


--
-- Name: ix_sbom_validation_sessions_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_validation_sessions_user_id ON public.sbom_validation_sessions USING btree (user_id);


--
-- Name: ix_sbom_validation_sessions_validation_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sbom_validation_sessions_validation_status ON public.sbom_validation_sessions USING btree (validation_status);


--
-- Name: ix_source_response_cache_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_source_response_cache_expires_at ON public.source_response_cache USING btree (expires_at);


--
-- Name: ix_tenant_users_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_tenant_users_tenant_id ON public.tenant_users USING btree (tenant_id);


--
-- Name: ix_tenant_users_tenant_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_tenant_users_tenant_status ON public.tenant_users USING btree (tenant_id, status);


--
-- Name: ix_tenant_users_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_tenant_users_user_id ON public.tenant_users USING btree (user_id);


--
-- Name: ix_tenants_external_iam_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_tenants_external_iam_tenant_id ON public.tenants USING btree (external_iam_tenant_id);


--
-- Name: ix_tenants_slug; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_tenants_slug ON public.tenants USING btree (slug);


--
-- Name: ix_vex_documents_format; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vex_documents_format ON public.vex_documents USING btree (format);


--
-- Name: ix_vex_documents_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vex_documents_id ON public.vex_documents USING btree (id);


--
-- Name: ix_vex_documents_sbom_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vex_documents_sbom_id ON public.vex_documents USING btree (sbom_id);


--
-- Name: ix_vex_documents_source_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vex_documents_source_type ON public.vex_documents USING btree (source_type);


--
-- Name: ix_vex_documents_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vex_documents_tenant_id ON public.vex_documents USING btree (tenant_id);


--
-- Name: ix_vex_documents_tenant_identity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vex_documents_tenant_identity ON public.vex_documents USING btree (tenant_id, id);


--
-- Name: ix_vex_documents_uploaded_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vex_documents_uploaded_at ON public.vex_documents USING btree (uploaded_at);


--
-- Name: ix_vex_documents_uploaded_by; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vex_documents_uploaded_by ON public.vex_documents USING btree (uploaded_by);


--
-- Name: ix_vex_documents_validation_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vex_documents_validation_status ON public.vex_documents USING btree (validation_status);


--
-- Name: ix_vex_override_audit_changed_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vex_override_audit_changed_at ON public.vex_override_audit USING btree (changed_at);


--
-- Name: ix_vex_override_audit_changed_by; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vex_override_audit_changed_by ON public.vex_override_audit USING btree (changed_by);


--
-- Name: ix_vex_override_audit_component_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vex_override_audit_component_id ON public.vex_override_audit USING btree (component_id);


--
-- Name: ix_vex_override_audit_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vex_override_audit_id ON public.vex_override_audit USING btree (id);


--
-- Name: ix_vex_override_audit_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vex_override_audit_tenant_id ON public.vex_override_audit USING btree (tenant_id);


--
-- Name: ix_vex_override_audit_tenant_identity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vex_override_audit_tenant_identity ON public.vex_override_audit USING btree (tenant_id, id);


--
-- Name: ix_vex_override_audit_vulnerability_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vex_override_audit_vulnerability_id ON public.vex_override_audit USING btree (vulnerability_id);


--
-- Name: ix_vex_statement_component_vuln; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vex_statement_component_vuln ON public.vex_statements USING btree (component_id, vulnerability_id);


--
-- Name: ix_vex_statement_sbom_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vex_statement_sbom_status ON public.vex_statements USING btree (sbom_id, status);


--
-- Name: ix_vex_statements_component_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vex_statements_component_id ON public.vex_statements USING btree (component_id);


--
-- Name: ix_vex_statements_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vex_statements_created_at ON public.vex_statements USING btree (created_at);


--
-- Name: ix_vex_statements_cve_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vex_statements_cve_id ON public.vex_statements USING btree (cve_id);


--
-- Name: ix_vex_statements_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vex_statements_id ON public.vex_statements USING btree (id);


--
-- Name: ix_vex_statements_sbom_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vex_statements_sbom_id ON public.vex_statements USING btree (sbom_id);


--
-- Name: ix_vex_statements_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vex_statements_status ON public.vex_statements USING btree (status);


--
-- Name: ix_vex_statements_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vex_statements_tenant_id ON public.vex_statements USING btree (tenant_id);


--
-- Name: ix_vex_statements_tenant_identity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vex_statements_tenant_identity ON public.vex_statements USING btree (tenant_id, id);


--
-- Name: ix_vex_statements_vex_document_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vex_statements_vex_document_id ON public.vex_statements USING btree (vex_document_id);


--
-- Name: ix_vex_statements_vulnerability_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vex_statements_vulnerability_id ON public.vex_statements USING btree (vulnerability_id);


--
-- Name: ix_vulnerability_remediation_audit_changed_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vulnerability_remediation_audit_changed_at ON public.vulnerability_remediation_audit USING btree (changed_at);


--
-- Name: ix_vulnerability_remediation_audit_component_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vulnerability_remediation_audit_component_name ON public.vulnerability_remediation_audit USING btree (component_name);


--
-- Name: ix_vulnerability_remediation_audit_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vulnerability_remediation_audit_id ON public.vulnerability_remediation_audit USING btree (id);


--
-- Name: ix_vulnerability_remediation_audit_project_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vulnerability_remediation_audit_project_id ON public.vulnerability_remediation_audit USING btree (project_id);


--
-- Name: ix_vulnerability_remediation_audit_remediation_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vulnerability_remediation_audit_remediation_id ON public.vulnerability_remediation_audit USING btree (remediation_id);


--
-- Name: ix_vulnerability_remediation_audit_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vulnerability_remediation_audit_tenant_id ON public.vulnerability_remediation_audit USING btree (tenant_id);


--
-- Name: ix_vulnerability_remediation_audit_tenant_identity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vulnerability_remediation_audit_tenant_identity ON public.vulnerability_remediation_audit USING btree (tenant_id, id);


--
-- Name: ix_vulnerability_remediation_audit_vuln_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vulnerability_remediation_audit_vuln_id ON public.vulnerability_remediation_audit USING btree (vuln_id);


--
-- Name: ix_vulnerability_remediation_component_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vulnerability_remediation_component_name ON public.vulnerability_remediation USING btree (component_name);


--
-- Name: ix_vulnerability_remediation_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vulnerability_remediation_id ON public.vulnerability_remediation USING btree (id);


--
-- Name: ix_vulnerability_remediation_project_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vulnerability_remediation_project_id ON public.vulnerability_remediation USING btree (project_id);


--
-- Name: ix_vulnerability_remediation_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vulnerability_remediation_tenant_id ON public.vulnerability_remediation USING btree (tenant_id);


--
-- Name: ix_vulnerability_remediation_tenant_identity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vulnerability_remediation_tenant_identity ON public.vulnerability_remediation USING btree (tenant_id, id);


--
-- Name: ix_vulnerability_remediation_vuln_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vulnerability_remediation_vuln_id ON public.vulnerability_remediation USING btree (vuln_id);


--
-- Name: uq_email_verification_tokens_active_user; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_email_verification_tokens_active_user ON public.email_verification_tokens USING btree (user_id) WHERE ((consumed_at IS NULL) AND (invalidated_at IS NULL));


--
-- Name: ai_fix_batch fk_ai_fix_batch_run_id_analysis_run; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ai_fix_batch
    ADD CONSTRAINT fk_ai_fix_batch_run_id_analysis_run FOREIGN KEY (run_id) REFERENCES public.analysis_run(id) ON DELETE CASCADE;


--
-- Name: ai_fix_batch fk_ai_fix_batch_tenant_id_tenants; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ai_fix_batch
    ADD CONSTRAINT fk_ai_fix_batch_tenant_id_tenants FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: ai_usage_log fk_ai_usage_log_tenant_id_tenants; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ai_usage_log
    ADD CONSTRAINT fk_ai_usage_log_tenant_id_tenants FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: analysis_finding fk_analysis_finding_analysis_run_id_analysis_run; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analysis_finding
    ADD CONSTRAINT fk_analysis_finding_analysis_run_id_analysis_run FOREIGN KEY (analysis_run_id) REFERENCES public.analysis_run(id);


--
-- Name: analysis_finding fk_analysis_finding_component_id_sbom_component; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analysis_finding
    ADD CONSTRAINT fk_analysis_finding_component_id_sbom_component FOREIGN KEY (component_id) REFERENCES public.sbom_component(id);


--
-- Name: analysis_finding fk_analysis_finding_tenant_id_tenants; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analysis_finding
    ADD CONSTRAINT fk_analysis_finding_tenant_id_tenants FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: analysis_run fk_analysis_run_product_id_products; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analysis_run
    ADD CONSTRAINT fk_analysis_run_product_id_products FOREIGN KEY (product_id) REFERENCES public.products(id);


--
-- Name: analysis_run fk_analysis_run_project_id_projects; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analysis_run
    ADD CONSTRAINT fk_analysis_run_project_id_projects FOREIGN KEY (project_id) REFERENCES public.projects(id);


--
-- Name: analysis_run fk_analysis_run_sbom_id_sbom_source; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analysis_run
    ADD CONSTRAINT fk_analysis_run_sbom_id_sbom_source FOREIGN KEY (sbom_id) REFERENCES public.sbom_source(id);


--
-- Name: analysis_run fk_analysis_run_tenant_id_tenants; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analysis_run
    ADD CONSTRAINT fk_analysis_run_tenant_id_tenants FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: analysis_schedule fk_analysis_schedule_last_run_id_analysis_run; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analysis_schedule
    ADD CONSTRAINT fk_analysis_schedule_last_run_id_analysis_run FOREIGN KEY (last_run_id) REFERENCES public.analysis_run(id) ON DELETE SET NULL;


--
-- Name: analysis_schedule fk_analysis_schedule_product_id_products; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analysis_schedule
    ADD CONSTRAINT fk_analysis_schedule_product_id_products FOREIGN KEY (product_id) REFERENCES public.products(id) ON DELETE CASCADE;


--
-- Name: analysis_schedule fk_analysis_schedule_project_id_projects; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analysis_schedule
    ADD CONSTRAINT fk_analysis_schedule_project_id_projects FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: analysis_schedule fk_analysis_schedule_sbom_id_sbom_source; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analysis_schedule
    ADD CONSTRAINT fk_analysis_schedule_sbom_id_sbom_source FOREIGN KEY (sbom_id) REFERENCES public.sbom_source(id) ON DELETE CASCADE;


--
-- Name: analysis_schedule fk_analysis_schedule_tenant_id_tenants; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analysis_schedule
    ADD CONSTRAINT fk_analysis_schedule_tenant_id_tenants FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: audit_log fk_audit_log_tenant_id_tenants; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT fk_audit_log_tenant_id_tenants FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: audit_log fk_audit_log_user_ref_id_iam_users; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT fk_audit_log_user_ref_id_iam_users FOREIGN KEY (user_ref_id) REFERENCES public.iam_users(id) ON DELETE SET NULL;


--
-- Name: authorization_audit_log fk_authorization_audit_log_actor_user_id_iam_users; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_audit_log
    ADD CONSTRAINT fk_authorization_audit_log_actor_user_id_iam_users FOREIGN KEY (actor_user_id) REFERENCES public.iam_users(id) ON DELETE SET NULL;


--
-- Name: authorization_audit_log fk_authorization_audit_log_target_membership_id_tenant_users; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_audit_log
    ADD CONSTRAINT fk_authorization_audit_log_target_membership_id_tenant_users FOREIGN KEY (target_membership_id) REFERENCES public.tenant_users(id) ON DELETE SET NULL;


--
-- Name: authorization_audit_log fk_authorization_audit_log_target_user_id_iam_users; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_audit_log
    ADD CONSTRAINT fk_authorization_audit_log_target_user_id_iam_users FOREIGN KEY (target_user_id) REFERENCES public.iam_users(id) ON DELETE SET NULL;


--
-- Name: authorization_audit_log fk_authorization_audit_log_tenant_id_tenants; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_audit_log
    ADD CONSTRAINT fk_authorization_audit_log_tenant_id_tenants FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE SET NULL;


--
-- Name: compare_cache fk_compare_cache_tenant_id_tenants; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compare_cache
    ADD CONSTRAINT fk_compare_cache_tenant_id_tenants FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: component_lifecycle_override_audit fk_component_lifecycle_override_audit_component_id_sbom_794b; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_lifecycle_override_audit
    ADD CONSTRAINT fk_component_lifecycle_override_audit_component_id_sbom_794b FOREIGN KEY (component_id) REFERENCES public.sbom_component(id) ON DELETE CASCADE;


--
-- Name: component_lifecycle_override_audit fk_component_lifecycle_override_audit_tenant_id_tenants; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_lifecycle_override_audit
    ADD CONSTRAINT fk_component_lifecycle_override_audit_tenant_id_tenants FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: email_verification_tokens fk_email_verification_tokens_user_id_iam_users; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_verification_tokens
    ADD CONSTRAINT fk_email_verification_tokens_user_id_iam_users FOREIGN KEY (user_id) REFERENCES public.iam_users(id) ON DELETE CASCADE;


--
-- Name: lifecycle_provider_configs fk_lifecycle_provider_configs_updated_by_user_id_iam_users; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lifecycle_provider_configs
    ADD CONSTRAINT fk_lifecycle_provider_configs_updated_by_user_id_iam_users FOREIGN KEY (updated_by_user_id) REFERENCES public.iam_users(id) ON DELETE SET NULL;


--
-- Name: lifecycle_provider_secrets fk_lifecycle_provider_secrets_updated_by_user_id_iam_users; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lifecycle_provider_secrets
    ADD CONSTRAINT fk_lifecycle_provider_secrets_updated_by_user_id_iam_users FOREIGN KEY (updated_by_user_id) REFERENCES public.iam_users(id) ON DELETE SET NULL;


--
-- Name: lifecycle_vendor_records fk_lifecycle_vendor_records_updated_by_user_id_iam_users; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lifecycle_vendor_records
    ADD CONSTRAINT fk_lifecycle_vendor_records_updated_by_user_id_iam_users FOREIGN KEY (updated_by_user_id) REFERENCES public.iam_users(id) ON DELETE SET NULL;


--
-- Name: platform_user_roles fk_platform_user_roles_created_by_user_id_iam_users; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_user_roles
    ADD CONSTRAINT fk_platform_user_roles_created_by_user_id_iam_users FOREIGN KEY (created_by_user_id) REFERENCES public.iam_users(id) ON DELETE SET NULL;


--
-- Name: platform_user_roles fk_platform_user_roles_user_id_iam_users; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_user_roles
    ADD CONSTRAINT fk_platform_user_roles_user_id_iam_users FOREIGN KEY (user_id) REFERENCES public.iam_users(id) ON DELETE CASCADE;


--
-- Name: products fk_products_project_id_projects; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.products
    ADD CONSTRAINT fk_products_project_id_projects FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: products fk_products_tenant_id_tenants; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.products
    ADD CONSTRAINT fk_products_tenant_id_tenants FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: projects fk_projects_tenant_id_tenants; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.projects
    ADD CONSTRAINT fk_projects_tenant_id_tenants FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: run_cache fk_run_cache_tenant_id_tenants; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.run_cache
    ADD CONSTRAINT fk_run_cache_tenant_id_tenants FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: sbom_analysis_report fk_sbom_analysis_report_sbom_ref_id_sbom_source; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sbom_analysis_report
    ADD CONSTRAINT fk_sbom_analysis_report_sbom_ref_id_sbom_source FOREIGN KEY (sbom_ref_id) REFERENCES public.sbom_source(id);


--
-- Name: sbom_analysis_report fk_sbom_analysis_report_tenant_id_tenants; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sbom_analysis_report
    ADD CONSTRAINT fk_sbom_analysis_report_tenant_id_tenants FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: sbom_component fk_sbom_component_duplicate_of_component_id_sbom_component; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sbom_component
    ADD CONSTRAINT fk_sbom_component_duplicate_of_component_id_sbom_component FOREIGN KEY (duplicate_of_component_id) REFERENCES public.sbom_component(id) ON DELETE CASCADE;


--
-- Name: sbom_component fk_sbom_component_sbom_id_sbom_source; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sbom_component
    ADD CONSTRAINT fk_sbom_component_sbom_id_sbom_source FOREIGN KEY (sbom_id) REFERENCES public.sbom_source(id);


--
-- Name: sbom_component fk_sbom_component_tenant_id_tenants; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sbom_component
    ADD CONSTRAINT fk_sbom_component_tenant_id_tenants FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: sbom_source fk_sbom_source_converted_sbom_id_sbom_source; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sbom_source
    ADD CONSTRAINT fk_sbom_source_converted_sbom_id_sbom_source FOREIGN KEY (converted_sbom_id) REFERENCES public.sbom_source(id);


--
-- Name: sbom_source fk_sbom_source_parent_id_sbom_source; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sbom_source
    ADD CONSTRAINT fk_sbom_source_parent_id_sbom_source FOREIGN KEY (parent_id) REFERENCES public.sbom_source(id);


--
-- Name: sbom_source fk_sbom_source_product_id_products; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sbom_source
    ADD CONSTRAINT fk_sbom_source_product_id_products FOREIGN KEY (product_id) REFERENCES public.products(id);


--
-- Name: sbom_source fk_sbom_source_projectid_projects; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sbom_source
    ADD CONSTRAINT fk_sbom_source_projectid_projects FOREIGN KEY (projectid) REFERENCES public.projects(id);


--
-- Name: sbom_source fk_sbom_source_sbom_type_sbom_type; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sbom_source
    ADD CONSTRAINT fk_sbom_source_sbom_type_sbom_type FOREIGN KEY (sbom_type) REFERENCES public.sbom_type(id);


--
-- Name: sbom_source fk_sbom_source_source_sbom_id_sbom_source; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sbom_source
    ADD CONSTRAINT fk_sbom_source_source_sbom_id_sbom_source FOREIGN KEY (source_sbom_id) REFERENCES public.sbom_source(id);


--
-- Name: sbom_source fk_sbom_source_tenant_id_tenants; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sbom_source
    ADD CONSTRAINT fk_sbom_source_tenant_id_tenants FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: sbom_validation_session_events fk_sbom_validation_session_events_session_id_sbom_valid_ca0d; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sbom_validation_session_events
    ADD CONSTRAINT fk_sbom_validation_session_events_session_id_sbom_valid_ca0d FOREIGN KEY (session_id) REFERENCES public.sbom_validation_sessions(id) ON DELETE CASCADE;


--
-- Name: sbom_validation_session_events fk_sbom_validation_session_events_tenant_id_tenants; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sbom_validation_session_events
    ADD CONSTRAINT fk_sbom_validation_session_events_tenant_id_tenants FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: sbom_validation_sessions fk_sbom_validation_sessions_imported_sbom_id_sbom_source; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sbom_validation_sessions
    ADD CONSTRAINT fk_sbom_validation_sessions_imported_sbom_id_sbom_source FOREIGN KEY (imported_sbom_id) REFERENCES public.sbom_source(id);


--
-- Name: sbom_validation_sessions fk_sbom_validation_sessions_project_id_projects; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sbom_validation_sessions
    ADD CONSTRAINT fk_sbom_validation_sessions_project_id_projects FOREIGN KEY (project_id) REFERENCES public.projects(id);


--
-- Name: sbom_validation_sessions fk_sbom_validation_sessions_sbom_type_sbom_type; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sbom_validation_sessions
    ADD CONSTRAINT fk_sbom_validation_sessions_sbom_type_sbom_type FOREIGN KEY (sbom_type) REFERENCES public.sbom_type(id);


--
-- Name: sbom_validation_sessions fk_sbom_validation_sessions_tenant_id_tenants; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sbom_validation_sessions
    ADD CONSTRAINT fk_sbom_validation_sessions_tenant_id_tenants FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: tenant_users fk_tenant_users_tenant_id_tenants; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_users
    ADD CONSTRAINT fk_tenant_users_tenant_id_tenants FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: tenant_users fk_tenant_users_user_id_iam_users; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_users
    ADD CONSTRAINT fk_tenant_users_user_id_iam_users FOREIGN KEY (user_id) REFERENCES public.iam_users(id) ON DELETE CASCADE;


--
-- Name: vex_documents fk_vex_documents_sbom_id_sbom_source; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vex_documents
    ADD CONSTRAINT fk_vex_documents_sbom_id_sbom_source FOREIGN KEY (sbom_id) REFERENCES public.sbom_source(id) ON DELETE CASCADE;


--
-- Name: vex_documents fk_vex_documents_tenant_id_tenants; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vex_documents
    ADD CONSTRAINT fk_vex_documents_tenant_id_tenants FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: vex_override_audit fk_vex_override_audit_component_id_sbom_component; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vex_override_audit
    ADD CONSTRAINT fk_vex_override_audit_component_id_sbom_component FOREIGN KEY (component_id) REFERENCES public.sbom_component(id) ON DELETE CASCADE;


--
-- Name: vex_override_audit fk_vex_override_audit_tenant_id_tenants; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vex_override_audit
    ADD CONSTRAINT fk_vex_override_audit_tenant_id_tenants FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: vex_statements fk_vex_statements_component_id_sbom_component; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vex_statements
    ADD CONSTRAINT fk_vex_statements_component_id_sbom_component FOREIGN KEY (component_id) REFERENCES public.sbom_component(id) ON DELETE SET NULL;


--
-- Name: vex_statements fk_vex_statements_sbom_id_sbom_source; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vex_statements
    ADD CONSTRAINT fk_vex_statements_sbom_id_sbom_source FOREIGN KEY (sbom_id) REFERENCES public.sbom_source(id) ON DELETE CASCADE;


--
-- Name: vex_statements fk_vex_statements_tenant_id_tenants; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vex_statements
    ADD CONSTRAINT fk_vex_statements_tenant_id_tenants FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: vex_statements fk_vex_statements_vex_document_id_vex_documents; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vex_statements
    ADD CONSTRAINT fk_vex_statements_vex_document_id_vex_documents FOREIGN KEY (vex_document_id) REFERENCES public.vex_documents(id) ON DELETE CASCADE;


--
-- Name: vulnerability_remediation_audit fk_vulnerability_remediation_audit_project_id_projects; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vulnerability_remediation_audit
    ADD CONSTRAINT fk_vulnerability_remediation_audit_project_id_projects FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: vulnerability_remediation_audit fk_vulnerability_remediation_audit_remediation_id_vulne_f9a9; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vulnerability_remediation_audit
    ADD CONSTRAINT fk_vulnerability_remediation_audit_remediation_id_vulne_f9a9 FOREIGN KEY (remediation_id) REFERENCES public.vulnerability_remediation(id) ON DELETE CASCADE;


--
-- Name: vulnerability_remediation_audit fk_vulnerability_remediation_audit_tenant_id_tenants; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vulnerability_remediation_audit
    ADD CONSTRAINT fk_vulnerability_remediation_audit_tenant_id_tenants FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: vulnerability_remediation fk_vulnerability_remediation_project_id_projects; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vulnerability_remediation
    ADD CONSTRAINT fk_vulnerability_remediation_project_id_projects FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: vulnerability_remediation fk_vulnerability_remediation_tenant_id_tenants; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vulnerability_remediation
    ADD CONSTRAINT fk_vulnerability_remediation_tenant_id_tenants FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- PostgreSQL database dump complete
--

