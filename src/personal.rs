//! Personal (single-operator) run-mode — the "just a gateway for my own email" configuration.
//!
//! This module is the thin bring-up that lets **one** person run the gateway as a bridge for **their
//! own** domain and account(s), without the mesh, cloud, or billing control-plane. It does not add
//! any new bridging logic: it only *composes the existing pieces* ([`InboundGateway`] with real
//! DKIM/SPF/DMARC, the file-backed recipient [`directory`](crate::directory), the HTTP
//! [`mesh`](crate::mesh) adapter, the [`OutboundGateway`] transport, and the [`IdentityRegistry`] +
//! [`QuotaLedger`] admission/quota seams) from a single flat config file or the equivalent `GATEWAY_*`
//! environment variables.
//!
//! Everything is **fail-closed**: an unparseable config, an unknown key, a malformed listen/DNS
//! address, or a bad directory file is a hard startup error — the daemon never comes up half-wired.
//!
//! The daemon serves the inbound MX leg on a real socket ([`MxListener`]); the outbound leg is driven
//! by the operator's own node over the mesh (a MOTE addressed to a legacy recipient), so the
//! [`OutboundGateway`], admission [`IdentityRegistry`], and [`QuotaLedger`] are built, wired, and
//! reported at startup, ready for that node-driven ingress — exactly as the reference `run` daemon
//! already does.

use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use dmtap_core::identity::IdentityKey;
use dmtap_mail::auth::StaticAuthenticator;
use dmtap_mail::store::{Flag, MemoryStore};
use rustls::ServerConfig;

use crate::attestation::AttestationKey;
use crate::authz::{
    AuthzMode, GatewayMode, IdentityRegistry, Quota, QuotaLedger, RegisteredIdentity,
};
use crate::directory::FileDirectory;
use crate::dkim::DnsDkimKeyResolver;
use crate::dmarc::DnsDmarcResolver;
use crate::imap_access::{load_maildir_messages, ImapAccessServer, ImapTls};
use crate::inbound::{
    AllowAllAbuse, DkimPolicy, DmarcHandling, InboundGateway, KeyDirectory, MeshDelivery, SpfPolicy,
};
use crate::legacy_net::LegacyTls;
use crate::mesh::{HttpMeshDelivery, NullMesh};
use crate::mta_sts::{DnsTxtResolver, HttpsPolicyFetcher, MtaStsTlsPolicy};
use crate::mx::DnsMxResolver;
use crate::outbound::OutboundGateway;
use crate::pop3_access::Pop3AccessServer;
use crate::smtp_submission::{SpoolSink, SubmissionServer};
use crate::spf::DnsSpfResolver;
use crate::{server_config_from_pem, InMemoryDirectory, MxListener, SmtpTcpTransport};

/// The personal-gateway configuration. Sensible, safe defaults throughout: a fresh config bridges
/// nobody (empty directory → every `RCPT` → `550`) rather than becoming an open relay, and the three
/// legacy-auth checks default to non-rejecting *annotate* so a new deployment never bounces
/// legitimate mail on a check the operator has not deliberately turned on.
#[derive(Debug, Clone)]
pub struct PersonalConfig {
    /// The domain this gateway is the MX for and signs attestations/DKIM as (your own domain).
    pub domain: String,
    /// The MX listen address. `0.0.0.0:25` in production (needs a public IP + inbound port 25),
    /// `127.0.0.1:2525` for local testing.
    pub listen: String,
    /// The gateway attestation / DKIM selector published under your domain (default `gw1`).
    pub selector: String,
    /// The recursive DNS server used for outbound MX/MTA-STS and inbound DKIM/SPF/DMARC TXT lookups.
    pub dns_server: SocketAddr,
    /// Path to the recipient directory file (`<email> <ik-b64> <seal-b64>` per line) — your own
    /// identities. Unset ⇒ empty directory (resolves nobody).
    pub directory: Option<String>,
    /// The node ingest URL (`http://host:port/path`) the converted MOTE is POSTed to. Unset ⇒
    /// [`NullMesh`] (inbound → `451`, sender retries): honest, never a silent drop.
    pub mesh_endpoint: Option<String>,
    /// PEM certificate chain path to enable STARTTLS (needs [`tls_key`](Self::tls_key) too).
    pub tls_cert: Option<String>,
    /// PEM private key path to enable STARTTLS.
    pub tls_key: Option<String>,
    /// Outbound-relay admission mode. The default [`AuthzMode::KeyRegistered`] admits only your own
    /// directory identities; [`AuthzMode::OpenPublic`] is a documented spam magnet — never on the
    /// public internet.
    pub authz_mode: AuthzMode,
    /// Reject inbound mail with a present-but-invalid DKIM signature (default: annotate only).
    pub dkim_enforce: bool,
    /// Reject inbound mail on an SPF hard fail (default: annotate only).
    pub spf_enforce: bool,
    /// Reject inbound mail on an unaligned DMARC `p=reject`/`sp=reject` policy (default: annotate).
    pub dmarc_enforce: bool,
    /// Optional per-identity hard cap on relayed messages (`0`/unset ⇒ unlimited).
    pub quota_messages: u64,
    /// Optional per-identity hard cap on relayed bytes (`0`/unset ⇒ unlimited).
    pub quota_bytes: u64,
    /// Enable the OPTIONAL legacy IMAP access server (spec §8.2) so old clients (Thunderbird, Apple
    /// Mail, Outlook) can read/manage the mailbox. **Off by default.** Requires
    /// [`tls_cert`](Self::tls_cert)/[`tls_key`](Self::tls_key): IMAP app-passwords must never travel
    /// in cleartext. See [`crate::imap_access`] for the honest store-source scoping.
    pub imap_enable: bool,
    /// IMAP access bind address (default `127.0.0.1:1143`). Production: `0.0.0.0:993` with
    /// `imap_tls = implicit`, or `0.0.0.0:143` with `imap_tls = starttls`.
    pub imap_listen: String,
    /// How the IMAP access server presents TLS (reuses the gateway cert/key): `starttls` (default)
    /// or `implicit`.
    pub imap_tls: ImapTls,
    /// App-password credentials file, one per line:
    /// `<username> <app-password> [<identity-pub-b64>]`. When the identity key is omitted it is
    /// resolved from the recipient [`directory`](Self::directory) by matching the username to an
    /// email. Unset ⇒ no credentials ⇒ every login is refused (fail-closed).
    pub imap_credentials: Option<String>,
    /// Optional directory of RFC 5322 `.eml` files projected into the served `INBOX` — the operator's
    /// own mailbox snapshot handed to the gateway. Unset ⇒ the standard empty folder layout. Shared by
    /// the IMAP and POP3 surfaces (they project the same maildrop).
    pub imap_maildir: Option<String>,
    /// The legacy-client service mode (§7.15.4): which accounts the legacy surfaces (IMAP/POP3/
    /// submission) will serve. Default [`GatewayMode::Private`] (single operator; most restrictive).
    pub gateway_mode: GatewayMode,
    /// Enable the OPTIONAL legacy POP3 access server (spec §7.15.1, RFC 1939) so old clients can
    /// download the INBOX maildrop. **Off by default.** Requires [`tls_cert`](Self::tls_cert)/
    /// [`tls_key`](Self::tls_key). Reuses [`imap_credentials`](Self::imap_credentials) (app-passwords)
    /// and [`imap_maildir`](Self::imap_maildir) (the maildrop).
    pub pop3_enable: bool,
    /// POP3 access bind address (default `127.0.0.1:1110`). Production: `0.0.0.0:995` with
    /// `pop3_tls = implicit`, or `0.0.0.0:110` with `pop3_tls = starttls` (STLS).
    pub pop3_listen: String,
    /// How the POP3 access server presents TLS: `starttls` (default, STLS) or `implicit`.
    pub pop3_tls: LegacyTls,
    /// Enable the OPTIONAL legacy SMTP-submission access server (spec §7.15.1, RFC 6409) so old
    /// clients can send outbound. **Off by default.** Requires [`tls_cert`](Self::tls_cert)/
    /// [`tls_key`](Self::tls_key): the app-password must never travel in cleartext, and AUTH is
    /// refused on a cleartext channel. Reuses [`imap_credentials`](Self::imap_credentials).
    pub submission_enable: bool,
    /// Submission access bind address (default `127.0.0.1:1587`). Production: `0.0.0.0:465` with
    /// `submission_tls = implicit`, or `0.0.0.0:587` with `submission_tls = starttls` (STARTTLS).
    pub submission_listen: String,
    /// How the submission access server presents TLS: `starttls` (default) or `implicit`.
    pub submission_tls: LegacyTls,
    /// Directory the accepted submissions are handed off into for the operator's node to pick up
    /// (§7.4: the gateway keeps no queue). Unset ⇒ accepted messages are logged and dropped after the
    /// `250` (honest: no durable hand-off), so set this to actually deliver.
    pub submission_spool: Option<String>,
    /// Recipient domains treated as **native** DMTAP destinations (→ MOTE / mesh) rather than legacy
    /// (→ §7.3 bridge). Whitespace/comma-separated. Unset ⇒ defaults to [`domain`](Self::domain).
    pub submission_native_domains: Option<String>,
}

impl Default for PersonalConfig {
    fn default() -> Self {
        PersonalConfig {
            domain: "localhost".to_string(),
            listen: "0.0.0.0:2525".to_string(),
            selector: "gw1".to_string(),
            dns_server: default_dns_server(),
            directory: None,
            mesh_endpoint: None,
            tls_cert: None,
            tls_key: None,
            authz_mode: AuthzMode::KeyRegistered,
            dkim_enforce: false,
            spf_enforce: false,
            dmarc_enforce: false,
            quota_messages: 0,
            quota_bytes: 0,
            imap_enable: false,
            imap_listen: "127.0.0.1:1143".to_string(),
            imap_tls: ImapTls::StartTls,
            imap_credentials: None,
            imap_maildir: None,
            gateway_mode: GatewayMode::Private,
            pop3_enable: false,
            pop3_listen: "127.0.0.1:1110".to_string(),
            pop3_tls: LegacyTls::StartTls,
            submission_enable: false,
            submission_listen: "127.0.0.1:1587".to_string(),
            submission_tls: LegacyTls::StartTls,
            submission_spool: None,
            submission_native_domains: None,
        }
    }
}

/// The fixed fallback resolver (`1.1.1.1:53`).
fn default_dns_server() -> SocketAddr {
    "1.1.1.1:53".parse().expect("valid fallback DNS server addr")
}

/// Why a personal config could not be loaded — every variant fails the whole load closed (a
/// half-parsed config could silently bring up a mis-scoped gateway).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    /// The config file could not be read.
    #[error("config file {path}: {reason}")]
    Io { path: String, reason: String },
    /// A line is not `key = value` (and is not blank/comment).
    #[error("config line {line}: expected `key = value`, got {raw:?}")]
    Syntax { line: usize, raw: String },
    /// A recognized key was given a value that does not parse (bad address, non-integer, bad bool).
    #[error("config line {line}: key {key:?} has an invalid value {value:?} ({reason})")]
    BadValue { line: usize, key: String, value: String, reason: &'static str },
    /// A key that the personal config does not recognize (fail-closed: a typo'd security knob such as
    /// `authz_moad` must not be silently ignored).
    #[error("config line {line}: unknown key {key:?}")]
    UnknownKey { line: usize, key: String },
    /// STARTTLS was half-configured (only one of cert/key given). TLS is all-or-nothing.
    #[error("tls_cert and tls_key must be set together (STARTTLS is all-or-nothing)")]
    PartialTls,
}

impl PersonalConfig {
    /// Load and parse a personal config file.
    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|e| ConfigError::Io {
            path: path.display().to_string(),
            reason: e.to_string(),
        })?;
        Self::parse(&text)
    }

    /// Parse a personal config from the flat `key = value` text format (comments with `#`, optional
    /// double-quotes around string values). Unknown keys and malformed values are hard errors.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let mut cfg = PersonalConfig::default();
        // Track whether dns_server was explicitly set so a parse failure is a hard error (not a
        // silent fallback) in the file path — the env path keeps the lenient fallback for back-compat.
        for (idx, raw) in text.lines().enumerate() {
            let line = idx + 1;
            let stripped = strip_comment(raw);
            let trimmed = stripped.trim();
            if trimmed.is_empty() {
                continue;
            }
            let (key, value) = trimmed
                .split_once('=')
                .ok_or_else(|| ConfigError::Syntax { line, raw: raw.trim().to_string() })?;
            let key = key.trim().to_ascii_lowercase();
            let value = unquote(value.trim());
            cfg.set(line, &key, value)?;
        }
        Ok(cfg)
    }

    /// Apply one recognized `key`/`value` to the config, fail-closed on an unknown key or bad value.
    fn set(&mut self, line: usize, key: &str, value: String) -> Result<(), ConfigError> {
        let bad = |reason: &'static str| ConfigError::BadValue {
            line,
            key: key.to_string(),
            value: value.clone(),
            reason,
        };
        match key {
            "domain" => self.domain = value,
            "listen" => self.listen = value,
            "selector" => self.selector = value,
            "dns_server" => {
                self.dns_server = value.parse().map_err(|_| bad("not an ip:port socket address"))?
            }
            "directory" => self.directory = non_empty(value),
            "mesh_endpoint" => self.mesh_endpoint = non_empty(value),
            "tls_cert" => self.tls_cert = non_empty(value),
            "tls_key" => self.tls_key = non_empty(value),
            "authz_mode" => {
                self.authz_mode = parse_authz_mode(&value)
                    .ok_or_else(|| bad("expected \"key-registered\" or \"open-public\""))?
            }
            "dkim_enforce" => {
                self.dkim_enforce = parse_bool(&value).ok_or_else(|| bad("expected true/false"))?
            }
            "spf_enforce" => {
                self.spf_enforce = parse_bool(&value).ok_or_else(|| bad("expected true/false"))?
            }
            "dmarc_enforce" => {
                self.dmarc_enforce = parse_bool(&value).ok_or_else(|| bad("expected true/false"))?
            }
            "quota_messages" => {
                self.quota_messages =
                    value.parse().map_err(|_| bad("expected a non-negative integer"))?
            }
            "quota_bytes" => {
                self.quota_bytes =
                    value.parse().map_err(|_| bad("expected a non-negative integer"))?
            }
            "imap_enable" => {
                self.imap_enable = parse_bool(&value).ok_or_else(|| bad("expected true/false"))?
            }
            "imap_listen" => self.imap_listen = value,
            "imap_tls" => {
                self.imap_tls = ImapTls::parse(&value)
                    .ok_or_else(|| bad("expected \"starttls\" or \"implicit\""))?
            }
            "imap_credentials" => self.imap_credentials = non_empty(value),
            "imap_maildir" => self.imap_maildir = non_empty(value),
            "gateway_mode" => {
                self.gateway_mode = GatewayMode::parse(&value).ok_or_else(|| {
                    bad("expected \"private\", \"registered-clients-only\", or \"public\"")
                })?
            }
            "pop3_enable" => {
                self.pop3_enable = parse_bool(&value).ok_or_else(|| bad("expected true/false"))?
            }
            "pop3_listen" => self.pop3_listen = value,
            "pop3_tls" => {
                self.pop3_tls = LegacyTls::parse(&value)
                    .ok_or_else(|| bad("expected \"starttls\" or \"implicit\""))?
            }
            "submission_enable" => {
                self.submission_enable =
                    parse_bool(&value).ok_or_else(|| bad("expected true/false"))?
            }
            "submission_listen" => self.submission_listen = value,
            "submission_tls" => {
                self.submission_tls = LegacyTls::parse(&value)
                    .ok_or_else(|| bad("expected \"starttls\" or \"implicit\""))?
            }
            "submission_spool" => self.submission_spool = non_empty(value),
            "submission_native_domains" => self.submission_native_domains = non_empty(value),
            other => return Err(ConfigError::UnknownKey { line, key: other.to_string() }),
        }
        Ok(())
    }

    /// Build a config from the `GATEWAY_*` environment variables (the env equivalent of the file
    /// format; the reference `run` daemon uses this). Lenient about a malformed `GATEWAY_DNS_SERVER`
    /// (falls back to `1.1.1.1:53`) for back-compat with the pre-config-file daemon.
    pub fn from_env() -> Self {
        let mut cfg = PersonalConfig::default();
        if let Ok(v) = std::env::var("GATEWAY_DOMAIN") {
            cfg.domain = v;
        }
        if let Ok(v) = std::env::var("GATEWAY_LISTEN") {
            cfg.listen = v;
        }
        if let Ok(v) = std::env::var("GATEWAY_GW_SELECTOR") {
            cfg.selector = v;
        }
        if let Ok(v) = std::env::var("GATEWAY_DNS_SERVER") {
            cfg.dns_server = v.parse().unwrap_or_else(|_| default_dns_server());
        }
        cfg.directory = std::env::var("GATEWAY_DIRECTORY").ok().and_then(non_empty);
        cfg.mesh_endpoint = std::env::var("GATEWAY_MESH_ENDPOINT").ok().and_then(non_empty);
        cfg.tls_cert = std::env::var("GATEWAY_TLS_CERT").ok().and_then(non_empty);
        cfg.tls_key = std::env::var("GATEWAY_TLS_KEY").ok().and_then(non_empty);
        if let Some(m) = std::env::var("GATEWAY_AUTHZ_MODE").ok().and_then(|v| parse_authz_mode(&v))
        {
            cfg.authz_mode = m;
        }
        cfg.dkim_enforce = env_flag("GATEWAY_DKIM_ENFORCE");
        cfg.spf_enforce = env_flag("GATEWAY_SPF_ENFORCE");
        cfg.dmarc_enforce = env_flag("GATEWAY_DMARC_ENFORCE");
        if let Ok(v) = std::env::var("GATEWAY_QUOTA_MESSAGES") {
            cfg.quota_messages = v.parse().unwrap_or(0);
        }
        if let Ok(v) = std::env::var("GATEWAY_QUOTA_BYTES") {
            cfg.quota_bytes = v.parse().unwrap_or(0);
        }
        cfg.imap_enable = env_flag("GATEWAY_IMAP_ENABLE");
        if let Ok(v) = std::env::var("GATEWAY_IMAP_LISTEN") {
            cfg.imap_listen = v;
        }
        if let Some(m) = std::env::var("GATEWAY_IMAP_TLS").ok().and_then(|v| ImapTls::parse(&v)) {
            cfg.imap_tls = m;
        }
        cfg.imap_credentials = std::env::var("GATEWAY_IMAP_CREDENTIALS").ok().and_then(non_empty);
        cfg.imap_maildir = std::env::var("GATEWAY_IMAP_MAILDIR").ok().and_then(non_empty);
        if let Some(m) = std::env::var("GATEWAY_MODE").ok().and_then(|v| GatewayMode::parse(&v)) {
            cfg.gateway_mode = m;
        }
        cfg.pop3_enable = env_flag("GATEWAY_POP3_ENABLE");
        if let Ok(v) = std::env::var("GATEWAY_POP3_LISTEN") {
            cfg.pop3_listen = v;
        }
        if let Some(m) = std::env::var("GATEWAY_POP3_TLS").ok().and_then(|v| LegacyTls::parse(&v)) {
            cfg.pop3_tls = m;
        }
        cfg.submission_enable = env_flag("GATEWAY_SUBMISSION_ENABLE");
        if let Ok(v) = std::env::var("GATEWAY_SUBMISSION_LISTEN") {
            cfg.submission_listen = v;
        }
        if let Some(m) =
            std::env::var("GATEWAY_SUBMISSION_TLS").ok().and_then(|v| LegacyTls::parse(&v))
        {
            cfg.submission_tls = m;
        }
        cfg.submission_spool = std::env::var("GATEWAY_SUBMISSION_SPOOL").ok().and_then(non_empty);
        cfg.submission_native_domains =
            std::env::var("GATEWAY_SUBMISSION_NATIVE_DOMAINS").ok().and_then(non_empty);
        cfg
    }

    /// The per-identity [`Quota`] the config describes, or `None` when both caps are `0` (unlimited).
    pub fn quota(&self) -> Option<Quota> {
        if self.quota_messages == 0 && self.quota_bytes == 0 {
            None
        } else {
            // free == hard cap: a personal gateway enforces a ceiling, it does not price overage.
            Some(Quota::new(
                self.quota_messages,
                self.quota_messages,
                self.quota_bytes,
                self.quota_bytes,
            ))
        }
    }

    /// Load the concrete recipient directory (or the empty default). Kept concrete (not boxed) so the
    /// admission registry can be seeded from the same entries.
    fn load_directory(&self) -> std::io::Result<DirectorySource> {
        match &self.directory {
            Some(path) => {
                let dir = FileDirectory::load(path).map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{e}"))
                })?;
                Ok(DirectorySource::File(dir))
            }
            None => Ok(DirectorySource::Empty(InMemoryDirectory::new())),
        }
    }

    /// The §4 mesh-delivery adapter the converted MOTE is handed to (real HTTP or honest [`NullMesh`]).
    fn build_mesh(&self) -> std::io::Result<Box<dyn MeshDelivery>> {
        match &self.mesh_endpoint {
            Some(endpoint) => {
                let mesh = HttpMeshDelivery::new(endpoint).map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("{e}"))
                })?;
                Ok(Box::new(mesh))
            }
            None => Ok(Box::new(NullMesh)),
        }
    }

    /// Build the STARTTLS [`ServerConfig`] from the cert/key PEM pair, or `None` for plaintext.
    /// Fail-closed on a half-configured pair.
    fn build_tls(&self) -> std::io::Result<Option<Arc<ServerConfig>>> {
        match (&self.tls_cert, &self.tls_key) {
            (Some(cert_path), Some(key_path)) => {
                let cert_pem = std::fs::read(cert_path)?;
                let key_pem = std::fs::read(key_path)?;
                Ok(Some(server_config_from_pem(&cert_pem, &key_pem)?))
            }
            (None, None) => Ok(None),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{}", ConfigError::PartialTls),
            )),
        }
    }

    /// Build the inbound gateway (§7.2): gateway identity + domain-anchored attestation key + the
    /// operator seams + real DNS-backed DKIM/SPF/DMARC at the configured policy.
    fn build_inbound(
        &self,
        directory: Box<dyn KeyDirectory>,
        mesh: Box<dyn MeshDelivery>,
    ) -> InboundGateway {
        let dkim_policy =
            if self.dkim_enforce { DkimPolicy::Enforce } else { DkimPolicy::Annotate };
        let spf_policy = if self.spf_enforce { SpfPolicy::Enforce } else { SpfPolicy::Annotate };
        let dmarc_policy =
            if self.dmarc_enforce { DmarcHandling::Enforce } else { DmarcHandling::Annotate };
        InboundGateway::new(
            IdentityKey::generate(),
            vec![AttestationKey::generate(&self.domain, &self.selector)],
            directory,
            mesh,
            Box::new(AllowAllAbuse),
        )
        .with_dkim(Box::new(DnsDkimKeyResolver::new(self.dns_server)), dkim_policy)
        .with_spf(Box::new(DnsSpfResolver::new(self.dns_server)), spf_policy)
        .with_dmarc(Box::new(DnsDmarcResolver::new(self.dns_server)), dmarc_policy)
    }

    /// Build the outbound gateway (§7.3): SMTP-STARTTLS transport + real MX resolution + MTA-STS.
    fn build_outbound(&self) -> OutboundGateway {
        let transport = SmtpTcpTransport::new(self.domain.clone());
        let tls_policy = MtaStsTlsPolicy::new(
            Box::new(DnsTxtResolver::new(self.dns_server)),
            Box::new(HttpsPolicyFetcher::new()),
        );
        OutboundGateway::new(Vec::new(), Box::new(tls_policy), Box::new(transport))
            .with_mx_resolver(Box::new(DnsMxResolver::new(self.dns_server)))
    }

    /// Build the outbound-relay admission registry (§7.9). In the default key-registered mode it is
    /// seeded with the operator's OWN directory identities (email → account, config domain, quota),
    /// so the operator's node authenticates to its own gateway with the same key the directory maps.
    /// Open-public mode registers nobody (any key-controller is admitted — spam risk).
    pub fn build_registry(&self, dir: &DirectorySource) -> IdentityRegistry {
        match self.authz_mode {
            AuthzMode::OpenPublic => IdentityRegistry::open_public(),
            AuthzMode::KeyRegistered => {
                let quota = self.quota().unwrap_or_else(|| Quota::messages(0, 0));
                let mut reg = IdentityRegistry::key_registered();
                for (email, key) in dir.iter() {
                    reg = reg.register(RegisteredIdentity {
                        public_key: key.ik.clone(),
                        account: email.to_string(),
                        domain: self.domain.clone(),
                        quota,
                    });
                }
                reg
            }
        }
    }

    /// The per-account quota ledger seeded from the directory identities (empty if no quota is set).
    pub fn build_quota_ledger(&self, dir: &DirectorySource) -> QuotaLedger {
        let mut ledger = QuotaLedger::new();
        if let Some(quota) = self.quota() {
            for (email, _key) in dir.iter() {
                ledger.upsert_quota(email.to_string(), quota);
            }
        }
        ledger
    }

    /// Load the shared legacy app-password authenticator from the credentials file (`<username>
    /// <app-password> [<identity-pub-b64>]` per line) — used by all legacy surfaces (IMAP, POP3,
    /// SMTP-submission). When the identity key is omitted it is resolved from the recipient directory
    /// by username→email. Fail-closed: a malformed line, a bad base64 key, or an unknown user with no
    /// explicit key is a hard error; an unset file yields an empty authenticator (every login
    /// refused). Returns the authenticator and the list of credential usernames (accounts served) so
    /// the caller can enforce the operator mode (§7.15.4).
    fn load_legacy_credentials(
        &self,
        dir: &DirectorySource,
    ) -> std::io::Result<(StaticAuthenticator, Vec<String>)> {
        let mut auth = StaticAuthenticator::new();
        let mut accounts = Vec::new();
        let Some(path) = &self.imap_credentials else {
            return Ok((auth, accounts));
        };
        let text = std::fs::read_to_string(path)
            .map_err(|e| std::io::Error::new(e.kind(), format!("imap_credentials {path}: {e}")))?;
        let invalid = |line: usize, msg: &str| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("imap_credentials {path} line {line}: {msg}"),
            )
        };
        for (idx, raw) in text.lines().enumerate() {
            let line = idx + 1;
            let stripped = strip_comment(raw);
            let trimmed = stripped.trim();
            if trimmed.is_empty() {
                continue;
            }
            let mut fields = trimmed.split_whitespace();
            let user = fields.next().expect("non-empty line has a first field");
            let password = fields.next().ok_or_else(|| {
                invalid(line, "expected `<username> <app-password> [<identity-pub-b64>]`")
            })?;
            let identity_pub = match fields.next() {
                Some(b64) => crate::b64::decode(b64)
                    .map_err(|e| invalid(line, &format!("bad identity-pub base64: {e}")))?,
                None => resolve_identity(dir, user).ok_or_else(|| {
                    invalid(
                        line,
                        &format!("user {user:?} not in directory and no identity-pub given"),
                    )
                })?,
            };
            if fields.next().is_some() {
                return Err(invalid(line, "too many fields"));
            }
            auth.issue(user, password, identity_pub, "app-password");
            accounts.push(user.to_string());
        }
        Ok((auth, accounts))
    }

    /// Enforce the legacy-client operator mode (§7.15.4) against the accounts a credentials file would
    /// serve — the fail-closed gate that decides *which* accounts the legacy surfaces admit:
    ///
    /// - [`GatewayMode::Private`]: a single-operator gateway. At most **one** distinct account may be
    ///   served; a credentials file naming two different users is refused (a private gateway is for
    ///   *your own* clients, not several people's).
    /// - [`GatewayMode::RegisteredClientsOnly`]: every served account MUST be one of the operator's
    ///   own directory identities (the established registration relationship, §7.12). An account with
    ///   no matching directory entry is refused.
    /// - [`GatewayMode::Public`]: open registration — any provisioned account is served.
    ///
    /// Case-insensitive account/email comparison throughout. Returns the number of distinct accounts.
    fn enforce_gateway_mode(
        &self,
        dir: &DirectorySource,
        accounts: &[String],
    ) -> std::io::Result<usize> {
        let deny = |msg: String| std::io::Error::new(std::io::ErrorKind::PermissionDenied, msg);
        let mut distinct: Vec<String> = Vec::new();
        for a in accounts {
            let lc = a.to_ascii_lowercase();
            if !distinct.contains(&lc) {
                distinct.push(lc);
            }
        }
        match self.gateway_mode {
            GatewayMode::Private => {
                if distinct.len() > 1 {
                    return Err(deny(format!(
                        "gateway_mode=private serves a single operator, but the credentials name {} \
                         distinct accounts ({:?}). Use registered-clients-only or public to serve \
                         more than one identity (§7.15.4).",
                        distinct.len(),
                        distinct,
                    )));
                }
            }
            GatewayMode::RegisteredClientsOnly => {
                for a in &distinct {
                    let registered = dir.iter().any(|(email, _)| email.eq_ignore_ascii_case(a));
                    if !registered {
                        return Err(deny(format!(
                            "gateway_mode=registered-clients-only serves only registered directory \
                             identities, but credential account {a:?} is not in the recipient \
                             directory (§7.15.4). Add it to `directory` or switch mode."
                        )));
                    }
                }
            }
            GatewayMode::Public => {}
        }
        Ok(distinct.len())
    }

    /// Build the optional IMAP access deployment, or `None` when `imap_enable` is false. Fail-closed:
    /// enabling IMAP without a TLS cert/key, a bad credentials file, or an unreadable maildir is a
    /// hard startup error (never a half-wired or cleartext-auth listener).
    fn build_imap(
        &self,
        dir: &DirectorySource,
        tls: Option<Arc<ServerConfig>>,
    ) -> std::io::Result<Option<ImapDeployment>> {
        if !self.imap_enable {
            return Ok(None);
        }
        let tls = tls.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "imap_enable=true requires tls_cert + tls_key — IMAP app-passwords must not travel in cleartext",
            )
        })?;
        let (auth, accounts) = self.load_legacy_credentials(dir)?;
        let served = self.enforce_gateway_mode(dir, &accounts)?;
        let seed = match &self.imap_maildir {
            Some(d) => load_maildir_messages(d)?,
            None => Vec::new(),
        };
        let server = ImapAccessServer::bind(&self.imap_listen, tls, self.imap_tls)?;
        let bound = server.local_addr()?;
        eprintln!(
            "gateway[imap]: legacy IMAP access on {bound} ({:?}); mode={}; {} account(s); {} seeded message(s)",
            self.imap_tls,
            self.gateway_mode.label(),
            served,
            seed.len()
        );
        if accounts.is_empty() {
            eprintln!(
                "gateway[imap]: WARNING — no imap_credentials configured; every login will be refused \
                 (fail-closed). Set imap_credentials to issue app-passwords."
            );
        }
        Ok(Some(ImapDeployment { server, seed: Arc::new(seed), auth: Arc::new(auth) }))
    }

    /// Build the optional POP3 access deployment, or `None` when `pop3_enable` is false. Same
    /// fail-closed rules as [`Self::build_imap`]: TLS is mandatory (app-passwords must not travel in
    /// cleartext), the operator mode (§7.15.4) is enforced against the served accounts, and the served
    /// maildrop is the operator's own `imap_maildir` snapshot.
    fn build_pop3(
        &self,
        dir: &DirectorySource,
        tls: Option<Arc<ServerConfig>>,
    ) -> std::io::Result<Option<Pop3Deployment>> {
        if !self.pop3_enable {
            return Ok(None);
        }
        let tls = tls.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "pop3_enable=true requires tls_cert + tls_key — POP3 app-passwords must not travel in cleartext",
            )
        })?;
        let (auth, accounts) = self.load_legacy_credentials(dir)?;
        let served = self.enforce_gateway_mode(dir, &accounts)?;
        let seed = match &self.imap_maildir {
            Some(d) => load_maildir_messages(d)?,
            None => Vec::new(),
        };
        let server = Pop3AccessServer::bind(&self.pop3_listen, tls, self.pop3_tls)?;
        let bound = server.local_addr()?;
        eprintln!(
            "gateway[pop3]: legacy POP3 access on {bound} ({:?}); mode={}; {} account(s); {} seeded message(s)",
            self.pop3_tls,
            self.gateway_mode.label(),
            served,
            seed.len()
        );
        if accounts.is_empty() {
            eprintln!(
                "gateway[pop3]: WARNING — no imap_credentials configured; every login will be refused \
                 (fail-closed)."
            );
        }
        Ok(Some(Pop3Deployment { server, seed: Arc::new(seed), auth: Arc::new(auth) }))
    }

    /// The recipient domains a submitted message is treated as **native** for (→ MOTE / mesh); any
    /// other domain is legacy (→ §7.3 bridge). From `submission_native_domains` if set, else the
    /// gateway's own `domain`.
    fn submission_native_domains(&self) -> Vec<String> {
        match &self.submission_native_domains {
            Some(list) => list
                .split([',', ' ', '\t'])
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect(),
            None => vec![self.domain.clone()],
        }
    }

    /// Build the optional SMTP-submission access deployment, or `None` when `submission_enable` is
    /// false. Fail-closed like the read surfaces: TLS is mandatory (the app-password must not travel
    /// in cleartext, and `dmtap-mail`'s session refuses AUTH on a cleartext channel), the operator
    /// mode (§7.15.4) is enforced, and a configured `submission_spool` must be an existing directory.
    fn build_submission(
        &self,
        dir: &DirectorySource,
        tls: Option<Arc<ServerConfig>>,
    ) -> std::io::Result<Option<SubmissionDeployment>> {
        if !self.submission_enable {
            return Ok(None);
        }
        let tls = tls.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "submission_enable=true requires tls_cert + tls_key — the app-password must not travel in cleartext",
            )
        })?;
        let (auth, accounts) = self.load_legacy_credentials(dir)?;
        let served = self.enforce_gateway_mode(dir, &accounts)?;
        let native = self.submission_native_domains();
        let sink: Arc<SpoolSink> = match &self.submission_spool {
            Some(spool) => Arc::new(SpoolSink::new(spool)?),
            None => return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "submission_enable=true requires submission_spool (a hand-off directory your node \
                     picks up); without it accepted mail would be dropped after the 250",
            )),
        };
        let server = SubmissionServer::bind(
            &self.submission_listen,
            tls,
            self.submission_tls,
            native.clone(),
        )?;
        let bound = server.local_addr()?;
        eprintln!(
            "gateway[submission]: legacy SMTP-submission on {bound} ({:?}); mode={}; {} account(s); \
             native domains {:?}; spool {}",
            self.submission_tls,
            self.gateway_mode.label(),
            served,
            native,
            self.submission_spool.as_deref().unwrap_or("-"),
        );
        if accounts.is_empty() {
            eprintln!(
                "gateway[submission]: WARNING — no imap_credentials configured; every AUTH will be \
                 refused (fail-closed)."
            );
        }
        Ok(Some(SubmissionDeployment { server, auth: Arc::new(auth), sink }))
    }

    /// Run the personal gateway daemon: bind the inbound MX, wire the outbound/admission/quota seams,
    /// and serve until `shutdown` flips (the caller installs the signal handler). Fail-closed: any
    /// mis-configuration surfaces as an `Err` here rather than a half-wired daemon.
    pub fn serve(&self, shutdown: &AtomicBool) -> std::io::Result<()> {
        let dir_source = self.load_directory()?;
        eprintln!(
            "gateway[personal]: domain={} recipients={} authz={:?}",
            self.domain,
            dir_source.len(),
            self.authz_mode
        );

        let mesh = self.build_mesh()?;
        match &self.mesh_endpoint {
            Some(e) => {
                eprintln!("gateway[personal]: mesh delivery → {e} (2xx = durable ack → 250)")
            }
            None => eprintln!(
                "gateway[personal]: no mesh_endpoint — NullMesh (inbound → 451, sender retries). \
                 Point mesh_endpoint at your node's ingest URL to deliver."
            ),
        }

        // Build outbound + admission + quota from the SAME directory identities, then hand the
        // directory to the inbound gateway. These are ready for the node-driven outbound ingress.
        let outbound = self.build_outbound();
        let registry = self.build_registry(&dir_source);
        let quota_ledger = self.build_quota_ledger(&dir_source);
        eprintln!(
            "gateway[personal]: outbound SMTP-STARTTLS + MX/MTA-STS via DNS {} ready; \
             {} identity(ies) admissible; quota {}",
            self.dns_server,
            dir_source.len(),
            describe_quota(self.quota()),
        );
        // The seams are wired and available for the node's outbound ingress (kept live for that leg).
        let _outbound = outbound;
        let _registry = registry;
        let _quota_ledger = quota_ledger;

        let tls = self.build_tls()?;
        if tls.is_some() {
            eprintln!("gateway[personal]: STARTTLS enabled");
        } else {
            eprintln!(
                "gateway[personal]: STARTTLS NOT offered (no tls_cert/tls_key) — plaintext MX"
            );
        }

        // Build the optional legacy access surfaces (IMAP / POP3 / SMTP-submission, §7.15.1) BEFORE
        // consuming the directory (they resolve credential identities from the same directory and
        // enforce the operator mode §7.15.4 against it) — fail-closed at startup on any misconfig.
        eprintln!(
            "gateway[personal]: legacy-client mode = {} (§7.15.4)",
            self.gateway_mode.label()
        );
        if !self.gateway_mode.is_zero_third_party()
            && (self.imap_enable || self.pop3_enable || self.submission_enable)
        {
            eprintln!(
                "gateway[personal]: NOTE — a non-private gateway DECRYPTS and can read the mail it \
                 serves (§7.15.3). This is a disclosed trust decision, not zero-access."
            );
        }
        let imap = self.build_imap(&dir_source, tls.clone())?;
        let pop3 = self.build_pop3(&dir_source, tls.clone())?;
        let submission = self.build_submission(&dir_source, tls.clone())?;

        let directory: Box<dyn KeyDirectory> = dir_source.into_boxed();
        let gw = self.build_inbound(directory, mesh);
        eprintln!(
            "gateway[personal]: inbound DKIM/SPF/DMARC via DNS {} (enforce: dkim={} spf={} dmarc={})",
            self.dns_server, self.dkim_enforce, self.spf_enforce, self.dmarc_enforce
        );

        let listener = MxListener::bind(&self.listen, tls)?;
        let bound = listener.local_addr()?;
        eprintln!("gateway[personal]: inbound MX listening on {bound} for {} — up (SIGINT/SIGTERM to stop)", self.domain);

        // Serve the inbound MX (this thread) and every enabled legacy access surface (each on its own
        // thread) concurrently. All poll the SAME shutdown flag, so one SIGINT/SIGTERM stops them all.
        // The MX gateway is not `Send`, so it stays on this thread; the legacy servers are all `Send`.
        std::thread::scope(|scope| -> std::io::Result<()> {
            let mut handles: Vec<std::thread::ScopedJoinHandle<std::io::Result<()>>> = Vec::new();
            if let Some(dep) = imap {
                handles.push(scope.spawn(move || dep.run(shutdown)));
            }
            if let Some(dep) = pop3 {
                handles.push(scope.spawn(move || dep.run(shutdown)));
            }
            if let Some(dep) = submission {
                handles.push(scope.spawn(move || dep.run(shutdown)));
            }
            let mx = listener.serve_until(&gw, shutdown);
            for h in handles {
                h.join().map_err(|_| std::io::Error::other("legacy access thread panicked"))??;
            }
            mx
        })?;
        eprintln!(
            "gateway[personal]: shutdown signal received — stopped accepting, exiting cleanly"
        );
        Ok(())
    }
}

/// A loaded recipient directory, kept concrete so both the inbound gateway and the admission registry
/// can be built from the same source.
pub enum DirectorySource {
    /// A file-backed directory (the operator's own identities).
    File(FileDirectory),
    /// The empty default (resolves nobody).
    Empty(InMemoryDirectory),
}

impl DirectorySource {
    /// Number of configured recipients.
    pub fn len(&self) -> usize {
        match self {
            DirectorySource::File(d) => d.len(),
            DirectorySource::Empty(d) => d.len(),
        }
    }

    /// Whether the directory resolves nobody.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterate the `(email, key)` recipients.
    pub fn iter(&self) -> Box<dyn Iterator<Item = (&str, &crate::inbound::RecipientKey)> + '_> {
        match self {
            DirectorySource::File(d) => Box::new(d.iter()),
            DirectorySource::Empty(d) => Box::new(d.iter()),
        }
    }

    /// Consume into a boxed [`KeyDirectory`] for the inbound gateway.
    pub fn into_boxed(self) -> Box<dyn KeyDirectory> {
        match self {
            DirectorySource::File(d) => Box::new(d),
            DirectorySource::Empty(d) => Box::new(d),
        }
    }
}

/// Resolve a credential username to a DMTAP identity public key from the recipient directory, by
/// case-insensitive email match. Used when an `imap_credentials` line omits the explicit key.
fn resolve_identity(dir: &DirectorySource, user: &str) -> Option<Vec<u8>> {
    dir.iter().find(|(email, _)| email.eq_ignore_ascii_case(user)).map(|(_, k)| k.ik.clone())
}

/// A built, bound legacy IMAP access server plus the per-session store snapshot and authenticator,
/// ready to serve until shutdown. The mailbox `seed` is held as raw `Send + Sync` bytes so a fresh
/// [`MemoryStore`] can be rebuilt per connection (the store's parse cache is `!Sync`).
struct ImapDeployment {
    server: ImapAccessServer,
    seed: Arc<Vec<(Vec<u8>, u64)>>,
    auth: Arc<StaticAuthenticator>,
}

impl ImapDeployment {
    /// Serve the IMAP access listener until `shutdown` flips. Each connection gets its own store
    /// (rebuilt from the snapshot) and a clone of the app-password authenticator.
    fn run(self, shutdown: &AtomicBool) -> std::io::Result<()> {
        let seed = self.seed;
        let auth = self.auth;
        self.server.serve_until(
            move || {
                let mut store = MemoryStore::new();
                for (raw, ts) in seed.iter() {
                    store.deliver_raw("INBOX", raw.clone(), vec![Flag::Recent], *ts);
                }
                store
            },
            move || (*auth).clone(),
            shutdown,
        )
    }
}

/// A built, bound legacy POP3 access server plus the maildrop snapshot + authenticator — the POP3
/// sibling of [`ImapDeployment`]. Serves the same `imap_maildir` snapshot as a POP3 maildrop.
struct Pop3Deployment {
    server: Pop3AccessServer,
    seed: Arc<Vec<(Vec<u8>, u64)>>,
    auth: Arc<StaticAuthenticator>,
}

impl Pop3Deployment {
    /// Serve the POP3 access listener until `shutdown` flips. Each connection gets its own store
    /// (rebuilt from the snapshot) and a clone of the app-password authenticator.
    fn run(self, shutdown: &AtomicBool) -> std::io::Result<()> {
        let seed = self.seed;
        let auth = self.auth;
        self.server.serve_until(
            move || {
                let mut store = MemoryStore::new();
                for (raw, ts) in seed.iter() {
                    store.deliver_raw("INBOX", raw.clone(), vec![Flag::Recent], *ts);
                }
                store
            },
            move || (*auth).clone(),
            shutdown,
        )
    }
}

/// A built, bound legacy SMTP-submission access server plus the authenticator and the [`SpoolSink`]
/// accepted messages are handed off to — the outbound sibling of [`ImapDeployment`].
struct SubmissionDeployment {
    server: SubmissionServer,
    auth: Arc<StaticAuthenticator>,
    sink: Arc<SpoolSink>,
}

impl SubmissionDeployment {
    /// Serve the submission access listener until `shutdown` flips. Each connection gets a clone of
    /// the app-password authenticator; all share the one spool sink.
    fn run(self, shutdown: &AtomicBool) -> std::io::Result<()> {
        let auth = self.auth;
        self.server.serve_until(move || (*auth).clone(), self.sink, shutdown)
    }
}

// ── small parse helpers (std-only; no toml/serde dependency) ──────────────────────────────────

/// Strip an inline `#` comment. A `#` only starts a comment when it is at the start of the trimmed
/// line or preceded by whitespace, so a `#` inside an unspaced value (e.g. a URL fragment) is kept.
fn strip_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'#' && (i == 0 || bytes[i - 1].is_ascii_whitespace()) {
            return &line[..i];
        }
    }
    line
}

/// Remove a single pair of surrounding double quotes, if present.
fn unquote(value: &str) -> String {
    let v = value.trim();
    if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
        v[1..v.len() - 1].to_string()
    } else {
        v.to_string()
    }
}

/// `Some(v)` unless `v` is empty after trimming (an empty value means "unset").
fn non_empty(v: String) -> Option<String> {
    let t = v.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

/// Parse `true`/`false`/`1`/`0`/`yes`/`no` (case-insensitive).
fn parse_bool(v: &str) -> Option<bool> {
    match v.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    }
}

/// Parse the admission mode spelling(s).
fn parse_authz_mode(v: &str) -> Option<AuthzMode> {
    match v.trim().to_ascii_lowercase().replace('_', "-").as_str() {
        "key-registered" | "keyregistered" | "registered" => Some(AuthzMode::KeyRegistered),
        "open-public" | "openpublic" | "open" | "public" => Some(AuthzMode::OpenPublic),
        _ => None,
    }
}

/// The `run`-daemon opt-in boolean env convention (`1`/`true`/`yes`).
fn env_flag(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"),
        Err(_) => false,
    }
}

/// Human-readable quota summary for the startup log.
fn describe_quota(quota: Option<Quota>) -> String {
    match quota {
        None => "unlimited".to_string(),
        Some(q) => {
            format!("cap {} msgs / {} bytes per identity", q.hard_cap_messages, q.hard_cap_bytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::b64;

    #[test]
    fn default_config_is_safe_and_fail_closed() {
        let cfg = PersonalConfig::default();
        assert_eq!(cfg.authz_mode, AuthzMode::KeyRegistered, "default is NOT an open relay");
        assert!(
            !cfg.dkim_enforce && !cfg.spf_enforce && !cfg.dmarc_enforce,
            "checks annotate by default"
        );
        assert!(cfg.directory.is_none(), "resolves nobody until configured");
        assert!(cfg.quota().is_none(), "unlimited until a cap is set");
        assert!(!cfg.imap_enable, "legacy IMAP access is OFF by default");
    }

    #[test]
    fn imap_config_keys_parse_and_default_off() {
        // Off by default; keys unset.
        let cfg = PersonalConfig::parse("domain = mail.example.org\n").unwrap();
        assert!(!cfg.imap_enable);
        assert_eq!(cfg.imap_tls, ImapTls::StartTls, "default TLS mode is STARTTLS");

        let text = r#"
            imap_enable      = true
            imap_listen      = "0.0.0.0:993"
            imap_tls         = implicit
            imap_credentials = "/etc/envoir/app-passwords.txt"
            imap_maildir     = "/var/mail/owner"
        "#;
        let cfg = PersonalConfig::parse(text).unwrap();
        assert!(cfg.imap_enable);
        assert_eq!(cfg.imap_listen, "0.0.0.0:993");
        assert_eq!(cfg.imap_tls, ImapTls::Implicit);
        assert_eq!(cfg.imap_credentials.as_deref(), Some("/etc/envoir/app-passwords.txt"));
        assert_eq!(cfg.imap_maildir.as_deref(), Some("/var/mail/owner"));

        // A bad imap_tls value fails closed.
        assert!(matches!(
            PersonalConfig::parse("imap_tls = plaintext\n").unwrap_err(),
            ConfigError::BadValue { key, .. } if key == "imap_tls"
        ));
    }

    #[test]
    fn imap_requires_tls_and_is_none_when_disabled() {
        // Disabled → no deployment regardless of the rest of the config.
        let cfg = PersonalConfig::default();
        let dir = cfg.load_directory().unwrap();
        assert!(cfg.build_imap(&dir, None).unwrap().is_none(), "disabled → None");

        // Enabled but no TLS cert/key → hard error (app-passwords must not travel in cleartext).
        let cfg = PersonalConfig { imap_enable: true, ..PersonalConfig::default() };
        let dir = cfg.load_directory().unwrap();
        assert!(cfg.build_imap(&dir, None).is_err(), "enabled without TLS must fail closed");
    }

    #[test]
    fn pop3_and_submission_keys_parse_and_default_off_and_require_tls() {
        // Off by default; safe defaults.
        let cfg = PersonalConfig::default();
        assert!(!cfg.pop3_enable && !cfg.submission_enable, "both legacy surfaces off by default");
        assert_eq!(cfg.gateway_mode, GatewayMode::Private, "default mode is the most restrictive");
        assert_eq!(cfg.pop3_tls, LegacyTls::StartTls);
        assert_eq!(cfg.submission_tls, LegacyTls::StartTls);

        let text = r#"
            gateway_mode              = public
            pop3_enable               = true
            pop3_listen               = "0.0.0.0:995"
            pop3_tls                  = implicit
            submission_enable         = true
            submission_listen         = "0.0.0.0:465"
            submission_tls            = implicit
            submission_spool          = "/var/spool/envoir-out"
            submission_native_domains = "example.org, mail.example.org"
        "#;
        let cfg = PersonalConfig::parse(text).unwrap();
        assert_eq!(cfg.gateway_mode, GatewayMode::Public);
        assert!(cfg.pop3_enable && cfg.submission_enable);
        assert_eq!(cfg.pop3_listen, "0.0.0.0:995");
        assert_eq!(cfg.pop3_tls, LegacyTls::Implicit);
        assert_eq!(cfg.submission_tls, LegacyTls::Implicit);
        assert_eq!(cfg.submission_spool.as_deref(), Some("/var/spool/envoir-out"));
        assert_eq!(
            cfg.submission_native_domains(),
            vec!["example.org".to_string(), "mail.example.org".to_string()]
        );

        // A bad mode value fails closed.
        assert!(matches!(
            PersonalConfig::parse("gateway_mode = whatever\n").unwrap_err(),
            ConfigError::BadValue { key, .. } if key == "gateway_mode"
        ));

        // Enabling either surface without TLS is a hard error (no cleartext app-passwords).
        let dir = PersonalConfig::default().load_directory().unwrap();
        let no_tls = PersonalConfig { pop3_enable: true, ..PersonalConfig::default() };
        assert!(no_tls.build_pop3(&dir, None).is_err(), "pop3 without TLS must fail closed");
        let no_tls = PersonalConfig { submission_enable: true, ..PersonalConfig::default() };
        assert!(
            no_tls.build_submission(&dir, None).is_err(),
            "submission without TLS must fail closed"
        );

        // Native domains default to the gateway's own domain.
        let cfg = PersonalConfig { domain: "host.net".into(), ..PersonalConfig::default() };
        assert_eq!(cfg.submission_native_domains(), vec!["host.net".to_string()]);
    }

    #[test]
    fn operator_mode_gates_which_accounts_are_served() {
        // Set up a directory with ONE registered identity (me@example.org).
        let ik = IdentityKey::generate();
        let seal = dmtap_core::mote::SealKeypair::generate();
        let mut dirpath = std::env::temp_dir();
        dirpath.push(format!("envoir-gw-mode-dir-{}.txt", std::process::id()));
        std::fs::write(
            &dirpath,
            format!(
                "me@example.org {} {}\n",
                b64::encode(&ik.public()),
                b64::encode(seal.public())
            ),
        )
        .unwrap();

        let base = PersonalConfig {
            domain: "example.org".into(),
            directory: Some(dirpath.display().to_string()),
            ..PersonalConfig::default()
        };
        let dir = base.load_directory().unwrap();

        let one = vec!["me@example.org".to_string()];
        let two = vec!["me@example.org".to_string(), "guest@example.org".to_string()];
        let stranger = vec!["stranger@elsewhere.net".to_string()];

        // PRIVATE: one account OK, two distinct accounts refused (single operator, §7.15.4).
        let private = PersonalConfig { gateway_mode: GatewayMode::Private, ..base.clone() };
        assert!(private.enforce_gateway_mode(&dir, &one).is_ok());
        assert!(
            private.enforce_gateway_mode(&dir, &two).is_err(),
            "private serves a single operator only"
        );

        // REGISTERED-CLIENTS-ONLY: a registered account OK, an unregistered one refused.
        let reg =
            PersonalConfig { gateway_mode: GatewayMode::RegisteredClientsOnly, ..base.clone() };
        assert!(reg.enforce_gateway_mode(&dir, &one).is_ok());
        assert!(
            reg.enforce_gateway_mode(&dir, &stranger).is_err(),
            "an unregistered account is refused in registered-clients-only mode"
        );

        // PUBLIC: anything goes (open registration).
        let public = PersonalConfig { gateway_mode: GatewayMode::Public, ..base.clone() };
        assert!(public.enforce_gateway_mode(&dir, &two).is_ok());
        assert!(public.enforce_gateway_mode(&dir, &stranger).is_ok());

        let _ = std::fs::remove_file(&dirpath);
    }

    #[test]
    fn imap_credentials_bind_to_directory_identity_and_fail_closed() {
        // A credentials file that omits the identity key resolves it from the recipient directory.
        let ik = IdentityKey::generate();
        let seal = dmtap_core::mote::SealKeypair::generate();
        let mut dirpath = std::env::temp_dir();
        dirpath.push(format!("envoir-gw-imap-dir-{}.txt", std::process::id()));
        std::fs::write(
            &dirpath,
            format!(
                "me@example.org {} {}\n",
                b64::encode(&ik.public()),
                b64::encode(seal.public())
            ),
        )
        .unwrap();
        let mut credpath = std::env::temp_dir();
        credpath.push(format!("envoir-gw-imap-cred-{}.txt", std::process::id()));
        // Line 1 omits the key (resolved from directory); line 2 gives an explicit key.
        std::fs::write(
            &credpath,
            format!(
                "me@example.org app-pw-1\nother@example.org app-pw-2 {}\n",
                b64::encode(&[7u8; 32])
            ),
        )
        .unwrap();

        let cfg = PersonalConfig {
            domain: "example.org".to_string(),
            directory: Some(dirpath.display().to_string()),
            imap_credentials: Some(credpath.display().to_string()),
            ..PersonalConfig::default()
        };
        let dir = cfg.load_directory().unwrap();
        let (auth, accounts) = cfg.load_legacy_credentials(&dir).unwrap();
        assert_eq!(accounts.len(), 2, "both credential lines load");
        // The directory-bound credential authenticates and resolves to the directory identity key.
        assert_eq!(
            dmtap_mail::auth::Authenticator::verify(&auth, "me@example.org", "app-pw-1"),
            Some(ik.public()),
            "directory-resolved identity"
        );
        assert!(
            dmtap_mail::auth::Authenticator::verify(&auth, "me@example.org", "wrong").is_none(),
            "wrong password fails closed"
        );

        // An unknown user with no explicit key is a hard error (cannot bind an identity).
        std::fs::write(&credpath, "ghost@example.org app-pw-3\n").unwrap();
        assert!(
            cfg.load_legacy_credentials(&dir).is_err(),
            "unknown user + no key must fail closed"
        );

        let _ = std::fs::remove_file(&dirpath);
        let _ = std::fs::remove_file(&credpath);
    }

    #[test]
    fn parses_a_full_personal_config() {
        let text = r#"
            # my personal gateway
            domain       = "mail.example.org"
            listen       = "0.0.0.0:25"
            selector     = gw1
            dns_server   = "9.9.9.9:53"
            directory    = "/etc/envoir/recipients.txt"
            mesh_endpoint = "http://127.0.0.1:8710/dmtap/ingest"
            tls_cert     = "/etc/envoir/fullchain.pem"
            tls_key      = "/etc/envoir/privkey.pem"
            authz_mode   = key-registered
            dkim_enforce = false
            spf_enforce  = true    # reject SPF hard-fails
            dmarc_enforce = true
            quota_messages = 5000
            quota_bytes    = 0
        "#;
        let cfg = PersonalConfig::parse(text).expect("parse");
        assert_eq!(cfg.domain, "mail.example.org");
        assert_eq!(cfg.listen, "0.0.0.0:25");
        assert_eq!(cfg.dns_server, "9.9.9.9:53".parse().unwrap());
        assert_eq!(cfg.directory.as_deref(), Some("/etc/envoir/recipients.txt"));
        assert_eq!(cfg.mesh_endpoint.as_deref(), Some("http://127.0.0.1:8710/dmtap/ingest"));
        assert_eq!(cfg.tls_cert.as_deref(), Some("/etc/envoir/fullchain.pem"));
        assert_eq!(cfg.authz_mode, AuthzMode::KeyRegistered);
        assert!(!cfg.dkim_enforce);
        assert!(cfg.spf_enforce);
        assert!(cfg.dmarc_enforce);
        assert_eq!(cfg.quota().unwrap().hard_cap_messages, 5000);
    }

    #[test]
    fn unknown_key_is_a_hard_error_not_silently_ignored() {
        // A typo'd security knob must fail closed, never be ignored.
        let err = PersonalConfig::parse("authz_moad = open-public\n").unwrap_err();
        assert!(matches!(err, ConfigError::UnknownKey { line: 1, .. }), "got {err:?}");
    }

    #[test]
    fn malformed_values_fail_closed() {
        assert!(matches!(
            PersonalConfig::parse("dns_server = not-an-address\n").unwrap_err(),
            ConfigError::BadValue { key, .. } if key == "dns_server"
        ));
        assert!(matches!(
            PersonalConfig::parse("authz_mode = whatever\n").unwrap_err(),
            ConfigError::BadValue { key, .. } if key == "authz_mode"
        ));
        assert!(matches!(
            PersonalConfig::parse("spf_enforce = maybe\n").unwrap_err(),
            ConfigError::BadValue { key, .. } if key == "spf_enforce"
        ));
        assert!(matches!(
            PersonalConfig::parse("quota_messages = lots\n").unwrap_err(),
            ConfigError::BadValue { key, .. } if key == "quota_messages"
        ));
        assert!(matches!(
            PersonalConfig::parse("domain\n").unwrap_err(),
            ConfigError::Syntax { line: 1, .. }
        ));
    }

    #[test]
    fn comments_and_blanks_are_ignored_but_hash_in_a_value_is_kept() {
        let cfg = PersonalConfig::parse("\n# full-line comment\n  selector = sel1  # trailing\n")
            .unwrap();
        assert_eq!(cfg.selector, "sel1");
        // A '#' not preceded by whitespace inside a value is preserved.
        let cfg2 = PersonalConfig::parse("mesh_endpoint = http://h/p#frag\n").unwrap();
        assert_eq!(cfg2.mesh_endpoint.as_deref(), Some("http://h/p#frag"));
    }

    #[test]
    fn key_registered_registry_is_seeded_from_the_operators_directory() {
        // The personal registry admits the operator's own directory identity and rejects a stranger.
        let ik = IdentityKey::generate();
        let seal = dmtap_core::mote::SealKeypair::generate();
        let mut path = std::env::temp_dir();
        path.push(format!("envoir-gw-personal-{}.txt", std::process::id()));
        std::fs::write(
            &path,
            format!(
                "me@example.org {} {}\n",
                b64::encode(&ik.public()),
                b64::encode(seal.public())
            ),
        )
        .unwrap();

        let cfg = PersonalConfig {
            domain: "example.org".to_string(),
            directory: Some(path.display().to_string()),
            authz_mode: AuthzMode::KeyRegistered,
            quota_messages: 100,
            ..PersonalConfig::default()
        };
        let dir = cfg.load_directory().expect("load directory");
        assert_eq!(dir.len(), 1);
        let reg = cfg.build_registry(&dir);

        // The operator's own key admits (challenge–response) and is bound to its directory account.
        let ch = reg.issue_challenge([3u8; 32], 1_000_000);
        let sig = ik.sign_domain(crate::authz::ADMISSION_DS, &ch.signing_body());
        let adm =
            reg.admit(&ch, &ik.public(), &sig, 1_000_050).expect("operator identity admitted");
        assert_eq!(adm.account, "me@example.org");
        assert_eq!(adm.domain, "example.org");

        // A stranger's key is NOT registered → UnknownKey (fail-closed, not an open relay).
        let stranger = IdentityKey::generate();
        let ch2 = reg.issue_challenge([4u8; 32], 1_000_000);
        let sig2 = stranger.sign_domain(crate::authz::ADMISSION_DS, &ch2.signing_body());
        assert_eq!(
            reg.admit(&ch2, &stranger.public(), &sig2, 1_000_050),
            Err(crate::authz::AdmissionError::UnknownKey)
        );

        // The quota ledger is seeded for that account at the configured cap.
        let ledger = cfg.build_quota_ledger(&dir);
        assert!(ledger.try_charge("me@example.org", 1).is_ok(), "within the 100-message cap");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn open_public_registry_registers_nobody() {
        let cfg = PersonalConfig { authz_mode: AuthzMode::OpenPublic, ..PersonalConfig::default() };
        let dir = cfg.load_directory().expect("empty directory");
        let reg = cfg.build_registry(&dir);
        assert_eq!(reg.mode(), AuthzMode::OpenPublic);
        // Any key-controller is admitted with an anon label (documented spam risk).
        let anyone = IdentityKey::generate();
        let ch = reg.issue_challenge([1u8; 32], 5_000);
        let sig = anyone.sign_domain(crate::authz::ADMISSION_DS, &ch.signing_body());
        let adm = reg.admit(&ch, &anyone.public(), &sig, 5_050).expect("open relay admits");
        assert!(adm.account.starts_with("anon:"));
    }

    #[test]
    fn partial_tls_is_rejected_fail_closed() {
        let cfg = PersonalConfig { tls_cert: Some("cert.pem".into()), ..PersonalConfig::default() };
        assert!(cfg.build_tls().is_err(), "only one of cert/key set must fail closed");
    }

    #[test]
    fn quota_is_none_when_uncapped_and_some_when_capped() {
        let mut cfg = PersonalConfig::default();
        assert!(cfg.quota().is_none());
        cfg.quota_messages = 10;
        let q = cfg.quota().expect("some");
        assert_eq!(q.hard_cap_messages, 10);
    }
}
