//! Autodiscovery — so a device needs only the email address (spec §8: "clients terminate on the
//! node"; onboarding must be zero-config). Generates:
//!
//! - **SRV records** (RFC 6186 + RFC 8314 implicit-TLS) a node publishes in DNS,
//! - **Thunderbird autoconfig** XML (`config-v1.1`, Mozilla ISPDB schema),
//! - **Apple `.mobileconfig`** configuration profile (plist),
//! - **Microsoft Autodiscover** POX XML (Outlook).
//!
//! Ports follow RFC 8314 (implicit TLS): IMAPS 993, POP3S 995, Submission 465, plus JMAP over
//! HTTPS. Auth is app-passwords (spec §8.2). Everything here is pure string generation and tested.

/// Connection coordinates for a DMTAP node's mail edge.
#[derive(Debug, Clone)]
pub struct HostConfig {
    /// The mail domain (right-hand side of the address), e.g. `dmtap.local`.
    pub domain: String,
    /// The reachable node host that terminates the legacy protocols, e.g. `mail.dmtap.local`.
    pub host: String,
    pub imaps_port: u16,
    pub pop3s_port: u16,
    pub submission_port: u16,
    /// The base HTTPS URL of the JMAP endpoint.
    pub jmap_url: String,
}

impl HostConfig {
    /// Standard RFC 8314 implicit-TLS ports for a node on `host` serving `domain`.
    pub fn standard(domain: impl Into<String>, host: impl Into<String>) -> HostConfig {
        let host = host.into();
        HostConfig {
            domain: domain.into(),
            jmap_url: format!("https://{host}/.well-known/jmap"),
            host,
            imaps_port: 993,
            pop3s_port: 995,
            submission_port: 465,
        }
    }
}

/// One DNS SRV record (RFC 2782 / RFC 6186).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrvRecord {
    /// Service label including protocol, e.g. `_imaps._tcp`.
    pub service: String,
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
}

impl SrvRecord {
    /// A BIND zone-file line, rooted at `domain`.
    pub fn zone_line(&self, domain: &str) -> String {
        format!(
            "{}.{}. 3600 IN SRV {} {} {} {}.",
            self.service, domain, self.priority, self.weight, self.port, self.target
        )
    }
}

/// The full SRV record set a node publishes for client autoconfiguration (RFC 6186 §3, plus
/// `_jmap._tcp` per RFC 8620 §2.2). A negative `_submission` (priority-0 to `.`) is omitted; we
/// advertise implicit-TLS submission on 465.
pub fn srv_records(cfg: &HostConfig) -> Vec<SrvRecord> {
    vec![
        SrvRecord { service: "_imaps._tcp".into(), priority: 0, weight: 1, port: cfg.imaps_port, target: cfg.host.clone() },
        SrvRecord { service: "_submissions._tcp".into(), priority: 0, weight: 1, port: cfg.submission_port, target: cfg.host.clone() },
        SrvRecord { service: "_pop3s._tcp".into(), priority: 10, weight: 1, port: cfg.pop3s_port, target: cfg.host.clone() },
        SrvRecord { service: "_jmap._tcp".into(), priority: 0, weight: 1, port: 443, target: cfg.host.clone() },
    ]
}

/// Render the SRV record set as zone-file lines.
pub fn srv_zone(cfg: &HostConfig) -> String {
    srv_records(cfg).iter().map(|r| r.zone_line(&cfg.domain)).collect::<Vec<_>>().join("\n")
}

/// Thunderbird / Mozilla autoconfig XML (`config-v1.1`), served at
/// `https://autoconfig.<domain>/mail/config-v1.1.xml?emailaddress=…` (RFC-adjacent, ISPDB).
pub fn thunderbird_autoconfig(cfg: &HostConfig) -> String {
    let d = &cfg.domain;
    let h = &cfg.host;
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<clientConfig version="1.1">
  <emailProvider id="{d}">
    <domain>{d}</domain>
    <displayName>Envoir DMTAP ({d})</displayName>
    <displayShortName>Envoir</displayShortName>
    <incomingServer type="imap">
      <hostname>{h}</hostname>
      <port>{imaps}</port>
      <socketType>SSL</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </incomingServer>
    <incomingServer type="pop3">
      <hostname>{h}</hostname>
      <port>{pop3s}</port>
      <socketType>SSL</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </incomingServer>
    <outgoingServer type="smtp">
      <hostname>{h}</hostname>
      <port>{sub}</port>
      <socketType>SSL</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </outgoingServer>
  </emailProvider>
</clientConfig>
"#,
        imaps = cfg.imaps_port,
        pop3s = cfg.pop3s_port,
        sub = cfg.submission_port,
    )
}

/// Apple `.mobileconfig` profile (plist) with an `com.apple.mail.managed` payload, so an iPhone
/// configures IMAP + submission from just the address.
pub fn apple_mobileconfig(cfg: &HostConfig, email: &str) -> String {
    let d = &cfg.domain;
    let h = &cfg.host;
    // Deterministic-ish UUIDs derived from the address so re-generating is stable.
    let uuid1 = pseudo_uuid(&format!("{email}-account"));
    let uuid2 = pseudo_uuid(&format!("{email}-profile"));
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key><string>com.apple.mail.managed</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadIdentifier</key><string>local.dmtap.{d}.mail</string>
      <key>PayloadUUID</key><string>{uuid1}</string>
      <key>PayloadDisplayName</key><string>Envoir ({d})</string>
      <key>EmailAccountType</key><string>EmailTypeIMAP</string>
      <key>EmailAccountName</key><string>{email}</string>
      <key>EmailAddress</key><string>{email}</string>
      <key>IncomingMailServerHostName</key><string>{h}</string>
      <key>IncomingMailServerPortNumber</key><integer>{imaps}</integer>
      <key>IncomingMailServerUseSSL</key><true/>
      <key>IncomingMailServerAuthentication</key><string>EmailAuthPassword</string>
      <key>IncomingMailServerUsername</key><string>{email}</string>
      <key>OutgoingMailServerHostName</key><string>{h}</string>
      <key>OutgoingMailServerPortNumber</key><integer>{sub}</integer>
      <key>OutgoingMailServerUseSSL</key><true/>
      <key>OutgoingMailServerAuthentication</key><string>EmailAuthPassword</string>
      <key>OutgoingMailServerUsername</key><string>{email}</string>
      <key>SMTPEnablePasswordAuthentication</key><true/>
    </dict>
  </array>
  <key>PayloadDisplayName</key><string>Envoir DMTAP Mail ({d})</string>
  <key>PayloadIdentifier</key><string>local.dmtap.{d}</string>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadUUID</key><string>{uuid2}</string>
  <key>PayloadVersion</key><integer>1</integer>
</dict>
</plist>
"#,
        imaps = cfg.imaps_port,
        sub = cfg.submission_port,
    )
}

/// Microsoft Autodiscover POX response XML (Outlook), served from
/// `https://autodiscover.<domain>/autodiscover/autodiscover.xml`.
pub fn microsoft_autodiscover(cfg: &HostConfig, email: &str) -> String {
    let h = &cfg.host;
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
  <Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
    <User>
      <DisplayName>{email}</DisplayName>
    </User>
    <Account>
      <AccountType>email</AccountType>
      <Action>settings</Action>
      <Protocol>
        <Type>IMAP</Type>
        <Server>{h}</Server>
        <Port>{imaps}</Port>
        <LoginName>{email}</LoginName>
        <SSL>on</SSL>
        <SPA>off</SPA>
        <AuthRequired>on</AuthRequired>
      </Protocol>
      <Protocol>
        <Type>SMTP</Type>
        <Server>{h}</Server>
        <Port>{sub}</Port>
        <LoginName>{email}</LoginName>
        <SSL>on</SSL>
        <SPA>off</SPA>
        <AuthRequired>on</AuthRequired>
      </Protocol>
    </Account>
  </Response>
</Autodiscover>
"#,
        imaps = cfg.imaps_port,
        sub = cfg.submission_port,
    )
}

/// A stable pseudo-UUID (v4-shaped) derived from a seed via the core content hash. Not a real
/// random UUID — deterministic so regenerating a profile yields the same identifier.
fn pseudo_uuid(seed: &str) -> String {
    let h = crate::util::hex(dmtap_core::ContentId::of(seed.as_bytes()).digest());
    format!(
        "{}-{}-4{}-8{}-{}",
        &h[0..8],
        &h[8..12],
        &h[13..16],
        &h[17..20],
        &h[20..32]
    )
    .to_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> HostConfig {
        HostConfig::standard("dmtap.local", "mail.dmtap.local")
    }

    #[test]
    fn srv_records_cover_all_services() {
        let recs = srv_records(&cfg());
        let services: Vec<&str> = recs.iter().map(|r| r.service.as_str()).collect();
        assert!(services.contains(&"_imaps._tcp"));
        assert!(services.contains(&"_submissions._tcp"));
        assert!(services.contains(&"_pop3s._tcp"));
        assert!(services.contains(&"_jmap._tcp"));
        let zone = srv_zone(&cfg());
        assert!(zone.contains("_imaps._tcp.dmtap.local. 3600 IN SRV 0 1 993 mail.dmtap.local."));
    }

    #[test]
    fn thunderbird_xml_well_formed_fields() {
        let xml = thunderbird_autoconfig(&cfg());
        assert!(xml.contains("<clientConfig version=\"1.1\">"));
        assert!(xml.contains("<hostname>mail.dmtap.local</hostname>"));
        assert!(xml.contains("<port>993</port>"));
        assert!(xml.contains("type=\"smtp\""));
        assert!(xml.contains("<port>465</port>"));
    }

    #[test]
    fn apple_profile_has_payloads() {
        let p = apple_mobileconfig(&cfg(), "alice@dmtap.local");
        assert!(p.contains("com.apple.mail.managed"));
        assert!(p.contains("<key>EmailAddress</key><string>alice@dmtap.local</string>"));
        assert!(p.contains("<key>IncomingMailServerPortNumber</key><integer>993</integer>"));
        // Deterministic UUID: regenerating yields the same value.
        assert_eq!(p, apple_mobileconfig(&cfg(), "alice@dmtap.local"));
    }

    #[test]
    fn microsoft_autodiscover_protocols() {
        let xml = microsoft_autodiscover(&cfg(), "bob@dmtap.local");
        assert!(xml.contains("<Type>IMAP</Type>"));
        assert!(xml.contains("<Type>SMTP</Type>"));
        assert!(xml.contains("<Port>993</Port>"));
        assert!(xml.contains("<LoginName>bob@dmtap.local</LoginName>"));
    }

    #[test]
    fn pseudo_uuid_shape() {
        let u = pseudo_uuid("seed");
        assert_eq!(u.len(), 36);
        assert_eq!(u.as_bytes()[14], b'4'); // version nibble
    }
}
