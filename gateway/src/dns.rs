//! A minimal, dependency-free DNS-over-UDP client (RFC 1035) — just enough wire format to resolve
//! MX (type 15), A (type 1), and TXT (type 16) records for outbound MX resolution (spec §7.3 step 4,
//! RFC 5321 §5.1) and the MTA-STS `_mta-sts` TXT lookup (RFC 8461 §3.1).
//!
//! This crate is deliberately std-only and synchronous (see crate docs): a full resolver crate
//! (`hickory-resolver`/`trust-dns`) drags in an async executor this crate does not otherwise need,
//! so instead this is a few hundred lines of wire codec behind [`UdpDnsClient`]. The codec
//! (`encode_query` / `parse_response` / `parse_mx_rdata` / ...) is pure and unit-tested directly
//! against hand-built byte buffers — no network involved in tests.
//!
//! **Known limitations (seams, not implemented):** no TCP fallback on a truncated (`TC`) UDP reply,
//! no EDNS0, no retries, no caching, no DNSSEC validation. A real high-volume deployment may want
//! those; the reference gateway does not need them to demonstrate the outbound MX/MTA-STS flow.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

pub const CLASS_IN: u16 = 1;
pub const TYPE_A: u16 = 1;
pub const TYPE_MX: u16 = 15;
pub const TYPE_TXT: u16 = 16;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DnsError {
    #[error("DNS message too short")]
    Truncated,
    #[error("DNS name compression pointer loop or out-of-range offset")]
    BadPointer,
    #[error("DNS response rcode indicates failure ({0})")]
    Rcode(u8),
}

/// One decoded resource record from the answer section. `rdata_offset` is the byte offset of
/// `rdata` within the **original** packet — needed so an MX record's exchange name (which may use a
/// compression pointer back into the packet) can be decoded after the fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRecord {
    pub name: String,
    pub rtype: u16,
    pub rdata: Vec<u8>,
    pub rdata_offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsMessage {
    pub id: u16,
    pub rcode: u8,
    pub answers: Vec<ResourceRecord>,
}

/// Draw a fresh, unpredictable 16-bit DNS transaction id from the OS CSPRNG (RFC 5452 §9.2). A
/// CSPRNG-derived id — not a clock reading — is what makes an off-path answer-forgery attacker have
/// to guess the id (there is no DNSSEC validation in this minimal client, so the id + source-port
/// entropy is the whole defense against off-path spoofing).
fn random_txn_id() -> io::Result<u16> {
    let mut b = [0u8; 2];
    getrandom::getrandom(&mut b)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("CSPRNG unavailable: {e}")))?;
    Ok(u16::from_be_bytes(b))
}

/// Build a standard, recursion-desired query packet for `qname`/`qtype`/IN.
pub fn encode_query(id: u16, qname: &str, qtype: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(qname.len() + 18);
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD=1
    buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    encode_name(&mut buf, qname);
    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&CLASS_IN.to_be_bytes());
    buf
}

fn encode_name(buf: &mut Vec<u8>, name: &str) {
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() {
            continue;
        }
        // A hostile/misconfigured label longer than 63 bytes is simply truncated to fit the DNS
        // label-length octet; the resulting query will just not resolve, which is a safe failure.
        let len = label.len().min(63);
        buf.push(len as u8);
        buf.extend_from_slice(&label.as_bytes()[..len]);
    }
    buf.push(0);
}

/// Decode a (possibly compressed) domain name starting at `start`. Returns the name and the offset
/// immediately after it in the **linear** stream (i.e. where a pointer was first taken, not where it
/// pointed to) — the correct place for the caller to resume sequential parsing.
fn read_name(packet: &[u8], start: usize) -> Result<(String, usize), DnsError> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut resume_at: Option<usize> = None;
    let mut jumps = 0u32;
    loop {
        if jumps > 32 {
            return Err(DnsError::BadPointer);
        }
        let len = *packet.get(pos).ok_or(DnsError::Truncated)?;
        if len == 0 {
            if resume_at.is_none() {
                resume_at = Some(pos + 1);
            }
            break;
        } else if len & 0xC0 == 0xC0 {
            let b2 = *packet.get(pos + 1).ok_or(DnsError::Truncated)?;
            if resume_at.is_none() {
                resume_at = Some(pos + 2);
            }
            let ptr = (((len & 0x3F) as usize) << 8) | b2 as usize;
            if ptr >= packet.len() || ptr >= pos {
                // Forbid pointers that don't strictly go backwards — RFC 1035 compression only ever
                // points earlier in the message; rejecting anything else avoids a parse loop.
                return Err(DnsError::BadPointer);
            }
            pos = ptr;
            jumps += 1;
            continue;
        } else if len & 0xC0 != 0 {
            return Err(DnsError::BadPointer); // reserved label-length bits
        } else {
            let len = len as usize;
            let lstart = pos + 1;
            let lend = lstart + len;
            let bytes = packet.get(lstart..lend).ok_or(DnsError::Truncated)?;
            labels.push(String::from_utf8_lossy(bytes).into_owned());
            pos = lend;
        }
    }
    Ok((labels.join("."), resume_at.unwrap_or(pos)))
}

fn read_u16(packet: &[u8], pos: usize) -> Result<u16, DnsError> {
    let b = packet.get(pos..pos + 2).ok_or(DnsError::Truncated)?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

/// Parse a full DNS response message: header + question section (skipped) + answer RRs. The
/// authority/additional sections are not decoded (not needed for MX/A/TXT lookups here).
pub fn parse_response(packet: &[u8]) -> Result<DnsMessage, DnsError> {
    if packet.len() < 12 {
        return Err(DnsError::Truncated);
    }
    let id = read_u16(packet, 0)?;
    let flags = read_u16(packet, 2)?;
    let rcode = (flags & 0x000F) as u8;
    let qdcount = read_u16(packet, 4)? as usize;
    let ancount = read_u16(packet, 6)? as usize;

    let mut pos = 12;
    for _ in 0..qdcount {
        let (_, next) = read_name(packet, pos)?;
        pos = next + 4; // QTYPE + QCLASS
        if pos > packet.len() {
            return Err(DnsError::Truncated);
        }
    }

    if rcode != 0 {
        // Still return the (empty) message — callers treat "no answers" and "server failure"
        // similarly (fall back / abort), but keep the rcode visible for diagnostics.
        return Ok(DnsMessage { id, rcode, answers: Vec::new() });
    }

    let mut answers = Vec::with_capacity(ancount);
    for _ in 0..ancount {
        let (name, next) = read_name(packet, pos)?;
        pos = next;
        let rtype = read_u16(packet, pos)?;
        pos += 2;
        let _rclass = read_u16(packet, pos)?;
        pos += 2;
        let _ttl = {
            let b = packet.get(pos..pos + 4).ok_or(DnsError::Truncated)?;
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        };
        pos += 4;
        let rdlength = read_u16(packet, pos)? as usize;
        pos += 2;
        let rdata_offset = pos;
        let rdata = packet.get(pos..pos + rdlength).ok_or(DnsError::Truncated)?.to_vec();
        pos += rdlength;
        answers.push(ResourceRecord { name, rtype, rdata, rdata_offset });
    }
    Ok(DnsMessage { id, rcode, answers })
}

/// Decode an MX record's rdata (2-byte preference + exchange name, RFC 1035 §3.3.9). `packet` is the
/// full original message (needed if the exchange name uses a compression pointer).
pub fn parse_mx_rdata(packet: &[u8], rr: &ResourceRecord) -> Result<(u16, String), DnsError> {
    if rr.rdata.len() < 3 {
        return Err(DnsError::Truncated);
    }
    let preference = u16::from_be_bytes([rr.rdata[0], rr.rdata[1]]);
    let (exchange, _) = read_name(packet, rr.rdata_offset + 2)?;
    Ok((preference, exchange))
}

/// Decode an A record's rdata (RFC 1035 §3.4.1).
pub fn parse_a_rdata(rr: &ResourceRecord) -> Option<Ipv4Addr> {
    if rr.rdata.len() == 4 {
        Some(Ipv4Addr::new(rr.rdata[0], rr.rdata[1], rr.rdata[2], rr.rdata[3]))
    } else {
        None
    }
}

/// Decode a TXT record's rdata: one or more length-prefixed character-strings, concatenated (RFC
/// 1035 §3.3.14; RFC 8461 §3.1 policies are carried as a single concatenated value).
pub fn parse_txt_rdata(rr: &ResourceRecord) -> String {
    let mut s = String::new();
    let mut i = 0;
    while i < rr.rdata.len() {
        let len = rr.rdata[i] as usize;
        i += 1;
        if i + len > rr.rdata.len() {
            break;
        }
        s.push_str(&String::from_utf8_lossy(&rr.rdata[i..i + len]));
        i += len;
    }
    s
}

/// A real DNS-over-UDP transport: one query, one datagram response, no retry/TCP-fallback (see
/// module docs). Used by [`crate::mx::DnsMxResolver`] and [`crate::mta_sts::DnsTxtResolver`].
#[derive(Debug, Clone)]
pub struct UdpDnsClient {
    pub server: SocketAddr,
    pub timeout: Duration,
}

impl UdpDnsClient {
    pub fn new(server: SocketAddr) -> Self {
        UdpDnsClient { server, timeout: Duration::from_secs(5) }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Send `qname`/`qtype` and return the parsed response. IO errors (timeout, connection refused,
    /// ...) and malformed-response errors are both surfaced as `io::Error` — callers treat any
    /// failure to resolve the same way (fall back / fail closed depending on context).
    pub fn query(&self, qname: &str, qtype: u16) -> io::Result<DnsMessage> {
        Ok(self.query_raw(qname, qtype)?.1)
    }

    /// As [`Self::query`], but also returns the raw response packet — needed by callers (MX record
    /// decoding) that must re-decode a compression pointer inside an answer's rdata against the
    /// original buffer.
    pub fn query_raw(&self, qname: &str, qtype: u16) -> io::Result<(Vec<u8>, DnsMessage)> {
        // The 16-bit query id is drawn from the OS CSPRNG, not a clock reading. Without DNSSEC
        // validation the only defenses against an OFF-PATH forged answer are the unpredictability
        // of the query id and the ephemeral source port; a predictable id (e.g. derived from
        // `subsec_nanos`) collapses the id-guessing cost to near zero, so a CSPRNG id is what
        // actually raises the bar (RFC 5452). It is not a substitute for DNSSEC — an on-path
        // attacker still wins — but it removes the cheap off-path spoof.
        let id = random_txn_id()?;
        let query = encode_query(id, qname, qtype);
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(self.timeout))?;
        socket.set_write_timeout(Some(self.timeout))?;
        socket.connect(self.server)?;
        socket.send(&query)?;
        let mut buf = [0u8; 4096];
        let n = socket.recv(&mut buf)?;
        let packet = buf[..n].to_vec();
        let msg = parse_response(&packet)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        Ok((packet, msg))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-build a minimal DNS response packet: one question, then `answers` as (name, rtype,
    /// rdata) triples, using a pointer back to the question name for each answer's owner name (the
    /// common real-world shape) — exercises compression-pointer decoding.
    fn build_response(qname: &str, qtype: u16, rrs: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0x1234u16.to_be_bytes()); // id
        buf.extend_from_slice(&0x8180u16.to_be_bytes()); // flags: response, RA, no error
        buf.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        buf.extend_from_slice(&(rrs.len() as u16).to_be_bytes()); // ancount
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        let qname_offset = buf.len();
        encode_name(&mut buf, qname);
        buf.extend_from_slice(&qtype.to_be_bytes());
        buf.extend_from_slice(&CLASS_IN.to_be_bytes());
        for (rtype, rdata) in rrs {
            // owner name: a compression pointer back to the question's name.
            let ptr = 0xC000u16 | (qname_offset as u16 & 0x3FFF);
            buf.extend_from_slice(&ptr.to_be_bytes());
            buf.extend_from_slice(&rtype.to_be_bytes());
            buf.extend_from_slice(&CLASS_IN.to_be_bytes());
            buf.extend_from_slice(&300u32.to_be_bytes()); // ttl
            buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            buf.extend_from_slice(rdata);
        }
        buf
    }

    fn mx_rdata(preference: u16, exchange: &str) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(&preference.to_be_bytes());
        encode_name(&mut r, exchange);
        r
    }

    #[test]
    fn round_trips_a_single_mx_record() {
        let packet = build_response("example.org", TYPE_MX, &[(TYPE_MX, mx_rdata(10, "mail.example.org"))]);
        let msg = parse_response(&packet).expect("parses");
        assert_eq!(msg.rcode, 0);
        assert_eq!(msg.answers.len(), 1);
        let (pref, exch) = parse_mx_rdata(&packet, &msg.answers[0]).expect("mx rdata");
        assert_eq!(pref, 10);
        assert_eq!(exch, "mail.example.org");
    }

    #[test]
    fn round_trips_multiple_mx_records_with_compressed_exchange_names() {
        // The second MX's exchange name is a suffix-shared compression back into the first RR's
        // rdata — a realistic real-world response shape.
        let mut buf = Vec::new();
        buf.extend_from_slice(&0xAAAAu16.to_be_bytes());
        buf.extend_from_slice(&0x8180u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&2u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        let qname_offset = buf.len();
        encode_name(&mut buf, "example.org");
        buf.extend_from_slice(&TYPE_MX.to_be_bytes());
        buf.extend_from_slice(&CLASS_IN.to_be_bytes());

        // RR1: mx10.example.org, preference 10, exchange name spelled out in full.
        let ptr = 0xC000u16 | (qname_offset as u16);
        buf.extend_from_slice(&ptr.to_be_bytes());
        buf.extend_from_slice(&TYPE_MX.to_be_bytes());
        buf.extend_from_slice(&CLASS_IN.to_be_bytes());
        buf.extend_from_slice(&300u32.to_be_bytes());
        let exch1_label_offset = buf.len() + 4; // rdata starts after rdlength field (2 bytes pref + label start)
        let rdata1 = mx_rdata(20, "mx-a.example.org");
        buf.extend_from_slice(&(rdata1.len() as u16).to_be_bytes());
        buf.extend_from_slice(&rdata1);
        let _ = exch1_label_offset;

        // RR2: preference 5 (higher priority — lower number wins), exchange name is a fresh label
        // "mx-b" followed by a pointer back to the qname "example.org".
        let mut rdata2 = Vec::new();
        rdata2.extend_from_slice(&5u16.to_be_bytes());
        rdata2.push(4);
        rdata2.extend_from_slice(b"mx-b");
        let ptr2 = 0xC000u16 | (qname_offset as u16);
        rdata2.extend_from_slice(&ptr2.to_be_bytes());
        buf.extend_from_slice(&ptr.to_be_bytes());
        buf.extend_from_slice(&TYPE_MX.to_be_bytes());
        buf.extend_from_slice(&CLASS_IN.to_be_bytes());
        buf.extend_from_slice(&300u32.to_be_bytes());
        buf.extend_from_slice(&(rdata2.len() as u16).to_be_bytes());
        buf.extend_from_slice(&rdata2);

        let msg = parse_response(&buf).expect("parses");
        assert_eq!(msg.answers.len(), 2);
        let (p1, e1) = parse_mx_rdata(&buf, &msg.answers[0]).unwrap();
        let (p2, e2) = parse_mx_rdata(&buf, &msg.answers[1]).unwrap();
        assert_eq!((p1, e1.as_str()), (20, "mx-a.example.org"));
        assert_eq!((p2, e2.as_str()), (5, "mx-b.example.org"), "pointer-compressed exchange name resolves");
    }

    #[test]
    fn round_trips_a_record() {
        let packet = build_response("mail.example.org", TYPE_A, &[(TYPE_A, vec![203, 0, 113, 7])]);
        let msg = parse_response(&packet).unwrap();
        assert_eq!(parse_a_rdata(&msg.answers[0]), Some(Ipv4Addr::new(203, 0, 113, 7)));
    }

    #[test]
    fn round_trips_txt_record_with_multiple_strings() {
        let mut rdata = Vec::new();
        rdata.push(9);
        rdata.extend_from_slice(b"v=STSv1; ");
        rdata.push(6);
        rdata.extend_from_slice(b"id=123");
        let packet = build_response("_mta-sts.example.org", TYPE_TXT, &[(TYPE_TXT, rdata)]);
        let msg = parse_response(&packet).unwrap();
        assert_eq!(parse_txt_rdata(&msg.answers[0]), "v=STSv1; id=123");
    }

    #[test]
    fn nxdomain_rcode_yields_no_answers_not_a_parse_error() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&0x8183u16.to_be_bytes()); // rcode 3 = NXDOMAIN
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        encode_name(&mut buf, "nowhere.invalid");
        buf.extend_from_slice(&TYPE_MX.to_be_bytes());
        buf.extend_from_slice(&CLASS_IN.to_be_bytes());
        let msg = parse_response(&buf).unwrap();
        assert_eq!(msg.rcode, 3);
        assert!(msg.answers.is_empty());
    }

    #[test]
    fn truncated_packet_is_a_dns_error_not_a_panic() {
        assert_eq!(parse_response(&[0u8; 4]), Err(DnsError::Truncated));
        let packet = build_response("example.org", TYPE_MX, &[(TYPE_MX, mx_rdata(10, "mail.example.org"))]);
        // Chop the packet mid-rdata.
        assert!(parse_response(&packet[..packet.len() - 3]).is_err());
    }

    #[test]
    fn txn_id_is_not_a_constant_and_spans_the_16_bit_space() {
        // Draw many ids; a CSPRNG source yields many distinct values and both high and low bytes
        // vary. A predictable/constant id (the old `subsec_nanos & 0xFFFF` under a coarse clock, or
        // a hard-coded value) would collapse this set — this guards the off-path-spoof fix.
        let ids: std::collections::HashSet<u16> =
            (0..256).map(|_| random_txn_id().expect("csprng")).collect();
        assert!(ids.len() > 200, "CSPRNG ids should be overwhelmingly distinct, got {}", ids.len());
        assert!(ids.iter().any(|&x| x > 0x00FF), "high byte varies");
        assert!(ids.iter().any(|&x| x & 0x00FF != 0), "low byte varies");
    }

    #[test]
    fn self_referential_pointer_is_rejected_not_an_infinite_loop() {
        // A name whose very first byte points at itself must error, not hang.
        let mut buf = vec![0u8; 12];
        buf.extend_from_slice(&[0xC0, 12]); // pointer to offset 12 == itself
        assert_eq!(read_name(&buf, 12), Err(DnsError::BadPointer));
    }
}
