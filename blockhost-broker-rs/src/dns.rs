//! Built-in authoritative DNS server for allocated prefixes.
//!
//! Resolves `<hex>.<domain>` → `AAAA <prefix>::<hex>` purely synthetically.
//! No database lookup, no allocation check — labels are parsed as hex
//! and OR'd into the prefix network address.

use std::net::Ipv6Addr;

use anyhow::{Context, Result};
use ipnet::Ipv6Net;
use simple_dns::rdata::{RData, AAAA, NS, SOA};
use simple_dns::{Name, Packet, PacketFlag, Question, ResourceRecord, OPCODE, RCODE};
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

use crate::config::DnsConfig;

/// Run the authoritative DNS server.
///
/// Binds to the configured UDP address and serves synthetic AAAA records
/// for `<hex>.<domain>` queries. Loops forever; returns only on fatal
/// bind errors.
pub async fn run_dns_server(config: &DnsConfig, prefix: Ipv6Net) -> Result<()> {
    let socket = UdpSocket::bind(&config.listen)
        .await
        .with_context(|| format!("DNS: failed to bind to {}", config.listen))?;

    info!(listen = %config.listen, domain = %config.domain, prefix = %prefix, "DNS server started");

    let mut buf = [0u8; 512];
    loop {
        let (len, src) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "DNS: recv_from failed");
                continue;
            }
        };

        let response = match handle_query(&buf[..len], config, prefix) {
            Ok(resp) => resp,
            Err(e) => {
                debug!(error = %e, src = %src, "DNS: failed to handle query");
                continue;
            }
        };

        if let Err(e) = socket.send_to(&response, src).await {
            warn!(error = %e, dst = %src, "DNS: send_to failed");
        }
    }
}

/// Parse a DNS query packet and build the appropriate response.
fn handle_query(data: &[u8], config: &DnsConfig, prefix: Ipv6Net) -> Result<Vec<u8>> {
    let query = Packet::parse(data).context("malformed DNS packet")?;

    // Only handle standard queries
    if query.opcode() != OPCODE::StandardQuery {
        return build_error_response(&query, RCODE::NotImplemented);
    }

    let question = match query.questions.first() {
        Some(q) => q,
        None => return build_error_response(&query, RCODE::FormatError),
    };

    let qname = question.qname.to_string();
    let qname_lower = qname.to_ascii_lowercase();
    let domain_lower = config.domain.to_ascii_lowercase();

    // Check if query is within our zone
    let in_zone = qname_lower == domain_lower
        || qname_lower.ends_with(&format!(".{}", domain_lower));

    if !in_zone {
        return build_error_response(&query, RCODE::Refused);
    }

    let is_apex = qname_lower == domain_lower;

    match question.qtype {
        // SOA at apex
        simple_dns::QTYPE::TYPE(simple_dns::TYPE::SOA) if is_apex => {
            build_soa_response(&query, config)
        }
        // NS at apex
        simple_dns::QTYPE::TYPE(simple_dns::TYPE::NS) if is_apex => {
            build_ns_response(&query, config)
        }
        // AAAA — either apex (NODATA) or host lookup
        simple_dns::QTYPE::TYPE(simple_dns::TYPE::AAAA) => {
            if is_apex {
                build_nodata_response(&query, config)
            } else {
                build_aaaa_response(&query, question, config, prefix)
            }
        }
        // Any other type at apex → NODATA
        _ if is_apex => build_nodata_response(&query, config),
        // Any other type under zone → NODATA (name exists but no matching type)
        // unless the host label is invalid, in which case NXDOMAIN
        _ => {
            let host_label = extract_host_label(&qname_lower, &domain_lower);
            match host_label {
                Some(label) if parse_host_hex(label).is_some() => {
                    build_nodata_response(&query, config)
                }
                _ => build_nxdomain_response(&query, config),
            }
        }
    }
}

/// Extract the host label (first label) from a qname under the domain.
/// E.g., "101.blockhost.thawaras.org" with domain "blockhost.thawaras.org" → "101"
fn extract_host_label<'a>(qname: &'a str, domain: &str) -> Option<&'a str> {
    let suffix = format!(".{}", domain);
    if let Some(prefix) = qname.strip_suffix(&suffix) {
        // Only single-label hosts: no dots in the prefix
        if !prefix.contains('.') {
            Some(prefix)
        } else {
            None
        }
    } else {
        None
    }
}

/// Parse a host label as a hex number. Returns None for invalid hex or zero.
fn parse_host_hex(label: &str) -> Option<u128> {
    if label.is_empty() {
        return None;
    }
    // Reject labels longer than 32 hex chars (max u128)
    if label.len() > 32 {
        return None;
    }
    let value = u128::from_str_radix(label, 16).ok()?;
    // Reject zero
    if value == 0 {
        return None;
    }
    Some(value)
}

/// Resolve a host hex value into an IPv6 address by OR'ing with the prefix network.
fn resolve_host(prefix: Ipv6Net, host_value: u128) -> Option<Ipv6Addr> {
    let net_bits: u128 = u128::from(prefix.network());
    // Ensure host_value fits within the host part of the prefix
    let host_bits = 128 - prefix.prefix_len();
    let max_host = if host_bits == 128 {
        u128::MAX
    } else {
        (1u128 << host_bits) - 1
    };
    if host_value > max_host {
        return None;
    }
    Some(Ipv6Addr::from(net_bits | host_value))
}

/// Initialize a response packet from a query, copying the ID and setting AA flag.
fn new_response(query: &Packet, rcode: RCODE) -> Packet<'static> {
    let mut response = Packet::new_reply(query.id());
    *response.rcode_mut() = rcode;
    response.set_flags(PacketFlag::AUTHORITATIVE_ANSWER);
    response.remove_flags(PacketFlag::RECURSION_AVAILABLE);
    if query.has_flags(PacketFlag::RECURSION_DESIRED) {
        response.set_flags(PacketFlag::RECURSION_DESIRED);
    }
    response
}

/// Build an AAAA response for a host query.
fn build_aaaa_response(
    query: &Packet,
    question: &Question,
    config: &DnsConfig,
    prefix: Ipv6Net,
) -> Result<Vec<u8>> {
    let qname = question.qname.to_string();
    let qname_lower = qname.to_ascii_lowercase();
    let domain_lower = config.domain.to_ascii_lowercase();

    let host_label = match extract_host_label(&qname_lower, &domain_lower) {
        Some(l) => l,
        None => return build_nxdomain_response(query, config),
    };

    let host_value = match parse_host_hex(host_label) {
        Some(v) => v,
        None => return build_nxdomain_response(query, config),
    };

    let addr = match resolve_host(prefix, host_value) {
        Some(a) => a,
        None => return build_nxdomain_response(query, config),
    };

    let mut response = new_response(query, RCODE::NoError);

    let qname_str = question.qname.to_string();
    let name = Name::new_unchecked(&qname_str);
    let rr = ResourceRecord::new(name, simple_dns::CLASS::IN, config.ttl, RData::AAAA(AAAA { address: addr.into() }));
    response.answers.push(rr);

    Ok(response.build_bytes_vec_compressed()?)
}

/// Build an SOA response.
fn build_soa_response(query: &Packet, config: &DnsConfig) -> Result<Vec<u8>> {
    let mut response = new_response(query, RCODE::NoError);

    let name = Name::new_unchecked(&config.domain);
    let soa = make_soa(config)?;
    let rr = ResourceRecord::new(name, simple_dns::CLASS::IN, config.ttl, RData::SOA(soa));
    response.answers.push(rr);

    Ok(response.build_bytes_vec_compressed()?)
}

/// Build an NS response.
fn build_ns_response(query: &Packet, config: &DnsConfig) -> Result<Vec<u8>> {
    let mut response = new_response(query, RCODE::NoError);

    let name = Name::new_unchecked(&config.domain);
    let ns_name = format!("ns1.{}", config.domain);
    let ns = NS(Name::new_unchecked(&ns_name));
    let rr = ResourceRecord::new(name, simple_dns::CLASS::IN, config.ttl, RData::NS(ns));
    response.answers.push(rr);

    Ok(response.build_bytes_vec_compressed()?)
}

/// Build a NODATA response (name exists, no matching type): empty answer + SOA in authority.
fn build_nodata_response(query: &Packet, config: &DnsConfig) -> Result<Vec<u8>> {
    let mut response = new_response(query, RCODE::NoError);

    let name = Name::new_unchecked(&config.domain);
    let soa = make_soa(config)?;
    let rr = ResourceRecord::new(name, simple_dns::CLASS::IN, config.ttl, RData::SOA(soa));
    response.name_servers.push(rr);

    Ok(response.build_bytes_vec_compressed()?)
}

/// Build an NXDOMAIN response with SOA in authority section.
fn build_nxdomain_response(query: &Packet, config: &DnsConfig) -> Result<Vec<u8>> {
    let mut response = new_response(query, RCODE::NameError);

    let name = Name::new_unchecked(&config.domain);
    let soa = make_soa(config)?;
    let rr = ResourceRecord::new(name, simple_dns::CLASS::IN, config.ttl, RData::SOA(soa));
    response.name_servers.push(rr);

    Ok(response.build_bytes_vec_compressed()?)
}

/// Build a minimal error response (REFUSED, NOTIMP, FORMERR).
fn build_error_response(query: &Packet, rcode: RCODE) -> Result<Vec<u8>> {
    let mut response = Packet::new_reply(query.id());
    *response.rcode_mut() = rcode;
    response.remove_flags(PacketFlag::RECURSION_AVAILABLE);
    Ok(response.build_bytes_vec_compressed()?)
}

/// Build the SOA record data. Derived from the configured domain.
fn make_soa(config: &DnsConfig) -> Result<SOA<'static>> {
    let mname = format!("ns1.{}", config.domain);
    let rname = format!("hostmaster.{}", config.domain);
    Ok(SOA {
        mname: Name::new_unchecked(&mname).into_owned(),
        rname: Name::new_unchecked(&rname).into_owned(),
        serial: 1,
        refresh: 3600,
        retry: 600,
        expire: 86400,
        minimum: 300,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_prefix() -> Ipv6Net {
        "2a11:6c7:f04:276::/64".parse().unwrap()
    }

    fn test_config() -> DnsConfig {
        DnsConfig {
            enabled: true,
            domain: "blockhost.thawaras.org".to_string(),
            listen: "0.0.0.0:53".to_string(),
            ttl: 300,
        }
    }

    #[test]
    fn test_parse_host_hex_valid() {
        assert_eq!(parse_host_hex("1"), Some(1));
        assert_eq!(parse_host_hex("ff"), Some(0xff));
        assert_eq!(parse_host_hex("101"), Some(0x101));
        assert_eq!(parse_host_hex("2"), Some(2));
        assert_eq!(parse_host_hex("a"), Some(0xa));
        assert_eq!(parse_host_hex("DEAD"), Some(0xDEAD));
    }

    #[test]
    fn test_parse_host_hex_invalid() {
        assert_eq!(parse_host_hex(""), None);
        assert_eq!(parse_host_hex("0"), None);
        assert_eq!(parse_host_hex("xyz"), None);
        assert_eq!(parse_host_hex("00"), None);
        assert_eq!(parse_host_hex("0x1"), None); // "0x" prefix not accepted
        assert_eq!(parse_host_hex("g1"), None);
        // 33 hex chars = too long
        assert_eq!(parse_host_hex("1234567890abcdef1234567890abcdef1"), None);
    }

    #[test]
    fn test_resolve_host() {
        let prefix = test_prefix();

        let addr = resolve_host(prefix, 0x101).unwrap();
        assert_eq!(addr, "2a11:6c7:f04:276::101".parse::<Ipv6Addr>().unwrap());

        let addr = resolve_host(prefix, 2).unwrap();
        assert_eq!(addr, "2a11:6c7:f04:276::2".parse::<Ipv6Addr>().unwrap());

        let addr = resolve_host(prefix, 0xff).unwrap();
        assert_eq!(addr, "2a11:6c7:f04:276::ff".parse::<Ipv6Addr>().unwrap());

        let addr = resolve_host(prefix, 0xdead_beef).unwrap();
        assert_eq!(addr, "2a11:6c7:f04:276::dead:beef".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn test_resolve_host_overflow() {
        let prefix: Ipv6Net = "2001:db8::/120".parse().unwrap();
        // /120 means 8 host bits → max host value = 255
        assert!(resolve_host(prefix, 255).is_some());
        assert!(resolve_host(prefix, 256).is_none());
    }

    #[test]
    fn test_extract_host_label() {
        let domain = "blockhost.thawaras.org";
        assert_eq!(extract_host_label("101.blockhost.thawaras.org", domain), Some("101"));
        assert_eq!(extract_host_label("ff.blockhost.thawaras.org", domain), Some("ff"));
        assert_eq!(extract_host_label("blockhost.thawaras.org", domain), None);
        // Multi-level subdomain rejected
        assert_eq!(extract_host_label("a.b.blockhost.thawaras.org", domain), None);
        // Unrelated domain
        assert_eq!(extract_host_label("other.example.com", domain), None);
    }

    /// Build a DNS query packet for testing.
    fn build_test_query(qname: &str, qtype: simple_dns::TYPE) -> Vec<u8> {
        let mut packet = Packet::new_query(1234);
        let name = Name::new_unchecked(qname);
        let question = Question::new(
            name,
            simple_dns::QTYPE::TYPE(qtype),
            simple_dns::QCLASS::CLASS(simple_dns::CLASS::IN),
            false,
        );
        packet.questions.push(question);
        packet.build_bytes_vec_compressed().unwrap()
    }

    #[test]
    fn test_aaaa_query() {
        let config = test_config();
        let prefix = test_prefix();

        let query_bytes = build_test_query("101.blockhost.thawaras.org", simple_dns::TYPE::AAAA);
        let response_bytes = handle_query(&query_bytes, &config, prefix).unwrap();
        let response = Packet::parse(&response_bytes).unwrap();

        assert_eq!(response.rcode(), RCODE::NoError);
        assert!(response.has_flags(PacketFlag::AUTHORITATIVE_ANSWER));
        assert_eq!(response.answers.len(), 1);

        match &response.answers[0].rdata {
            RData::AAAA(aaaa) => {
                let addr: Ipv6Addr = aaaa.address.into();
                assert_eq!(addr, "2a11:6c7:f04:276::101".parse::<Ipv6Addr>().unwrap());
            }
            _ => panic!("Expected AAAA record"),
        }
    }

    #[test]
    fn test_invalid_hex_nxdomain() {
        let config = test_config();
        let prefix = test_prefix();

        let query_bytes = build_test_query("xyz.blockhost.thawaras.org", simple_dns::TYPE::AAAA);
        let response_bytes = handle_query(&query_bytes, &config, prefix).unwrap();
        let response = Packet::parse(&response_bytes).unwrap();

        assert_eq!(response.rcode(), RCODE::NameError);
        assert!(response.answers.is_empty());
        assert_eq!(response.name_servers.len(), 1); // SOA in authority
    }

    #[test]
    fn test_zero_host_nxdomain() {
        let config = test_config();
        let prefix = test_prefix();

        let query_bytes = build_test_query("0.blockhost.thawaras.org", simple_dns::TYPE::AAAA);
        let response_bytes = handle_query(&query_bytes, &config, prefix).unwrap();
        let response = Packet::parse(&response_bytes).unwrap();

        assert_eq!(response.rcode(), RCODE::NameError);
    }

    #[test]
    fn test_soa_query() {
        let config = test_config();
        let prefix = test_prefix();

        let query_bytes = build_test_query("blockhost.thawaras.org", simple_dns::TYPE::SOA);
        let response_bytes = handle_query(&query_bytes, &config, prefix).unwrap();
        let response = Packet::parse(&response_bytes).unwrap();

        assert_eq!(response.rcode(), RCODE::NoError);
        assert_eq!(response.answers.len(), 1);
        match &response.answers[0].rdata {
            RData::SOA(soa) => {
                assert_eq!(soa.mname.to_string(), "ns1.blockhost.thawaras.org");
                assert_eq!(soa.rname.to_string(), "hostmaster.blockhost.thawaras.org");
            }
            _ => panic!("Expected SOA record"),
        }
    }

    #[test]
    fn test_ns_query() {
        let config = test_config();
        let prefix = test_prefix();

        let query_bytes = build_test_query("blockhost.thawaras.org", simple_dns::TYPE::NS);
        let response_bytes = handle_query(&query_bytes, &config, prefix).unwrap();
        let response = Packet::parse(&response_bytes).unwrap();

        assert_eq!(response.rcode(), RCODE::NoError);
        assert_eq!(response.answers.len(), 1);
        match &response.answers[0].rdata {
            RData::NS(ns) => {
                assert_eq!(ns.0.to_string(), "ns1.blockhost.thawaras.org");
            }
            _ => panic!("Expected NS record"),
        }
    }

    #[test]
    fn test_apex_aaaa_nodata() {
        let config = test_config();
        let prefix = test_prefix();

        let query_bytes = build_test_query("blockhost.thawaras.org", simple_dns::TYPE::AAAA);
        let response_bytes = handle_query(&query_bytes, &config, prefix).unwrap();
        let response = Packet::parse(&response_bytes).unwrap();

        assert_eq!(response.rcode(), RCODE::NoError);
        assert!(response.answers.is_empty());
        assert_eq!(response.name_servers.len(), 1); // SOA in authority
    }

    #[test]
    fn test_out_of_zone_refused() {
        let config = test_config();
        let prefix = test_prefix();

        let query_bytes = build_test_query("example.com", simple_dns::TYPE::AAAA);
        let response_bytes = handle_query(&query_bytes, &config, prefix).unwrap();
        let response = Packet::parse(&response_bytes).unwrap();

        assert_eq!(response.rcode(), RCODE::Refused);
    }
}
