//! Built-in authoritative DNS server for allocated prefixes.
//!
//! Resolves `<hex>.<domain>` → `AAAA <prefix>::<hex>` purely synthetically.
//! No database lookup, no allocation check — labels are parsed as hex
//! and OR'd into the prefix network address.

use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result};
use ipnet::Ipv6Net;
use simple_dns::rdata::{RData, A, AAAA, NS, OPT, SOA};
use simple_dns::{Name, Packet, PacketFlag, Question, ResourceRecord, OPCODE, RCODE};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tracing::{debug, info, warn};

use crate::config::DnsConfig;

/// Run the authoritative DNS server on both UDP and TCP.
///
/// Binds to the configured address and serves synthetic AAAA records
/// for `<hex>.<domain>` queries. Loops forever; returns only on fatal
/// bind errors.
pub async fn run_dns_server(config: &DnsConfig, prefix: Ipv6Net) -> Result<()> {
    let udp_socket = UdpSocket::bind(&config.listen)
        .await
        .with_context(|| format!("DNS: failed to bind UDP to {}", config.listen))?;

    let tcp_listener = TcpListener::bind(&config.listen)
        .await
        .with_context(|| format!("DNS: failed to bind TCP to {}", config.listen))?;

    info!(listen = %config.listen, domains = ?config.all_domains(), prefix = %prefix, "DNS server started (UDP+TCP)");

    let config_tcp = config.clone();
    tokio::spawn(async move {
        run_tcp_listener(tcp_listener, &config_tcp, prefix).await;
    });

    let mut buf = [0u8; 512];
    loop {
        let (len, src) = match udp_socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "DNS: UDP recv_from failed");
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

        if let Err(e) = udp_socket.send_to(&response, src).await {
            warn!(error = %e, dst = %src, "DNS: UDP send_to failed");
        }
    }
}

/// Accept TCP connections and handle DNS queries (RFC 7766).
/// Each query is prefixed with a 2-byte length.
async fn run_tcp_listener(listener: TcpListener, config: &DnsConfig, prefix: Ipv6Net) {
    loop {
        let (mut stream, src) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "DNS: TCP accept failed");
                continue;
            }
        };

        let config = config.clone();
        tokio::spawn(async move {
            // Read 2-byte length prefix
            let len = match stream.read_u16().await {
                Ok(l) => l as usize,
                Err(e) => {
                    debug!(error = %e, src = %src, "DNS: TCP read length failed");
                    return;
                }
            };

            if len == 0 || len > 4096 {
                debug!(len, src = %src, "DNS: TCP invalid query length");
                return;
            }

            let mut buf = vec![0u8; len];
            if let Err(e) = stream.read_exact(&mut buf).await {
                debug!(error = %e, src = %src, "DNS: TCP read query failed");
                return;
            }

            let response = match handle_query(&buf, &config, prefix) {
                Ok(resp) => resp,
                Err(e) => {
                    debug!(error = %e, src = %src, "DNS: TCP failed to handle query");
                    return;
                }
            };

            // Write 2-byte length prefix + response
            if let Err(e) = stream.write_u16(response.len() as u16).await {
                debug!(error = %e, src = %src, "DNS: TCP write length failed");
                return;
            }
            if let Err(e) = stream.write_all(&response).await {
                debug!(error = %e, src = %src, "DNS: TCP write response failed");
            }
        });
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

    // Find which domain this query belongs to
    let matched_domain = config.all_domains().into_iter().find(|d| {
        let d_lower = d.to_ascii_lowercase();
        qname_lower == d_lower || qname_lower.ends_with(&format!(".{}", d_lower))
    });

    let domain = match matched_domain {
        Some(d) => d,
        None => return build_error_response(&query, RCODE::Refused),
    };

    let domain_lower = domain.to_ascii_lowercase();
    let is_apex = qname_lower == domain_lower;
    let ns1_name = format!("ns1.{}", domain_lower);
    let is_ns1 = qname_lower == ns1_name;

    match question.qtype {
        // SOA at apex
        simple_dns::QTYPE::TYPE(simple_dns::TYPE::SOA) if is_apex => {
            build_soa_response(&query, domain, config)
        }
        // NS at apex
        simple_dns::QTYPE::TYPE(simple_dns::TYPE::NS) if is_apex => {
            build_ns_response(&query, domain, config)
        }
        // A record for ns1.<domain>
        simple_dns::QTYPE::TYPE(simple_dns::TYPE::A) if is_ns1 => {
            build_ns1_a_response(&query, domain, config)
        }
        // AAAA — either apex (NODATA) or host lookup
        simple_dns::QTYPE::TYPE(simple_dns::TYPE::AAAA) => {
            if is_apex || is_ns1 {
                build_nodata_response(&query, domain, config)
            } else {
                build_aaaa_response(&query, question, domain, config, prefix)
            }
        }
        // Any other type at apex → NODATA
        _ if is_apex => build_nodata_response(&query, domain, config),
        // ns1 exists but no matching type → NODATA
        _ if is_ns1 => build_nodata_response(&query, domain, config),
        // Any other type under zone → NODATA (name exists but no matching type)
        // unless the host label is invalid, in which case NXDOMAIN
        _ => {
            let host_label = extract_host_label(&qname_lower, &domain_lower);
            match host_label {
                Some(label) if parse_host_hex(label).is_some() => {
                    build_nodata_response(&query, domain, config)
                }
                _ => build_nxdomain_response(&query, domain, config),
            }
        }
    }
}

/// Extract the host label (first label) from a qname under the domain.
/// E.g., "101.tunnel.example.org" with domain "tunnel.example.org" → "101"
fn extract_host_label<'a>(qname: &'a str, domain: &str) -> Option<&'a str> {
    let suffix = format!(".{}", domain);
    if let Some(prefix) = qname.strip_suffix(&suffix) {
        // Take the rightmost label (closest to the domain).
        // "101.domain" → "101", "foo.101.domain" → "101"
        Some(prefix.rsplit('.').next().unwrap_or(prefix))
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

/// Initialize a response packet from a query, copying the ID, question section,
/// and setting AA flag. Echoes EDNS OPT if present in the query.
fn new_response(query: &Packet, rcode: RCODE) -> Packet<'static> {
    let mut response = Packet::new_reply(query.id());
    *response.rcode_mut() = rcode;
    response.set_flags(PacketFlag::AUTHORITATIVE_ANSWER);
    response.remove_flags(PacketFlag::RECURSION_AVAILABLE);
    if query.has_flags(PacketFlag::RECURSION_DESIRED) {
        response.set_flags(PacketFlag::RECURSION_DESIRED);
    }
    // RFC 1035 §4.1.1: response MUST echo the question section
    for q in &query.questions {
        response.questions.push(q.clone().into_owned());
    }
    if query.opt().is_some() {
        *response.opt_mut() = Some(OPT {
            udp_packet_size: 512,
            version: 0,
            opt_codes: vec![],
        });
    }
    response
}

/// Build an AAAA response for a host query.
fn build_aaaa_response(
    query: &Packet,
    question: &Question,
    domain: &str,
    config: &DnsConfig,
    prefix: Ipv6Net,
) -> Result<Vec<u8>> {
    let qname = question.qname.to_string();
    let qname_lower = qname.to_ascii_lowercase();
    let domain_lower = domain.to_ascii_lowercase();

    let host_label = match extract_host_label(&qname_lower, &domain_lower) {
        Some(l) => l,
        None => return build_nxdomain_response(query, domain, config),
    };

    let host_value = match parse_host_hex(host_label) {
        Some(v) => v,
        None => return build_nxdomain_response(query, domain, config),
    };

    let addr = match resolve_host(prefix, host_value) {
        Some(a) => a,
        None => return build_nxdomain_response(query, domain, config),
    };

    let mut response = new_response(query, RCODE::NoError);

    let qname_str = question.qname.to_string();
    let name = Name::new_unchecked(&qname_str);
    let rr = ResourceRecord::new(name, simple_dns::CLASS::IN, config.ttl, RData::AAAA(AAAA { address: addr.into() }));
    response.answers.push(rr);

    Ok(response.build_bytes_vec_compressed()?)
}

/// Build an SOA response.
fn build_soa_response(query: &Packet, domain: &str, config: &DnsConfig) -> Result<Vec<u8>> {
    let mut response = new_response(query, RCODE::NoError);

    let name = Name::new_unchecked(domain);
    let soa = make_soa(domain)?;
    let rr = ResourceRecord::new(name, simple_dns::CLASS::IN, config.ttl, RData::SOA(soa));
    response.answers.push(rr);

    Ok(response.build_bytes_vec_compressed()?)
}

/// Build an NS response with optional glue A record.
fn build_ns_response(query: &Packet, domain: &str, config: &DnsConfig) -> Result<Vec<u8>> {
    let mut response = new_response(query, RCODE::NoError);

    let name = Name::new_unchecked(domain);
    let ns_name = format!("ns1.{}", domain);
    let ns = NS(Name::new_unchecked(&ns_name));
    let rr = ResourceRecord::new(name, simple_dns::CLASS::IN, config.ttl, RData::NS(ns));
    response.answers.push(rr);

    // Glue record for ns1
    if let Some(addr) = parse_ns_ipv4(config) {
        let glue_name = Name::new_unchecked(&ns_name);
        let glue = ResourceRecord::new(glue_name, simple_dns::CLASS::IN, config.ttl, RData::A(A { address: addr.into() }));
        response.additional_records.push(glue);
    }

    Ok(response.build_bytes_vec_compressed()?)
}

/// Build an A response for ns1.<domain>.
fn build_ns1_a_response(query: &Packet, domain: &str, config: &DnsConfig) -> Result<Vec<u8>> {
    let addr = match parse_ns_ipv4(config) {
        Some(a) => a,
        None => return build_nodata_response(query, domain, config),
    };

    let mut response = new_response(query, RCODE::NoError);
    let ns_name = format!("ns1.{}", domain);
    let name = Name::new_unchecked(&ns_name);
    let rr = ResourceRecord::new(name, simple_dns::CLASS::IN, config.ttl, RData::A(A { address: addr.into() }));
    response.answers.push(rr);

    Ok(response.build_bytes_vec_compressed()?)
}

/// Parse the configured ns_ipv4 address.
fn parse_ns_ipv4(config: &DnsConfig) -> Option<Ipv4Addr> {
    config.ns_ipv4.as_deref()?.parse().ok()
}

/// Build a NODATA response (name exists, no matching type): empty answer + SOA in authority.
fn build_nodata_response(query: &Packet, domain: &str, config: &DnsConfig) -> Result<Vec<u8>> {
    let mut response = new_response(query, RCODE::NoError);

    let name = Name::new_unchecked(domain);
    let soa = make_soa(domain)?;
    let rr = ResourceRecord::new(name, simple_dns::CLASS::IN, config.ttl, RData::SOA(soa));
    response.name_servers.push(rr);

    Ok(response.build_bytes_vec_compressed()?)
}

/// Build an NXDOMAIN response with SOA in authority section.
fn build_nxdomain_response(query: &Packet, domain: &str, config: &DnsConfig) -> Result<Vec<u8>> {
    let mut response = new_response(query, RCODE::NameError);

    let name = Name::new_unchecked(domain);
    let soa = make_soa(domain)?;
    let rr = ResourceRecord::new(name, simple_dns::CLASS::IN, config.ttl, RData::SOA(soa));
    response.name_servers.push(rr);

    Ok(response.build_bytes_vec_compressed()?)
}

/// Build a minimal error response (REFUSED, NOTIMP, FORMERR).
fn build_error_response(query: &Packet, rcode: RCODE) -> Result<Vec<u8>> {
    let mut response = Packet::new_reply(query.id());
    *response.rcode_mut() = rcode;
    response.remove_flags(PacketFlag::RECURSION_AVAILABLE);
    for q in &query.questions {
        response.questions.push(q.clone().into_owned());
    }
    Ok(response.build_bytes_vec_compressed()?)
}

/// Build the SOA record data. Derived from the matched domain.
fn make_soa(domain: &str) -> Result<SOA<'static>> {
    let mname = format!("ns1.{}", domain);
    let rname = format!("hostmaster.{}", domain);
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
        "2001:db8:1:2::/64".parse().unwrap()
    }

    fn test_config() -> DnsConfig {
        DnsConfig {
            enabled: true,
            domain: "tunnel.example.org".to_string(),
            listen: "0.0.0.0:53".to_string(),
            ttl: 300,
            ns_ipv4: Some("198.51.100.1".to_string()),
            extra_domains: vec![],
        }
    }

    fn test_config_multi() -> DnsConfig {
        DnsConfig {
            extra_domains: vec!["vm.example.io".to_string()],
            ..test_config()
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
        assert_eq!(addr, "2001:db8:1:2::101".parse::<Ipv6Addr>().unwrap());

        let addr = resolve_host(prefix, 2).unwrap();
        assert_eq!(addr, "2001:db8:1:2::2".parse::<Ipv6Addr>().unwrap());

        let addr = resolve_host(prefix, 0xff).unwrap();
        assert_eq!(addr, "2001:db8:1:2::ff".parse::<Ipv6Addr>().unwrap());

        let addr = resolve_host(prefix, 0xdead_beef).unwrap();
        assert_eq!(addr, "2001:db8:1:2::dead:beef".parse::<Ipv6Addr>().unwrap());
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
        let domain = "tunnel.example.org";
        assert_eq!(extract_host_label("101.tunnel.example.org", domain), Some("101"));
        assert_eq!(extract_host_label("ff.tunnel.example.org", domain), Some("ff"));
        assert_eq!(extract_host_label("tunnel.example.org", domain), None);
        // Multi-level subdomain → rightmost label
        assert_eq!(extract_host_label("a.b.tunnel.example.org", domain), Some("b"));
        assert_eq!(extract_host_label("foo.101.tunnel.example.org", domain), Some("101"));
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

        let query_bytes = build_test_query("101.tunnel.example.org", simple_dns::TYPE::AAAA);
        let response_bytes = handle_query(&query_bytes, &config, prefix).unwrap();
        let response = Packet::parse(&response_bytes).unwrap();

        assert_eq!(response.rcode(), RCODE::NoError);
        assert!(response.has_flags(PacketFlag::AUTHORITATIVE_ANSWER));
        // RFC 1035: question section must be echoed
        assert_eq!(response.questions.len(), 1);
        assert_eq!(response.questions[0].qname.to_string(), "101.tunnel.example.org");
        assert_eq!(response.answers.len(), 1);

        match &response.answers[0].rdata {
            RData::AAAA(aaaa) => {
                let addr: Ipv6Addr = aaaa.address.into();
                assert_eq!(addr, "2001:db8:1:2::101".parse::<Ipv6Addr>().unwrap());
            }
            _ => panic!("Expected AAAA record"),
        }
    }

    #[test]
    fn test_invalid_hex_nxdomain() {
        let config = test_config();
        let prefix = test_prefix();

        let query_bytes = build_test_query("xyz.tunnel.example.org", simple_dns::TYPE::AAAA);
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

        let query_bytes = build_test_query("0.tunnel.example.org", simple_dns::TYPE::AAAA);
        let response_bytes = handle_query(&query_bytes, &config, prefix).unwrap();
        let response = Packet::parse(&response_bytes).unwrap();

        assert_eq!(response.rcode(), RCODE::NameError);
    }

    #[test]
    fn test_soa_query() {
        let config = test_config();
        let prefix = test_prefix();

        let query_bytes = build_test_query("tunnel.example.org", simple_dns::TYPE::SOA);
        let response_bytes = handle_query(&query_bytes, &config, prefix).unwrap();
        let response = Packet::parse(&response_bytes).unwrap();

        assert_eq!(response.rcode(), RCODE::NoError);
        assert_eq!(response.answers.len(), 1);
        match &response.answers[0].rdata {
            RData::SOA(soa) => {
                assert_eq!(soa.mname.to_string(), "ns1.tunnel.example.org");
                assert_eq!(soa.rname.to_string(), "hostmaster.tunnel.example.org");
            }
            _ => panic!("Expected SOA record"),
        }
    }

    #[test]
    fn test_ns_query() {
        let config = test_config();
        let prefix = test_prefix();

        let query_bytes = build_test_query("tunnel.example.org", simple_dns::TYPE::NS);
        let response_bytes = handle_query(&query_bytes, &config, prefix).unwrap();
        let response = Packet::parse(&response_bytes).unwrap();

        assert_eq!(response.rcode(), RCODE::NoError);
        assert_eq!(response.answers.len(), 1);
        match &response.answers[0].rdata {
            RData::NS(ns) => {
                assert_eq!(ns.0.to_string(), "ns1.tunnel.example.org");
            }
            _ => panic!("Expected NS record"),
        }
        // Glue A record in additional section
        assert_eq!(response.additional_records.len(), 1);
        match &response.additional_records[0].rdata {
            RData::A(a) => {
                let addr: Ipv4Addr = a.address.into();
                assert_eq!(addr, "198.51.100.1".parse::<Ipv4Addr>().unwrap());
            }
            _ => panic!("Expected A glue record"),
        }
    }

    #[test]
    fn test_ns1_a_query() {
        let config = test_config();
        let prefix = test_prefix();

        let query_bytes = build_test_query("ns1.tunnel.example.org", simple_dns::TYPE::A);
        let response_bytes = handle_query(&query_bytes, &config, prefix).unwrap();
        let response = Packet::parse(&response_bytes).unwrap();

        assert_eq!(response.rcode(), RCODE::NoError);
        assert_eq!(response.answers.len(), 1);
        match &response.answers[0].rdata {
            RData::A(a) => {
                let addr: Ipv4Addr = a.address.into();
                assert_eq!(addr, "198.51.100.1".parse::<Ipv4Addr>().unwrap());
            }
            _ => panic!("Expected A record"),
        }
    }

    #[test]
    fn test_ns1_aaaa_nodata() {
        let config = test_config();
        let prefix = test_prefix();

        let query_bytes = build_test_query("ns1.tunnel.example.org", simple_dns::TYPE::AAAA);
        let response_bytes = handle_query(&query_bytes, &config, prefix).unwrap();
        let response = Packet::parse(&response_bytes).unwrap();

        assert_eq!(response.rcode(), RCODE::NoError);
        assert!(response.answers.is_empty());
    }

    #[test]
    fn test_apex_aaaa_nodata() {
        let config = test_config();
        let prefix = test_prefix();

        let query_bytes = build_test_query("tunnel.example.org", simple_dns::TYPE::AAAA);
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

    // --- Multi-domain tests ---

    #[test]
    fn test_extra_domain_aaaa() {
        let config = test_config_multi();
        let prefix = test_prefix();

        let query_bytes = build_test_query("101.vm.example.io", simple_dns::TYPE::AAAA);
        let response_bytes = handle_query(&query_bytes, &config, prefix).unwrap();
        let response = Packet::parse(&response_bytes).unwrap();

        assert_eq!(response.rcode(), RCODE::NoError);
        assert_eq!(response.answers.len(), 1);
        match &response.answers[0].rdata {
            RData::AAAA(aaaa) => {
                let addr: Ipv6Addr = aaaa.address.into();
                // Same address as primary domain
                assert_eq!(addr, "2001:db8:1:2::101".parse::<Ipv6Addr>().unwrap());
            }
            _ => panic!("Expected AAAA record"),
        }
    }

    #[test]
    fn test_extra_domain_soa() {
        let config = test_config_multi();
        let prefix = test_prefix();

        let query_bytes = build_test_query("vm.example.io", simple_dns::TYPE::SOA);
        let response_bytes = handle_query(&query_bytes, &config, prefix).unwrap();
        let response = Packet::parse(&response_bytes).unwrap();

        assert_eq!(response.rcode(), RCODE::NoError);
        assert_eq!(response.answers.len(), 1);
        match &response.answers[0].rdata {
            RData::SOA(soa) => {
                assert_eq!(soa.mname.to_string(), "ns1.vm.example.io");
                assert_eq!(soa.rname.to_string(), "hostmaster.vm.example.io");
            }
            _ => panic!("Expected SOA record"),
        }
    }

    #[test]
    fn test_extra_domain_ns() {
        let config = test_config_multi();
        let prefix = test_prefix();

        let query_bytes = build_test_query("vm.example.io", simple_dns::TYPE::NS);
        let response_bytes = handle_query(&query_bytes, &config, prefix).unwrap();
        let response = Packet::parse(&response_bytes).unwrap();

        assert_eq!(response.rcode(), RCODE::NoError);
        match &response.answers[0].rdata {
            RData::NS(ns) => {
                assert_eq!(ns.0.to_string(), "ns1.vm.example.io");
            }
            _ => panic!("Expected NS record"),
        }
    }

    #[test]
    fn test_primary_still_works_with_extra() {
        let config = test_config_multi();
        let prefix = test_prefix();

        // Primary domain still resolves
        let query_bytes = build_test_query("101.tunnel.example.org", simple_dns::TYPE::AAAA);
        let response_bytes = handle_query(&query_bytes, &config, prefix).unwrap();
        let response = Packet::parse(&response_bytes).unwrap();

        assert_eq!(response.rcode(), RCODE::NoError);
        assert_eq!(response.answers.len(), 1);
    }

    #[test]
    fn test_unrelated_domain_refused_with_extra() {
        let config = test_config_multi();
        let prefix = test_prefix();

        let query_bytes = build_test_query("other.example.com", simple_dns::TYPE::AAAA);
        let response_bytes = handle_query(&query_bytes, &config, prefix).unwrap();
        let response = Packet::parse(&response_bytes).unwrap();

        assert_eq!(response.rcode(), RCODE::Refused);
    }
}
