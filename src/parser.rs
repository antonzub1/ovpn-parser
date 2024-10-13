use crate::format::*;

use std::str::FromStr;
use std::net::SocketAddrV4;

use nom::branch::{alt, permutation};
use nom::bytes::complete::tag;
use nom::character::complete::{digit1, line_ending, not_line_ending, space1};
use nom::combinator::{map_res, opt};
use nom::multi::many1;
use nom::sequence::{separated_pair, terminated};
use nom::IResult;

use tuple_conv::TupleOrVec;

fn parse_openvpn_config_entries(input: &str) -> IResult<&str, Vec<OpenVPNConfigEntry>> {
    let (remainder, entries) = permutation((
        parse_config_type,
        parse_dev,
        parse_resolv_retry,
        parse_persist_key,
        parse_persist_tun,
        parse_nobind,
        parse_verb,
        parse_remote_cert_tls,
        parse_ping,
        parse_ping_restart,
        parse_sndbuf,
        parse_rcvbuf,
        parse_cipher,
        parse_tls_cipher,
        parse_proto,
        parse_ca,
        parse_cert,
        parse_key,
        parse_remote_random,
        parse_remotes,
    ))(input)?;
    Ok((remainder, entries.as_vec()))
}

pub fn parse_openvpn_config(input: &str) -> IResult<&str, OpenVPNConfig> {
    let mut config = OpenVPNConfig::default();
    let (remainder, entries) = parse_openvpn_config_entries(input)?;
    for entry in entries {
        match entry {
            OpenVPNConfigEntry::ConfigType(config_type) => config.config_type = config_type,
            OpenVPNConfigEntry::Dev(dev) => config.dev = dev,
            OpenVPNConfigEntry::ResolvRetry(resolv_retry) => config.resolv_retry = resolv_retry,
            OpenVPNConfigEntry::PersistKey(persist_key) => config.persist_key = persist_key,
            OpenVPNConfigEntry::PersistTun(persist_tun) => config.persist_tun = persist_tun,
            OpenVPNConfigEntry::NoBind(nobind) => config.nobind = nobind,
            OpenVPNConfigEntry::Verb(verb) => config.verb = verb,
            OpenVPNConfigEntry::RemoteCertTLS(remote_tls_cert) => {
                config.remote_cert_tls = remote_tls_cert
            }
            OpenVPNConfigEntry::Ping(ping) => config.ping = ping,
            OpenVPNConfigEntry::PingRestart(ping_restart) => config.ping_restart = ping_restart,
            OpenVPNConfigEntry::SndBuf(sndbuf) => config.sndbuf = sndbuf,
            OpenVPNConfigEntry::RcvBuf(rcvbuf) => config.rcvbuf = rcvbuf,
            OpenVPNConfigEntry::Cipher(cipher) => config.cipher = cipher,
            OpenVPNConfigEntry::TLSCipher(tls_cipher) => config.tls_cipher = tls_cipher,
            OpenVPNConfigEntry::Proto(proto) => config.proto = proto,
            OpenVPNConfigEntry::CA(ca) => config.ca = ca,
            OpenVPNConfigEntry::Cert(cert) => config.cert = cert,
            OpenVPNConfigEntry::Key(key) => config.key = key,
            OpenVPNConfigEntry::RemoteRandom(remote_random) => config.remote_random = remote_random,
            OpenVPNConfigEntry::Remotes(remotes) => config.remotes = remotes,
        }
    }
    Ok((remainder, config))
}

fn parse_config_type(input: &str) -> IResult<&str, OpenVPNConfigEntry> {
    let (remainder, config_type) = terminated(tag("client"), line_ending)(input)?;
    Ok((
        remainder,
        OpenVPNConfigEntry::ConfigType(config_type.into()),
    ))
}

fn parse_dev(input: &str) -> IResult<&str, OpenVPNConfigEntry> {
    let (remainder, raw_entry) = terminated(not_line_ending, line_ending)(input)?;
    let (_, (_, dev)) =
        separated_pair(tag("dev"), space1, alt((tag("tun"), tag("tap"))))(raw_entry)?;
    Ok((remainder, OpenVPNConfigEntry::Dev(dev.into())))
}

fn parse_resolv_retry(input: &str) -> IResult<&str, OpenVPNConfigEntry> {
    let (remainder, raw_entry) = terminated(not_line_ending, line_ending)(input)?;
    let (_, (_, resolv_retry)) =
        separated_pair(tag("resolv-retry"), space1, alt((tag("infinite"), digit1)))(raw_entry)?;
    Ok((
        remainder,
        OpenVPNConfigEntry::ResolvRetry(resolv_retry.into()),
    ))
}

fn parse_nobind(input: &str) -> IResult<&str, OpenVPNConfigEntry> {
    let (remainder, nobind) = opt(terminated(tag("nobind"), line_ending))(input)?;
    Ok((remainder, OpenVPNConfigEntry::NoBind(nobind.is_some())))
}

fn parse_persist_key(input: &str) -> IResult<&str, OpenVPNConfigEntry> {
    let (remainder, persist_key) = opt(terminated(tag("persist-key"), line_ending))(input)?;
    Ok((
        remainder,
        OpenVPNConfigEntry::PersistKey(persist_key.is_some()),
    ))
}

fn parse_persist_tun(input: &str) -> IResult<&str, OpenVPNConfigEntry> {
    let (remainder, persist_tun) = opt(terminated(tag("persist-tun"), line_ending))(input)?;
    Ok((
        remainder,
        OpenVPNConfigEntry::PersistTun(persist_tun.is_some()),
    ))
}

fn parse_verb(input: &str) -> IResult<&str, OpenVPNConfigEntry> {
    let (remainder, raw_entry) = terminated(not_line_ending, line_ending)(input)?;
    let (_, (_, verb)) = separated_pair(
        tag("verb"),
        space1,
        map_res(digit1, |s: &str| s.parse::<u32>()),
    )(raw_entry)?;
    Ok((remainder, OpenVPNConfigEntry::Verb(verb)))
}

fn parse_remote_cert_tls(input: &str) -> IResult<&str, OpenVPNConfigEntry> {
    let (remainder, raw_entry) = terminated(not_line_ending, line_ending)(input)?;
    let (_, (_, remote_cert_tls)) = separated_pair(
        tag("remote-cert-tls"),
        space1,
        alt((tag("client"), tag("server"))),
    )(raw_entry)?;
    Ok((
        remainder,
        OpenVPNConfigEntry::RemoteCertTLS(remote_cert_tls.into()),
    ))
}

fn parse_ping(input: &str) -> IResult<&str, OpenVPNConfigEntry> {
    let (remainder, raw_entry) = terminated(not_line_ending, line_ending)(input)?;
    let (_, (_, ping)) = separated_pair(
        tag("ping"),
        space1,
        map_res(digit1, |s: &str| s.parse::<u32>()),
    )(raw_entry)?;
    Ok((remainder, OpenVPNConfigEntry::Ping(ping)))
}

fn parse_ping_restart(input: &str) -> IResult<&str, OpenVPNConfigEntry> {
    let (remainder, raw_entry) = terminated(not_line_ending, line_ending)(input)?;
    let (_, (_, ping_restart)) = separated_pair(
        tag("ping-restart"),
        space1,
        map_res(digit1, |s: &str| s.parse::<u32>()),
    )(raw_entry)?;
    Ok((remainder, OpenVPNConfigEntry::PingRestart(ping_restart)))
}

fn parse_sndbuf(input: &str) -> IResult<&str, OpenVPNConfigEntry> {
    let (remainder, raw_entry) = terminated(not_line_ending, line_ending)(input)?;
    let (_, (_, sndbuf)) = separated_pair(
        tag("sndbuf"),
        space1,
        map_res(digit1, |s: &str| s.parse::<u32>()),
    )(raw_entry)?;
    Ok((remainder, OpenVPNConfigEntry::SndBuf(sndbuf)))
}

fn parse_rcvbuf(input: &str) -> IResult<&str, OpenVPNConfigEntry> {
    let (remainder, raw_entry) = terminated(not_line_ending, line_ending)(input)?;
    let (_, (_, rcvbuf)) = separated_pair(
        tag("rcvbuf"),
        space1,
        map_res(digit1, |s: &str| s.parse::<u32>()),
    )(raw_entry)?;
    Ok((remainder, OpenVPNConfigEntry::RcvBuf(rcvbuf)))
}

fn parse_cipher(input: &str) -> IResult<&str, OpenVPNConfigEntry> {
    let (remainder, raw_entry) = terminated(not_line_ending, line_ending)(input)?;
    let (_, (_, cipher)) = separated_pair(tag("cipher"), space1, not_line_ending)(raw_entry)?;
    Ok((remainder, OpenVPNConfigEntry::Cipher(cipher.into())))
}

fn parse_tls_cipher(input: &str) -> IResult<&str, OpenVPNConfigEntry> {
    let (remainder, raw_entry) = terminated(not_line_ending, line_ending)(input)?;
    let (_, (_, tls_cipher)) =
        separated_pair(tag("tls-cipher"), space1, not_line_ending)(raw_entry)?;
    Ok((remainder, OpenVPNConfigEntry::TLSCipher(tls_cipher.into())))
}

fn parse_proto(input: &str) -> IResult<&str, OpenVPNConfigEntry> {
    let (remainder, raw_entry) = terminated(not_line_ending, line_ending)(input)?;
    let (_, (_, proto)) =
        separated_pair(tag("proto"), space1, alt((tag("tcp"), tag("udp"))))(raw_entry)?;
    Ok((remainder, OpenVPNConfigEntry::Proto(proto.into())))
}

fn parse_ca(input: &str) -> IResult<&str, OpenVPNConfigEntry> {
    let (remainder, raw_entry) = terminated(not_line_ending, line_ending)(input)?;
    let (_, (_, tls_cipher)) = separated_pair(tag("ca"), space1, not_line_ending)(raw_entry)?;
    Ok((remainder, OpenVPNConfigEntry::CA(tls_cipher.into())))
}

fn parse_cert(input: &str) -> IResult<&str, OpenVPNConfigEntry> {
    let (remainder, raw_entry) = terminated(not_line_ending, line_ending)(input)?;
    let (_, (_, cert)) = separated_pair(tag("cert"), space1, not_line_ending)(raw_entry)?;
    Ok((remainder, OpenVPNConfigEntry::Cert(cert.into())))
}

fn parse_key(input: &str) -> IResult<&str, OpenVPNConfigEntry> {
    let (remainder, raw_entry) = terminated(not_line_ending, line_ending)(input)?;
    let (_, (_, key)) = separated_pair(tag("key"), space1, not_line_ending)(raw_entry)?;
    Ok((remainder, OpenVPNConfigEntry::Key(key.into())))
}

fn parse_remote(input: &str) -> IResult<&str, SocketAddrV4> {
    let (remainder, raw_entry) = terminated(not_line_ending, line_ending)(input)?;
    let (_, (_, addr_string)) = separated_pair(tag("remote"), space1, not_line_ending)(raw_entry)?;
    let addr_string = addr_string.replace(" ", ":");
    Ok((
        remainder,
        SocketAddrV4::from_str(&addr_string).expect("Failed to parse an address"),
    ))
}

fn parse_remotes(input: &str) -> IResult<&str, OpenVPNConfigEntry> {
    let (remainder, remotes) = many1(parse_remote)(input)?;
    Ok((remainder, OpenVPNConfigEntry::Remotes(remotes)))
}

fn parse_remote_random(input: &str) -> IResult<&str, OpenVPNConfigEntry> {
    let (remainder, remote_random) = opt(terminated(tag("remote-random"), line_ending))(input)?;
    Ok((
        remainder,
        OpenVPNConfigEntry::RemoteRandom(remote_random.is_some()),
    ))
}
