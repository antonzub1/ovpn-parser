use clap::Parser;
use nom::branch::{alt, permutation};
use nom::bytes::complete::tag;
use nom::character::complete::{digit1, line_ending, not_line_ending, space1};
use nom::combinator::{map_res, opt};
use nom::multi::many1;
use nom::sequence::{separated_pair, terminated};
use nom::IResult;
use tuple_conv::TupleOrVec;

use std::fs::File;
use std::io::Read;
use std::net::SocketAddrV4;
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Parser)]
#[command(version, about)]
struct Args {
    #[arg(short, long)]
    conf: String,
}

#[derive(Debug)]
pub enum OpenVPNConfigEntry {
    ConfigType(ConfigType),
    Dev(DevType),
    ResolvRetry(ResolvRetry),
    NoBind(bool),
    PersistKey(bool),
    PersistTun(bool),
    Verb(u32),
    RemoteCertTLS(RemoteCertTLS),
    Ping(u32),
    PingRestart(u32),
    SndBuf(u32),
    RcvBuf(u32),
    Cipher(Cipher),
    TLSCipher(TLSCipher),
    Proto(Proto),
    CA(PathBuf),
    Cert(PathBuf),
    Key(PathBuf),
    Remotes(Vec<SocketAddrV4>),
    RemoteRandom(bool),
}

#[derive(Debug, Default)]
pub struct OpenVPNConfig {
    config_type: ConfigType,
    dev: DevType,
    resolv_retry: ResolvRetry,
    nobind: bool,
    persist_key: bool,
    persist_tun: bool,
    verb: u32,
    remote_cert_tls: RemoteCertTLS,
    ping: u32,
    ping_restart: u32,
    sndbuf: u32,
    rcvbuf: u32,
    cipher: Cipher,
    tls_cipher: TLSCipher,
    proto: Proto,
    ca: PathBuf,
    cert: PathBuf,
    key: PathBuf,
    remotes: Vec<SocketAddrV4>,
    remote_random: bool,
}

#[derive(Debug, Default)]
pub enum DevType {
    #[default]
    Tun,
    Tap,
}

impl From<&str> for DevType {
    fn from(s: &str) -> Self {
        match s {
            "tun" => Self::Tun,
            "tap" => Self::Tap,
            _ => panic!("Invalid dev type"),
        }
    }
}

#[derive(Debug, Default)]
pub enum ConfigType {
    #[default]
    Client,
    Server,
}

impl From<&str> for ConfigType {
    fn from(s: &str) -> Self {
        match s {
            "client" => Self::Client,
            "server" => Self::Server,
            _ => panic!("Unknown config type"),
        }
    }
}

#[derive(Debug, Default)]
pub enum ResolvRetry {
    Seconds(u32),
    #[default]
    Infinite,
}

impl From<&str> for ResolvRetry {
    fn from(s: &str) -> Self {
        match s {
            "infinite" => Self::Infinite,
            seconds => Self::Seconds(u32::from_str(seconds).unwrap()),
        }
    }
}

#[derive(Debug, Default)]
pub enum RemoteCertTLS {
    #[default]
    Client,
    Server,
}

impl From<&str> for RemoteCertTLS {
    fn from(s: &str) -> Self {
        match s {
            "client" => Self::Client,
            "server" => Self::Server,
            _ => panic!("Invalid remote-cert-tls type"),
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Default)]
pub enum Cipher {
    #[default]
    None,
    AES_128_CBC,
    AES_128_CFB,
    AES_128_CFB1,
    AES_128_CFB8,
    AES_128_GCM,
    AES_128_OFB,
    AES_192_CBC,
    AES_192_CFB,
    AES_192_CFB1,
    AES_192_CFB8,
    AES_192_GCM,
    AES_192_OFB,
    AES_256_CBC,
    AES_256_CFB,
    AES_256_CFB1,
    AES_256_CFB8,
    AES_256_GCM,
    AES_256_OFB,
}

impl From<&str> for Cipher {
    fn from(s: &str) -> Self {
        match s {
            "none" => Self::None,
            "AES-128-CBC" => Self::AES_128_CBC,
            "AES-128-CFB" => Self::AES_128_CFB,
            "AES-128-CFB1" => Self::AES_128_CFB1,
            "AES-128-CFB8" => Self::AES_128_CFB8,
            "AES-128-GCM" => Self::AES_128_GCM,
            "AES-128-OFB" => Self::AES_128_OFB,
            "AES-192-CBC" => Self::AES_192_CBC,
            "AES-192-CFB" => Self::AES_192_CFB,
            "AES-192-CFB1" => Self::AES_192_CFB1,
            "AES-192-CFB8" => Self::AES_192_CFB8,
            "AES-192-GCM" => Self::AES_192_GCM,
            "AES-192-OFB" => Self::AES_192_OFB,
            "AES-256-CBC" => Self::AES_256_CBC,
            "AES-256-CFB" => Self::AES_256_CFB,
            "AES-256-CFB1" => Self::AES_256_CFB1,
            "AES-256-CFB8" => Self::AES_256_CFB8,
            "AES-256-GCM" => Self::AES_256_GCM,
            "AES-256-OFB" => Self::AES_256_OFB,
            _ => panic!("Invalid cipher type"),
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Default)]
pub enum TLSCipher {
    // TLS 1.3
    #[default]
    TLS_AES_256_GCM_SHA384,
    TLS_CHACHA20_POLY1305_SHA256,
    TLS_AES_128_GCM_SHA256,

    // TLS 1.2 and older
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
}

impl From<&str> for TLSCipher {
    fn from(s: &str) -> Self {
        match s {
            "TLS_AES_256_GCM_SHA384" => Self::TLS_AES_256_GCM_SHA384,
            "TLS_CHACHA20_POLY1305_SHA256" => Self::TLS_CHACHA20_POLY1305_SHA256,
            "TLS_AES_128_GCM_SHA256" => Self::TLS_AES_128_GCM_SHA256,

            "TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384" => {
                Self::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            }
            "TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384" => Self::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            "TLS-DHE-RSA-WITH-AES-256-GCM-SHA384" => Self::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
            "TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256" => {
                Self::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            }
            "TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256" => {
                Self::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            }
            "TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256" => {
                Self::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            }
            "TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256" => {
                Self::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            }
            "TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256" => Self::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            "TLS-DHE-RSA-WITH-AES-128-GCM-SHA256" => Self::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
            "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384" => {
                Self::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
            }
            "TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384" => Self::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
            "TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256" => {
                Self::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
            }
            "TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256" => Self::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
            "TLS-DHE-RSA-WITH-AES-128-CBC-SHA256" => Self::TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
            "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA" => Self::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            "TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA" => Self::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            "TLS-DHE-RSA-WITH-AES-256-CBC-SHA" => Self::TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
            "TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA" => Self::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            "TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA" => Self::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            "TLS-DHE-RSA-WITH-AES-128-CBC-SHA" => Self::TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
            _ => panic!("Invalid TLS cipher"),
        }
    }
}

#[derive(Debug, Default)]
pub enum Proto {
    #[default]
    TCP,
    UDP,
}

impl From<&str> for Proto {
    fn from(s: &str) -> Self {
        match s {
            "tcp" => Self::TCP,
            "udp" => Self::UDP,
            _ => panic!("Invalid proto type"),
        }
    }
}

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

fn parse_openvpn_config(input: &str) -> IResult<&str, OpenVPNConfig> {
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

fn main() {
    let args = Args::parse();
    let mut conf = String::new();

    File::open(args.conf)
        .expect("Failed to open a conf file")
        .read_to_string(&mut conf)
        .expect("Failed to read a conf");

    let (_, config) = parse_openvpn_config(&conf).expect("Failed to parse openvpn config");
    println!("Parsed OpenVPN config: {:?}", config);
}
