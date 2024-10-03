use clap::Parser;
use nom::branch::alt;
use nom::bytes::complete::tag;
use nom::character::complete::{digit1, line_ending, space1};
use nom::combinator::{map_res, opt};
use nom::sequence::{separated_pair, terminated};
use nom::{Err, IResult};
use tracing::info;

use std::fs::{read_to_string, remove_file, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::Command;
use std::str::FromStr;
use tracing_subscriber::fmt::SubscriberBuilder;

// #[derive(Parser)]
// #[command(version, about)]
// struct Args {
//     #[arg(short, long)]
//     conf: String,
// }

// fn import_connection(connection_id: &str) {
//     unimplemented!();
//     Command::new("nmcli")
//         .args(["connection", "import", "type", "openvpn", "file", &format!("{}.ovpn", connection_id)])
//         .output()
//         .expect("Failed to import connection");
// }

// fn set_connection_username(connection_id: &str, username: &str) {
//     unimplemented!();
//     Command::new("nmcli")
//         .args(["connection", "modify", "id", connection_id, "+vpn.data", &format!("username={}", username)])
//         .output()
//         .expect("Failed to set a username");
// }

// fn set_connection_password(connection_id: &str, password: &str) {
//     unimplemented!();
//     Command::new("nmcli")
//         .args(["connection", "modify", "id", &connection_id, "+vpn.secrets", &format!("password={}", password)])
//         .output()
//         .expect("Failed to set a password");
// }

#[derive(Debug)]
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
}

#[derive(Debug)]
pub enum DevType {
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

#[derive(Debug)]
pub enum ConfigType {
    Client,
    Server,
}

impl From<Option<&str>> for ConfigType {
    fn from(value: Option<&str>) -> Self {
        match value {
            Some(_) => Self::Client,
            None => Self::Server,
        }
    }
}

#[derive(Debug)]
pub enum ResolvRetry {
    Seconds(u32),
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

#[derive(Debug)]
pub enum RemoteCertTLS {
    Client,
    Server
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
#[derive(Debug)]
pub enum Cipher {
    None,
    BF_CBC,
    AES_256_GCM,
}

fn parse_openvpn_config(input: &str) -> IResult<&str, OpenVPNConfig> {
    let (remainder, config_type) = parse_config_type(input)?;
    let (remainder, dev) = parse_dev(remainder)?;
    let (remainder, resolv_retry) = parse_resolv_retry(remainder)?;
    let (remainder, nobind) = parse_nobind(remainder)?;
    let (remainder, persist_key) = parse_persist_key(remainder)?;
    let (remainder, persist_tun) = parse_persist_tun(remainder)?;
    let (remainder, verb) = parse_verb(remainder)?;
    let (remainder, remote_cert_tls) = parse_remote_cert_tls(remainder)?;
    let (remainder, ping) = parse_ping(remainder)?;
    let (remainder, ping_restart) = parse_ping_restart(remainder)?;
    let (remainder, sndbuf) = parse_sndbuf(remainder)?;
    let (remainder, rcvbuf) = parse_rcvbuf(remainder)?;
    Ok((
        remainder,
        OpenVPNConfig {
            config_type,
            dev,
            resolv_retry,
            nobind,
            persist_key,
            persist_tun,
            verb,
            remote_cert_tls,
            ping,
            ping_restart,
            sndbuf,
            rcvbuf,
        },
    ))
}

fn parse_config_type(input: &str) -> IResult<&str, ConfigType> {
    let (remainder, config_type) = opt(terminated(tag("client"), line_ending))(input)?;
    Ok((remainder, config_type.into()))
}

fn parse_dev(input: &str) -> IResult<&str, DevType> {
    let (remainder, (_, dev)) = terminated(
        separated_pair(tag("dev"), space1, alt((tag("tun"), tag("tap")))),
        line_ending,
    )(input)?;
    Ok((remainder, dev.into()))
}

fn parse_resolv_retry(input: &str) -> IResult<&str, ResolvRetry> {
    let (remainder, (_, resolv_retry)) = terminated(
        separated_pair(tag("resolv-retry"), space1, alt((tag("infinite"), digit1))),
        line_ending,
    )(input)?;
    Ok((remainder, resolv_retry.into()))
}

fn parse_nobind(input: &str) -> IResult<&str, bool> {
    let (remainder, nobind) = opt(terminated(tag("nobind"), line_ending))(input)?;
    Ok((remainder, nobind.is_some()))
}

fn parse_persist_key(input: &str) -> IResult<&str, bool> {
    let (remainder, persist_key) = opt(terminated(tag("persist-key"), line_ending))(input)?;
    Ok((remainder, persist_key.is_some()))
}

fn parse_persist_tun(input: &str) -> IResult<&str, bool> {
    let (remainder, persist_tun) = opt(terminated(tag("persist-tun"), line_ending))(input)?;
    Ok((remainder, persist_tun.is_some()))
}

fn parse_verb(input: &str) -> IResult<&str, u32> {
    // TODO: Parse verbosity level with iterator combinator
    let (remainder, (_, verb)) = terminated(
        separated_pair(
            tag("verb"),
            space1,
            map_res(digit1, |s: &str| s.parse::<u32>()),
        ),
        line_ending,
    )(input)?;
    Ok((remainder, verb))
}

fn parse_remote_cert_tls(input: &str) -> IResult<&str, RemoteCertTLS> {
    let (remainder, (_, remote_cert_tls)) = terminated(
        separated_pair(tag("remote-cert-tls"), space1, alt((tag("client"), tag("server")))),
        line_ending,
    )(input)?;
    Ok((remainder, remote_cert_tls.into()))
}

fn parse_ping(input: &str) -> IResult<&str, u32> {
    let (remainder, (_, ping)) = terminated(
        separated_pair(
            tag("ping"),
            space1,
            map_res(digit1, |s: &str| s.parse::<u32>()),
        ),
        line_ending,
    )(input)?;
    Ok((remainder, ping))
}

fn parse_ping_restart(input: &str) -> IResult<&str, u32> {
    let (remainder, (_, ping_restart)) = terminated(
        separated_pair(
            tag("ping-restart"),
            space1,
            map_res(digit1, |s: &str| s.parse::<u32>()),
        ),
        line_ending,
    )(input)?;
    Ok((remainder, ping_restart))
}

fn parse_sndbuf(input: &str) -> IResult<&str, u32> {
    let (remainder, (_, sndbuf)) = terminated(
        separated_pair(
            tag("sndbuf"),
            space1,
            map_res(digit1, |s: &str| s.parse::<u32>()),
        ),
        line_ending,
    )(input)?;
    Ok((remainder, sndbuf))
}

fn parse_rcvbuf(input: &str) -> IResult<&str, u32> {
    let (remainder, (_, rcvbuf)) = terminated(
        separated_pair(
            tag("rcvbuf"),
            space1,
            map_res(digit1, |s: &str| s.parse::<u32>()),
        ),
        line_ending,
    )(input)?;
    Ok((remainder, rcvbuf))
}

fn main() {
    // let args = Args::parse();
    // let mut conf = String::new();
    // let mut cert = String::new();

    // File::open(format!("{}/mullvad_se_mma.conf", args.conf))
    //     .expect("Failed to open a conf file")
    //     .read_to_string(&mut conf)
    //     .expect("Failed to read a conf");

    // File::open(format!("{}/mullvad_ca.crt", args.conf))
    //     .expect("Failed to open a cert file")
    //     .read_to_string(&mut cert)
    //     .expect("Failed to read a cert");

    // let auth: Vec<String> = BufReader::new(
    //     File::open(format!("{}/mullvad_userpass.txt", args.conf))
    //     .expect("Failed to open an authentication file")
    // )
    //     .lines()
    //     .map(|line| line.unwrap())
    //     .collect();

    // let connection_id = "conn";
    // let filename = format!("{}.ovpn", connection_id);
    // let mut ovpn = File::create(filename)
    //     .expect("Failed to create a file");
    // write!(&mut ovpn, "{}\n<ca>\n{}\n</ca>", conf, cert)
    //     .expect("Failed to write a temp file");
    // import_connection(connection_id);
    // set_connection_username(connection_id, &auth[0]);
    // set_connection_password(connection_id, &auth[1]);
    // remove_file("conn.ovpn").expect("Failed to remove a temporary file");

    let global_default = SubscriberBuilder::default()
        .with_level(true)
        .with_file(true)
        .finish();

    tracing::subscriber::set_global_default(global_default)
        .expect("Unable to set global subscriber.");
    let conf = read_to_string("conn.ovpn").expect("Failed to read a file");
    let (_, config) = parse_openvpn_config(&conf).expect("Failed to parse OpenVPN configuration");
    info!("config: {:?}", config);
    // info!("remainder: {}", remainder);
}
