use clap::Parser;
use nom::branch::alt;
use nom::bytes::complete::tag;
use nom::character::complete::{digit1, line_ending, space1};
use nom::sequence::{separated_pair, terminated};
use nom::IResult;
use tracing::info;

use std::fs::{read_to_string, remove_file, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::Command;
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
    config_type: String,
    dev: String,
    resolv_retry: String,
    verb: String,
}

pub enum ResolvRetry {
    Seconds(u32),
    Infinite
}

fn parse_openvpn_config(input: &str) -> IResult<&str, OpenVPNConfig> {
    let (remainder, client) = parse_client(input)?;
    let (remainder, dev) = parse_dev(remainder)?;
    let (remainder, resolv_retry) = parse_resolv_retry(remainder)?;
    let (remainder, verb) = parse_verb(remainder)?;
    Ok((
        remainder,
        OpenVPNConfig {
            config_type: client.into(),
            dev: dev.into(),
            resolv_retry: resolv_retry.into(),
            verb: verb.into(),
        },
    ))
}

fn parse_client(input: &str) -> IResult<&str, &str> {
    terminated(tag("client"), line_ending)(input)
}

fn parse_dev(input: &str) -> IResult<&str, &str> {
    let (remainder, (_, dev)) = terminated(
        separated_pair(tag("dev"), space1, alt((tag("tun"), tag("tap")))),
        line_ending,
    )(input)?;
    Ok((remainder, dev))
}

fn parse_resolv_retry(input: &str) -> IResult<&str, &str> {
    let (remainder, (_, resolv_retry)) = terminated(
        separated_pair(tag("resolv-retry"), space1, alt((tag("infinite"), digit1))),
        line_ending,
    )(input)?;
    Ok((remainder, resolv_retry))
}

fn parse_nobind(input: &str) -> IResult<&str, &str> {
    terminated(tag("nobind"), line_ending)(input)
}

fn parse_persist_key(input: &str) -> IResult<&str, &str> {
    terminated(tag("persist-key"), line_ending)(input)
}

fn parse_persist_tun(input: &str) -> IResult<&str, &str> {
    terminated(tag("persist-tun"), line_ending)(input)
}

fn parse_verb(input: &str) -> IResult<&str, &str> {
    // TODO: Parse verbosity level with iterator combinator
    let (remainder, (_, verb)) = terminated(
        separated_pair(tag("verb"), space1, digit1),
        line_ending,
    )(input)?;
    Ok((remainder, verb))
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
    let conf = conf.as_str();
    let (_, config) =
        parse_openvpn_config(conf).expect("Failed to parse OpenVPN configuration");
    info!("config: {:?}", config);
    // info!("remainder: {}", remainder);
}
