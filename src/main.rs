mod format;
mod parser;

use crate::parser::parse_openvpn_config;

use clap::Parser;

use std::fs::File;
use std::io::Read;

#[derive(Parser)]
#[command(version, about)]
struct Args {
    #[arg(short, long)]
    conf: String,
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
