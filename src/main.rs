use clap::Parser;

use std::fs::{ File, remove_file };
use std::io::{ BufRead, BufReader, Read, Write };
use std::process::Command;

#[derive(Parser)]
#[command(version, about)]
struct Args {
    #[arg(short, long)]
    conf: String,
}

fn import_connection(connection_id: &str) {
    Command::new("nmcli")
        .args(["connection", "import", "type", "openvpn", "file", &format!("{}.ovpn", connection_id)])
        .output()
        .expect("Failed to import connection");
}

fn set_connection_username(connection_id: &str, username: &str) {
    Command::new("nmcli")
        .args(["connection", "modify", "id", connection_id, "+vpn.data", &format!("username={}", username)])
        .output()
        .expect("Failed to set a username");
}

fn set_connection_password(connection_id: &str, password: &str) {
    Command::new("nmcli")
        .args(["connection", "modify", "id", &connection_id, "+vpn.secrets", &format!("password={}", password)])
        .output()
        .expect("Failed to set a password");
}

fn main() {
    let args = Args::parse();
    let mut conf = String::new();
    let mut cert = String::new();

    File::open(format!("{}/mullvad_se_mma.conf", args.conf))
        .expect("Failed to open a conf file")
        .read_to_string(&mut conf)
        .expect("Failed to read a conf");

    File::open(format!("{}/mullvad_ca.crt", args.conf))
        .expect("Failed to open a cert file")
        .read_to_string(&mut cert)
        .expect("Failed to read a cert");

    let auth: Vec<String> = BufReader::new(
        File::open(format!("{}/mullvad_userpass.txt", args.conf))
        .expect("Failed to open an authentication file")
    )
        .lines()
        .map(|line| line.unwrap())
        .collect();

    let connection_id = "conn";
    let filename = format!("{}.ovpn", connection_id);
    let mut ovpn = File::create(filename)
        .expect("Failed to create a file");
    write!(&mut ovpn, "{}\n<ca>\n{}\n</ca>", conf, cert)
        .expect("Failed to write a temp file");
    import_connection(connection_id);
    set_connection_username(connection_id, &auth[0]);
    set_connection_password(connection_id, &auth[1]);
    remove_file("conn.ovpn").expect("Failed to remove a temporary file");
}
