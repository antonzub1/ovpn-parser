use std::str::FromStr;
use std::net::SocketAddrV4;
use std::path::PathBuf;

use strum::{Display, EnumString};

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
    pub config_type: ConfigType,
    pub dev: DevType,
    pub resolv_retry: ResolvRetry,
    pub nobind: bool,
    pub persist_key: bool,
    pub persist_tun: bool,
    pub verb: u32,
    pub remote_cert_tls: RemoteCertTLS,
    pub ping: u32,
    pub ping_restart: u32,
    pub sndbuf: u32,
    pub rcvbuf: u32,
    pub cipher: Cipher,
    pub tls_cipher: TLSCipher,
    pub proto: Proto,
    pub ca: PathBuf,
    pub cert: PathBuf,
    pub key: PathBuf,
    pub remotes: Vec<SocketAddrV4>,
    pub remote_random: bool,
}

#[derive(Debug, Default, Display, EnumString)]
pub enum DevType {
    #[default]
    #[strum(to_string="tun")]
    Tun,
    #[strum(to_string="tap")]
    Tap,
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
