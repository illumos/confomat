/*
 * Copyright 2020 Oxide Computer Company
 */

use std::net::Ipv4Addr;
use std::time::Duration;
use slog::{Logger, warn};

use reqwest::blocking::ClientBuilder;

use anyhow::{Result, bail};

pub struct IP {
    pub address: Ipv4Addr,
    pub netmask: Ipv4Addr,
}

fn sleep(ms: u64) {
    std::thread::sleep(Duration::from_millis(ms));
}

pub fn private_ip(log: &Logger) -> Result<IP> {
    let c = ClientBuilder::new()
        .timeout(Duration::from_secs(15))
        .build()?;

    let url = |p: &str| {
        format!("http://169.254.169.254/metadata/v1/{}", p)
    };

    let fetch = |p: &str| -> Result<Ipv4Addr> {
        loop {
            let res = match c.get(&url(p)).send() {
                Err(e) if e.is_timeout() => {
                    warn!(log, "metadata request timed out, retrying");
                    sleep(1);
                    continue;
                }
                Err(e) => return Err(e.into()),
                Ok(res) => res,
            };

            if !res.status().is_success() {
                bail!("metadata request failure: status {}", res.status());
            }

            return Ok(res.text()?.trim().parse()?);
        }
    };

    Ok(IP {
        address: fetch("interfaces/private/0/ipv4/address")?,
        netmask: fetch("interfaces/private/0/ipv4/netmask")?,
    })
}
