use std::net::{SocketAddr, IpAddr};
use std::fs;
use std::str::FromStr;
use std::io::prelude::*;
use std::time::Duration;

use clap::Parser;

use async_channel::unbounded as UnboundedChannel;
use async_channel::{Sender, Receiver};

use futures::future::join_all;

use trust_dns_client::client::{AsyncClient, ClientHandle};
use trust_dns_client::rr::{DNSClass, RData, Name, RecordType};
use trust_dns_client::udp::UdpClientStream;

use tokio::net::UdpSocket;

use indicatif::{ProgressBar, ProgressStyle};

use serde::Serialize;

// Domain structs
#[derive(Debug, Clone, Serialize)]
#[allow(dead_code)]
struct RootDomain {
    name: String,
    subdomains: Vec<Subdomain>,
    addresses: Vec<Address>
}

#[derive(Debug, Clone, Serialize)]
#[allow(dead_code)]
struct Subdomain {
    name: String,
    addresses: Vec<Address>
}

#[derive(Debug, Clone, Serialize)]
#[allow(dead_code)]
struct Address {
    ip: IpAddr
}

#[derive(Parser)]
#[clap(author, version, about)]
struct Args {

    #[clap(short, long, help = "What root domain to start with")]
    target: String,

    #[clap(short, long, default_value = "8.8.8.8:53", help = "What DNS resolver to use")]
    dns_resolver: SocketAddr,

    #[clap(short, long, default_value_t = 1, help = "How many tasks to spawn (even if set, will always set the amount of threads to the amount of logical cores you have available)")]
    concurrency: u8,

    #[clap(short, long, default_value = "/usr/share/dnsenum/dns.txt", help = "What file to use for getting subdomains from. One subdomain per file.")]
    subdomains_file: String,

    #[clap(short, long, default_value = "./skanuvaty.output.json", help = "Where to output the results to.")]
    output_file: String,

    #[clap(short, long, help = "If we should output a lot of log items or not")]
    verbose: bool,
}

async fn get_hostname_ips(client: &mut AsyncClient, hostname: &str) -> Option<Vec<IpAddr>> {
    match Name::from_str(&hostname) {
        Ok(hostname) => {
            let query = client.query(
                hostname,
                DNSClass::IN,
                RecordType::A,
           );

            match query.await {
                Ok(response) => {
                    let mut addresses: Vec<IpAddr> = vec![];

                    for response in response.answers() {
                        match response.data() {
                            Some(record) => {
                                match record {
                                    RData::A(record) => {
                                        addresses.push(std::net::IpAddr::V4(record.to_owned()))
                                    },
                                    _ => {},
                                }
                            },
                            None => {}
                        }
                    }

                    if addresses.len() > 0 {
                        // println!("!!!!!!!!!!!! {} existed", hostname);
                        Some(addresses)
                    } else {
                        None
                    }
                },
                Err(err) => {
                    match err.kind() {
                        trust_dns_client::error::ClientErrorKind::Timeout => {
                            // No need to log timeout errors
                            None
                        }
                        _ => {
                            println!("Query Error: {:?}", err);
                            None
                        }
                    }
                }
            }
        },
        Err(err) => {
            println!("Error creating Hostname: {:?}", err);
            None
        }
    }
}

use std::sync::Arc;
use tokio::sync::Mutex;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    // console_subscriber::init();
    let args = Args::parse();

    println!("######################");
    println!("### Target: {:?}", args.target);
    println!("### DNS resolver: {:?}", args.dns_resolver);
    println!("### Concurrency: {:?}", args.concurrency);
    println!("### Subdomains File: {:?}", args.subdomains_file);
    println!("### Output File: {:?}", args.output_file);
    println!("### Verbose: {:?}", args.verbose);
    println!("######################");

    let target = args.target;
    let dns_resolver = args.dns_resolver;
    let concurrency = args.concurrency;
    let subdomains_file = args.subdomains_file;
    let output_file = args.output_file;
    let verbose = args.verbose;

    let file_subdomains = fs::File::open(subdomains_file).expect("Couldn't read subdomains file");
    let reader = std::io::BufReader::new(file_subdomains);
    let subdomains: Vec<String> = reader.lines().map(|l| l.expect("Couldn't read line")).collect();

    let (s, r): (Sender<String>, Receiver<String>) = UnboundedChannel();


    if verbose {
        println!("# Starting scan of {}", target);
        println!("# Subdomain enumeration with {} subdomains", subdomains.len())
    }

    let progress = ProgressBar::new(subdomains.len() as u64);

    let style = ProgressStyle::default_bar();
    let style = style.template("{spinner:.red} [{elapsed_precise:.blue}] [{bar:30.cyan/blue}] {pos:.green}/{len:.green} ({eta:.yellow}) (Found: {msg})");
    let style = style.progress_chars("=> ");

    progress.set_style(style);

    progress.enable_steady_tick(100);
    progress.set_draw_delta(1000);

    let (progress_send, progress_receive): (Sender<&str>, Receiver<&str>) = UnboundedChannel();

    let found_count = Arc::new(Mutex::new(0));

    let found_count_progress = Arc::clone(&found_count);
    tokio::spawn(async move {
        loop {
            match progress_receive.recv().await {
                Ok(res) => {
                    match res {
                        "inc" => {
                            progress.inc(1);
                        },
                        "finish" => {
                            let count = found_count_progress.lock().await;
                            progress.set_message(count.to_string());
                            drop(count);

                            progress.finish();
                            progress_receive.close();
                            break
                        },
                        "found" => {
                            let count = found_count_progress.lock().await;
                            progress.set_message(count.to_string());
                            drop(count)
                        },
                        _ => {
                        }
                    }
                },
                Err(_err) => {
                    // progress.finish();
                }
            }
        }
    });

    let timeout = Duration::from_secs(1);

    // let found_subdomains = Arc::new(Mutex::new(vec![]));

    // let mut handles: Vec<tokio::task::JoinHandle<_>> = vec![];
    let mut handles: Vec<tokio::task::JoinHandle<Vec<Subdomain>>> = vec![];

    for _ in 0..concurrency {
        let r = r.clone();
        let progress_send = progress_send.clone();
        let found_count_scan = Arc::clone(&found_count);

        let stream = UdpClientStream::<UdpSocket>::with_timeout(dns_resolver, timeout);
        let client = AsyncClient::connect(stream);
        let (mut client, bg) = client.await.expect("connection failed");
        tokio::spawn(bg);

        // let found_subdomains = Arc::clone(&found_subdomains);

        let handle = tokio::spawn(async move {
            let mut found_subdomains: Vec<Subdomain> = vec![];
            loop {
                let res = r.recv().await;
                // let res = r.try_recv();
                match res {
                    Ok(host) => {
                        // if verbose {
                        //     println!("checking {}", host);
                        // }
                        let res = get_hostname_ips(&mut client, &host).await;
                        match res {
                            Some(ips) => {
                                let mut found_count = found_count_scan.lock().await;
                                *found_count += 1;
                                progress_send.send("found").await.unwrap();

                                let subdomain = Subdomain {
                                    name: host.clone(),
                                    addresses: ips.into_iter().map(|ip| {
                                        Address {
                                            ip
                                        }
                                    }).collect()
                                };
                                // let mut found_subdomains = found_subdomains.lock().unwrap();
                                found_subdomains.push(subdomain);
                                // drop(found_subdomains);
                                // recurse the enumeration
                                // for subdomain in subdomains {
                                //     let host = format!("{}.{}", subdomain, host);
                                //     s.send(host).await.unwrap();
                                // }
                                // drop(s);
                            },
                            None => {}
                        }
                        progress_send.send("inc").await.unwrap();
                    },
                    Err(_) => {
                        break;
                    }
                }
            }
            found_subdomains
        });
        handles.push(handle);
    }

    for subdomain in subdomains {
        // let host = format!("{}.{}", subdomain, target);
        let host = subdomain + "." + &target;
        s.send(host).await.unwrap();
    }
    drop(s);

    let handle = join_all(handles);
    let awaited_handles = handle.await;
    progress_send.send("finish").await.unwrap();

    let found_subdomains: Vec<Subdomain> = awaited_handles.into_iter().map(|res| {
        res.unwrap()
    }).flatten().collect();

    // let found_subdomains = found_subdomains.lock().unwrap();

    println!("######################");
    println!("### Found subdomains: {}", found_subdomains.len());
    if verbose {
        println!("{:#?}", found_subdomains);
    }
    println!("######################");

    let stream = UdpClientStream::<UdpSocket>::with_timeout(dns_resolver, timeout);
    let client = AsyncClient::connect(stream);
    let (mut client, bg) = client.await.expect("connection failed");
    tokio::spawn(bg);

    let root_addresses = get_hostname_ips(&mut client, &target).await;
    let root_addresses = match root_addresses {
        Some(root_addresses) => {
            root_addresses
        },
        None => {
            println!("Domain didn't have any addresses");
            vec![]
        }
    };
    let root_domain = RootDomain {
        name: target.to_string(),
        subdomains: found_subdomains,
        addresses: root_addresses.into_iter().map(|ip| {
            Address {
                ip
            }
        }).collect(),
    };
    let json = serde_json::to_string(&root_domain).unwrap();
    let mut file = std::fs::File::create(output_file).unwrap();
    file.write(json.as_bytes()).unwrap();
    file.flush().unwrap();
    println!("{:#?}", root_domain);
}
