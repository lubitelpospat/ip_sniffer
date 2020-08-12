use clap::{App, Arg};
use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::process;
use std::str::FromStr;
use std::sync::mpsc::{channel, Sender};
use std::thread;
use std::time::Duration;


const MAX_PORT: u16 = 65535;

fn main() {
    let matches = App::new("IP sniffer")
        .version("0.1.0")
        .author("SADDAM")
        .about("A simple implemetation if IP sniffer that allows to sniff TCP ports")
        .arg(
            Arg::with_name("nthreads")
                .short('j')
                .takes_value(true)
                .about("Number of threads"),
        )
        .arg(
            Arg::with_name("timeout")
                .short('t')
                .long("timeout")
                .takes_value(true)
                .about("Timeout, in seconds"),
        )
        .arg(
            Arg::new("input")
                .about("Ip address, IPv4 or IPv6")
                .index(1)
                .required(true),
        )
        .get_matches();
    let nthreads = match matches.value_of("nthreads") {
        None => 1u16,
        Some(s) => match s.parse::<u16>() {
            Ok(n) => n,
            Err(_) => {
                println!("Number of threads must be a number!");
                process::exit(0);
            }
        },
    };

    let timeout = match matches.value_of("timeout") {
        None => Duration::new(2, 0),
        Some(s) => match s.parse::<u64>() {
            Ok(n) => Duration::new(n, 0),
            Err(_) => {
                println!("Timeout must be a number!");
                process::exit(0);
            }
        },
    };

    //println!("Addr: {}", addr);
    //let args: Vec<String> = env::args().collect();

    // let program = args[0].clone();

    /*let arguments = Arguments::new(&args).unwrap_or_else(|err| {
        if err.contains("help") {
            process::exit(0);
        } else {
            eprintln!("{} has problem parsing arguments: {}", program, err);
            process::exit(0);
        }
    });*/
    //let nthreads = arguments.threads;
    //let addr = arguments.ipaddr;
    //let timeout = Duration::new(2, 0);
    let addr = IpAddr::from_str(matches.value_of("input").unwrap()).unwrap();

    println!(
        "Starting sniffing on address {} with timeout {:?} in {} threads",
        addr, timeout, nthreads
    );
    let (transmitter, resiever) = channel();
    for i in 0..nthreads {
        let tx = transmitter.clone();
        thread::spawn(move || {
            scan(tx, i, addr, nthreads, timeout);
        });
    }

    let mut out = vec![];
    drop(transmitter);
    for p in resiever {
        out.push(p);
    }

    out.sort();
    println!(" ");
    for o in out {
        println!("{} is open", o);
    }
}

fn scan(tx: Sender<u16>, start_port: u16, addr: IpAddr, num_threads: u16, duration: Duration) {
    let mut port: u16 = start_port + 1;
    loop {
        //println!("Scanning {}:{}", addr, port);
        let socket_addr = SocketAddr::new(addr, port);
        match TcpStream::connect_timeout(&socket_addr, duration) {
            Ok(_) => {
                print!(".");
                io::stdout().flush().unwrap();
                tx.send(port).unwrap();
            }
            Err(_) => {}
        }
        if MAX_PORT - port <= num_threads {
            break;
        }
        port += num_threads;
    }
}
