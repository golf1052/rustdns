use std::env;

struct Header {
    id: u16,
    qr: u8, // 1 bit
    opcode: u8, // 4 bit
    aa: u8, // 1 bit
    tc: u8, // 1 bit
    rd: u8, // 1 bit
    ra: u8, // 1 bit
    z: u8, // 3 bit
    rcode: u8, // 4 bit
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16
}

struct Question {
    qname: Vec<u8>,
    qtype: u16,
    qclass: u16
}

struct Answer {
    name: Vec<u8>,
    _type: u16,
    class: u16,
    ttl: u32,
    rdlength: u16,
    rdata: Vec<u8>
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        panic!("Minimum number of arguments not found");
    }
    let serverPort: &String = &args[1];
    let name: &String = &args[2];

    let colonIndex = serverPort.find(':');

    let portNumber: Option<u16> = match colonIndex {
        None => None,
        Some(i) => {
            Some(serverPort[i + 1..].parse::<u16>().expect("Port number wasn't actually a valid port number"))
        }
    };

    let server = match colonIndex {
        None => &serverPort[..],
        Some(i) => &serverPort[..i]
    };

    println!("Server {}", server);
    println!("Port Number {:?}", portNumber);
}
