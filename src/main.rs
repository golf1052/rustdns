use std::env;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::str::FromStr;
use std::process;

#[derive(Debug)]
struct Header {
    id: u16,
    qr: u8,     // 1 bit
    opcode: u8, // 4 bit
    aa: u8,     // 1 bit
    tc: u8,     // 1 bit
    rd: u8,     // 1 bit
    ra: u8,     // 1 bit
    z: u8,      // 3 bit
    rcode: u8,  // 4 bit
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

struct Question {
    qname: Vec<u8>,
    qtype: u16,
    qclass: u16,
}

struct Answer {
    name: Vec<u8>,
    _type: u16,
    class: u16,
    ttl: u32,
    rdlength: u16,
    rdata: Vec<u8>,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        panic!("Minimum number of arguments not found");
    }
    let server_port: &String = &args[1];
    let name: &String = &args[2];

    let colon_index = server_port.find(':');

    let port_number: u16 = match colon_index {
        None => 53,
        Some(i) => server_port[i + 1..]
            .parse::<u16>()
            .expect("Port number wasn't actually a valid port number"),
    };

    let server = match colon_index {
        None => &server_port[..],
        Some(i) => &server_port[..i],
    };

    println!("Server {}", server);
    println!("Port Number {:?}", port_number);

    let question = create_question(name);

    let address = Ipv4Addr::from_str(server).expect("Could not parse server IP");
    let socket_addr = SocketAddrV4::new(address, port_number);

    // bind to any address on our machine
    let socket = UdpSocket::bind("0.0.0.0:0").expect("Couldn't bind to address");
    socket
        .connect(socket_addr)
        .expect("Could not connect to server");
    socket.send(&question[..]).expect("Send failed");
    let mut buf = [0; 65535];
    let received = socket.recv(&mut buf).expect("Receive failed");
    println!("Received {} bytes", received);
    let raw_answer = &buf[..received];
    // dump_packet(raw_answer);

    let answer_header = get_header(raw_answer);
    if answer_header.id != 1337 {
        panic!(
            "Answer id ({}) did not match requested id",
            answer_header.id
        );
    }

    if answer_header.qr != 1 {
        panic!("Answer is not a response");
    }

    if answer_header.tc == 1 {
        panic!("Answer was truncated");
    }

    if answer_header.ra != 1 {
        panic!("DNS server does not support recursion");
    }

    if answer_header.rcode == 1 {
        println!("ERROR\tFormat error - The name server was unable to interpret the query.");
        process::exit(0);
    } else if answer_header.rcode == 2 {
        println!("ERROR\tServer failure - The name server was unable to process this query due to a problem with the name server.");
        process::exit(0);
    } else if answer_header.rcode == 3 {
        println!("NOTFOUND");
        process::exit(0);
    } else if answer_header.rcode == 4 {
        println!("ERROR\tNot Implemented - The name server does not support the requested kind of query.");
        process::exit(0);
    } else if answer_header.rcode == 5 {
        println!("ERROR\tRefused - The name server refuses to perform the specified operation for policy reasons.");
        process::exit(0);
    }
    println!("{:?}", answer_header);
}

fn create_question(name: &str) -> Vec<u8> {
    let header = Header {
        id: 1337,
        qr: 0,
        opcode: 0,
        aa: 0,
        tc: 0,
        rd: 1,
        ra: 0,
        z: 0,
        rcode: 0,
        qdcount: 1,
        ancount: 0,
        nscount: 0,
        arcount: 0,
    };

    let question = Question {
        qname: name_to_dns_name(name),
        qtype: 1,
        qclass: 1,
    };

    let mut question_vec: Vec<u8> = Vec::new();
    put_onto_vec(header.id, &mut question_vec);
    // since all the values before rd are 0 just push rd
    question_vec.push(header.rd);
    // ra, z, and rcode are 0
    question_vec.push(0);
    put_onto_vec(header.qdcount, &mut question_vec);
    for _ in 0..6 {
        question_vec.push(0);
    }
    question_vec.extend_from_slice(&question.qname);
    put_onto_vec(question.qtype, &mut question_vec);
    put_onto_vec(question.qclass, &mut question_vec);
    question_vec
}

fn put_onto_vec(num: u16, vec: &mut Vec<u8>) {
    vec.push(get_byte_at(num.to_be(), 0));
    vec.push(get_byte_at(num.to_be(), 1));
}

fn get_byte_at(num: u16, i: u8) -> u8 {
    ((num >> (i * 8)) & 0xff) as u8
}

fn name_to_dns_name(name: &str) -> Vec<u8> {
    let split_name: Vec<&str> = name.split('.').collect();
    let mut dns_name: Vec<u8> = Vec::new();
    for portion in split_name {
        dns_name.push(portion.len() as u8);
        dns_name.extend_from_slice(portion.as_bytes());
    }
    dns_name.push(0);
    dns_name
}

fn get_header(data: &[u8]) -> Header {
    Header {
        id: to_u16(&data[0..2]),
        qr: (data[2] & 0x80) >> 7,
        opcode: (data[2] & 0x78) >> 3,
        aa: (data[2] & 0x8) >> 3,
        tc: (data[2] & 0x2) >> 1,
        rd: data[2] & 0x1,
        ra: (data[3] & 0x80) >> 7,
        z: (data[3] & 0x70) >> 4,
        rcode: data[3] & 0xF,
        qdcount: to_u16(&data[4..6]),
        ancount: to_u16(&data[6..8]),
        nscount: to_u16(&data[8..10]),
        arcount: to_u16(&data[10..12]),
    }
}

fn to_u16(bytes: &[u8]) -> u16 {
    let mut value: u16 = 0;
    for byte in bytes {
        value <<= 8;
        value |= *byte as u16 & 0xff;
    }
    value
}

fn unpointerfy(data: &[u8]) -> Vec<u8> {
    let mut expanded_data: Vec<u8> = Vec::new();
    let mut i: usize = 0;
    while i < data.len() {
        let datum: u8 = data[i];
        if (datum & 0xc0) == 0xc0 {
            // found a pointer, follow it
            let o: u8 = data[i + 1];
            pointer_follower(&mut expanded_data, o, i as u16);
        } else {
            expanded_data.push(datum);
        }
        i += 1;
    }
    expanded_data
}

fn pointer_follower(data: &mut Vec<u8>, offset: u8, pointer_index: u16) {
    let mut found_data: Vec<u8> = Vec::new();
    let mut i: usize = offset as usize;
    while i < data.len() {
        let datum: u8 = data[i];
        if datum == 0 {
            println!("Finished following pointer");
            found_data.push(datum);
            replace_pointer(data, found_data.as_slice(), pointer_index);
            return;
        } else if datum & 0xc0 == 0xc0 {
            if found_data.len() > 0 {
                println!("Found pointer at end of sequence");
                replace_pointer(data, found_data.as_slice(), pointer_index);
                // not correctly getting last 6 bits of pointer...
                let o: u8 = data[i + 1];
                pointer_follower(data, o, i as u16);
            } else {
                panic!("This probably shouldn't happen");
            }
        } else {
            found_data.push(datum);
        }
        i += 1;
    }
}

fn replace_pointer(data: &mut Vec<u8>, to_replace: &[u8], mut index: u16) {
    println!("replace_pointer( {} )", String::from_utf8_lossy(to_replace));
    for datum in to_replace {
        data.insert(index as usize, *datum);
        index += 1;
    }
}

fn dns_name_to_name(dns_name: &[u8]) -> String {
    let mut name: String = String::new();
    let mut length: u8 = 0;
    for byte in dns_name {
        if length == 0 {
            if name.len() > 0 {
                name.push('.');
            }
            length = *byte;
            continue;
        } else {
            name.push(*byte as char);
            length -= 1;
        }
    }
    name
}

fn dump_packet(data: &[u8]) {
    let mut chars: String = String::new();
    for (i, datum) in data.iter().enumerate() {
        let i = i + 1;
        print!("{:02x}", datum);
        chars.push(get_char(*datum));
        if i % 16 == 0 {
            println!("\t{}", chars);
            chars.clear();
        } else if i % 2 == 0 {
            print!(" ");
        }
    }

    if chars.len() != 0 {
        println!("{}", chars);
    }
}

fn get_char(datum: u8) -> char {
    let c: char = datum as char;
    if c.is_alphanumeric() {
        c
    } else {
        '.'
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_dns_name_to_name() {
        let vec: Vec<u8> = vec![8, 103, 111, 108, 102, 49, 48, 53, 50, 3, 99, 111, 109];
        let name: String = dns_name_to_name(&vec);
        assert_eq!("golf1052.com", name);
    }

    #[test]
    fn test_to_u16() {
        let vec: Vec<u8> = vec![0x5, 0x39];
        assert_eq!(1337, to_u16(&vec));
    }
}
