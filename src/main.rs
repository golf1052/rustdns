use std::env;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::str::FromStr;
use std::process;
use std::fmt::Write;
use std::time::Duration;

const DEFAULT_PORT: u16 = 53;
const DEFAULT_ID: u16 = 1337;
const HEADER_SIZE: usize = 12;

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

#[derive(Debug)]
struct Question {
    qname: Vec<u8>,
    qtype: u16,
    qclass: u16,
}

#[derive(Debug)]
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
        None => DEFAULT_PORT,
        Some(i) => server_port[i + 1..]
            .parse::<u16>()
            .expect("Port number wasn't actually a valid port number"),
    };

    let server = match colon_index {
        None => &server_port[..],
        Some(i) => &server_port[..i],
    };

    // println!("Server {}", server);
    // println!("Port Number {:?}", port_number);

    let question = create_question(name);

    let address = Ipv4Addr::from_str(server).expect("Could not parse server IP");
    let socket_addr = SocketAddrV4::new(address, port_number);

    // bind to any address on our machine
    let socket = UdpSocket::bind("0.0.0.0:0").expect("Couldn't bind to address");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set_read_timeout call failed");
    socket
        .connect(socket_addr)
        .expect("Could not connect to server");
    socket.send(&question[..]).expect("Send failed");
    let mut buf = [0; 65535];
    let received = match socket.recv(&mut buf) {
        Ok(received) => if received == 0 {
            println!("ERROR\tFailed to receive packet");
            process::exit(0);
        } else {
            received
        },
        Err(_) => {
            println!("NORESPONSE");
            process::exit(0);
        }
    };

    // println!("Received {} bytes", received);
    let raw_answer = &buf[..received];
    // dump_packet(raw_answer);

    let answer_header = get_header(raw_answer);
    // println!("{:?}", answer_header);

    if answer_header.id != DEFAULT_ID {
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

    let answer_question = get_question(raw_answer);
    // println!("{:?}", answer_question);

    let mut answer_start = (HEADER_SIZE + answer_question.qname.len() + 4) as usize;

    let answers = get_answer(raw_answer, answer_header.ancount, answer_start);
    // println!("{:?}", answers);

    let auth = if answer_header.aa == 0 {
        "nonauth"
    } else {
        "auth"
    };

    for answer in answers {
        if answer._type == 1 {
            println!("IP\t{}\t{}", get_ip(&answer.rdata), auth);
        } else if answer._type == 5 {
            println!(
                "CNAME\t{}\t{}",
                unpointerfy(raw_answer, answer_start, answer.rdlength),
                auth
            );
        }

        answer_start = answer.name.len() + 2 + 2 + 4 + 2 + answer.rdata.len();
    }
}

fn create_question(name: &str) -> Vec<u8> {
    let header = Header {
        id: DEFAULT_ID,
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

fn get_question(data: &[u8]) -> Question {
    let mut end_of_name: usize = 0;
    for i in HEADER_SIZE..data.len() {
        if data[i] == 0 {
            end_of_name = i + 1;
            break;
        }
    }

    Question {
        qname: data[HEADER_SIZE..end_of_name].to_vec(),
        qtype: to_u16(&data[end_of_name..end_of_name + 2]),
        qclass: to_u16(&data[end_of_name + 2..end_of_name + 4]),
    }
}

fn get_answer(data: &[u8], num_answers: u16, beginning_of_answer: usize) -> Vec<Answer> {
    let mut answers: Vec<Answer> = Vec::new();
    let mut answer_start: usize = beginning_of_answer;
    for _ in 0..num_answers {
        let mut end_of_name: usize = 0;
        for i in answer_start..data.len() {
            if data[i] & 0xc0 == 0xc0 {
                // i is the pointer, i + 1 is the length
                end_of_name = i + 2;
                break;
            }
            if data[i] == 0 {
                end_of_name = i + 1;
                break;
            }
        }

        let rdlength = to_u16(&data[end_of_name + 8..end_of_name + 10]);

        answers.push(Answer {
            name: data[answer_start..end_of_name].to_vec(),
            _type: to_u16(&data[end_of_name..end_of_name + 2]),
            class: to_u16(&data[end_of_name + 2..end_of_name + 4]),
            ttl: to_u32(&data[end_of_name + 4..end_of_name + 8]),
            rdlength: rdlength,
            rdata: data[end_of_name + 10..end_of_name + 10 + rdlength as usize].to_vec(),
        });

        answer_start =
            answer_start + (end_of_name - answer_start) + 2 + 2 + 4 + 2 + rdlength as usize;
    }

    answers
}

fn get_ip(rdata: &[u8]) -> String {
    let mut ip = String::new();
    for i in 0..rdata.len() {
        if i != rdata.len() - 1 {
            write!(&mut ip, "{}.", rdata[i]).expect("Couldn't write to string");
        } else {
            write!(&mut ip, "{}", rdata[i]).expect("Couldn't write to string");
        }
    }
    ip
}

fn to_u16(bytes: &[u8]) -> u16 {
    let mut value: u16 = 0;
    for byte in bytes {
        value <<= 8;
        value |= *byte as u16 & 0xff;
    }
    value
}

fn to_u32(bytes: &[u8]) -> u32 {
    let mut value: u32 = 0;
    for byte in bytes {
        value <<= 8;
        value |= *byte as u32 & 0xff;
    }
    value
}

fn unpointerfy(data: &[u8], pointer_index: usize, rdlength: u16) -> String {
    let mut found_data: Vec<u8> = Vec::new();
    for i in pointer_index..pointer_index + rdlength as usize {
        let datum = data[i];
        if datum & 0xc0 == 0xc0 {
            let offset = to_u16(&vec![datum & 0x30, data[i + 1]]);
            found_data = pointer_follower(data, offset, found_data);
        } else if datum == 0 {
            found_data.push(datum);
            break;
        }
    }
    dns_name_to_name(&found_data)
}

fn pointer_follower(data: &[u8], offset: u16, mut found_data: Vec<u8>) -> Vec<u8> {
    let mut i: usize = offset as usize;
    while i < data.len() {
        let datum: u8 = data[i];
        if datum == 0 {
            return found_data;
        } else if datum & 0xc0 == 0xc0 {
            if found_data.len() > 0 {
                println!("Found pointer at end of sequence");
                let offset: u16 = to_u16(&vec![datum & 0x30, data[i + 1]]);
                found_data = pointer_follower(data, offset, found_data);
            } else {
                panic!("This probably shouldn't happen");
            }
        } else {
            found_data.push(datum);
        }
        i += 1;
    }

    found_data
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

    #[test]
    fn test_to_u32() {
        let vec: Vec<u8> = vec![0xF, 0x42, 0x40];
        assert_eq!(1000000, to_u32(&vec));
    }
}
