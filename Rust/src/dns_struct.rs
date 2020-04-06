#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
use std::io::Cursor;
use byteorder::*;
use std::{net::{SocketAddr}};
use std::str::FromStr;
use std::net::{IpAddr, Ipv4Addr};

// 点分十进制转u8序列
pub fn pton(ip:&str)->Vec<u8>{
    ip.split('.').map(|x|{u8::from_str(x).unwrap()}).collect()
}
pub fn ntop(ip:Vec<u8>) -> String {
    let mut res = String::new();
    for e in ip.iter(){
        res.push('.');
        res += e.to_string().as_str();
    }
    res.drain(..1);
    res
}

pub fn extract_dns_header(cursor:&mut Cursor<&[u8]>)->DNSHeader{
    DNSHeader{
        ID:cursor.read_u16::<BigEndian>().unwrap(),
        second_line:cursor.read_u16::<BigEndian>().unwrap(),
        QDCOUNT:cursor.read_u16::<BigEndian>().unwrap(),
        ANCOUNT:cursor.read_u16::<BigEndian>().unwrap(),
        NSCOUNT:cursor.read_u16::<BigEndian>().unwrap(),
        ARCOUNT:cursor.read_u16::<BigEndian>().unwrap(),
    }
}

pub fn extract_question(cursor:&mut Cursor<&[u8]>,num:u16)-> Result<Vec<Question>,()>{
    // 提取所有question
    let mut question_list:Vec<Question> = vec![];
    for _ in 0..num {
        let mut name:Vec<u8> = vec![];
        while let Ok(c) = cursor.read_u8() {
            if c==0 { // 忽视掉末尾的0
                break;
            }
            name.push(c);
        }
        let qtype = cursor.read_u16::<BigEndian>().unwrap();
        let qclass = cursor.read_u16::<BigEndian>().unwrap();
        question_list.push(Question::new(name,qtype,qclass));
    }
    Ok(question_list)
}

pub fn extract_rr(cursor:&mut Cursor<&[u8]>,num:u16) -> Result<Vec<ResourceRecord>,()> {
    let mut answer_list:Vec<ResourceRecord> = vec![];
    for _ in 0..num {
        let mut name:Vec<u8> = vec![];
        while let Ok(c) = cursor.read_u8() {
            if c==0 {
                break;
            }
            name.push(c);
        }
        // 若检测到不是A类消息,立即返回
        if name.is_empty() || name[0] == 0xc0 {
            return Err(());
        }
        let rrtype = cursor.read_u16::<BigEndian>().expect("一");
        let class = cursor.read_u16::<BigEndian>().expect("二");
        let ttl = cursor.read_u32::<BigEndian>().expect("三");
        let rd_length = cursor.read_u16::<BigEndian>().expect("四");
        let mut rd_date:Vec<u8> = vec![];
        for _ in 0..rd_length{
            rd_date.push(cursor.read_u8().unwrap());
        }
        answer_list.push(ResourceRecord::new(name,rrtype,class,ttl,rd_length,rd_date));
    }
    Ok(answer_list)
}

pub fn extract_all_message(buffer:&[u8])-> Result<(DNSHeader,Vec<Question>,Vec<ResourceRecord>,Vec<ResourceRecord>,Vec<ResourceRecord>),()> {
    // 提取所有信息
    let mut cursor = Cursor::new(buffer);

    // 提取dns头部
    let dns_header = extract_dns_header(&mut cursor);
//    println!("{:?}",dns_header);
    // 提取所有question
    let question_list = extract_question(&mut cursor,dns_header.QDCOUNT).unwrap();
//    println!("{:?}",question_list);

    // 提取所有answer
    let answer_list = extract_rr(&mut cursor,dns_header.ANCOUNT)?;
//        .("answer_list 解析错误");
//    println!("{:?}",answer_list);

    // 提取所有authority
    let authority_list = extract_rr(&mut cursor,dns_header.NSCOUNT)?;
//        .expect("authority_list 解析错误");
//    println!("{:?}",authority_list);

    // 提取所有additional
    let additional_list = extract_rr(&mut cursor,dns_header.ARCOUNT)?;
//        .expect("additional_list 解析错误");
//    println!("{:?}",additional_list);

    Ok((dns_header,question_list,answer_list,authority_list,additional_list))
}

pub fn construct_bytestream(message:&Message)->Vec<u8>{
    let mut res:Vec<u8> = vec![];

    // 构建头部
    construct_dns_header(&message.dnsheader,&mut res);

    // 构建问题列表
    construct_question(&message.question,&mut res);

    //构建RR列表
    construct_rr(&message.answer,&mut res);
    construct_rr(&message.authority,&mut res);
    construct_rr(&message.additional,&mut res);

    res
}

pub fn construct_dns_header(dns_header:&DNSHeader,res:&mut Vec<u8>){
    res.write_u16::<BigEndian>(dns_header.ID).unwrap();
    res.write_u16::<BigEndian>(dns_header.second_line).unwrap();
    res.write_u16::<BigEndian>(dns_header.QDCOUNT).unwrap();
    res.write_u16::<BigEndian>(dns_header.ANCOUNT).unwrap();
    res.write_u16::<BigEndian>(dns_header.NSCOUNT).unwrap();
    res.write_u16::<BigEndian>(dns_header.ARCOUNT).unwrap();
}

pub fn construct_question(question_list:&Vec<Question>,res:&mut Vec<u8>){
    // 提取所有question
    for i  in 0..question_list.len() {
        for &c in question_list[i].QNAME.iter() {
            res.write_u8(c).unwrap();
        }
        res.write_u8(0).unwrap(); // 名字末尾的0
        res.write_u16::<BigEndian>(question_list[i].QTYPE).unwrap();
        res.write_u16::<BigEndian>(question_list[i].QCLASS).unwrap();
    }
}

pub fn construct_rr(rr_list:&Vec<ResourceRecord>,res:&mut Vec<u8>){
    for i in 0..rr_list.len() {
        for &c in rr_list[i].NAME.iter(){
            res.write_u8(c).unwrap();
        }
        res.write_u8(0).unwrap(); // 名字末尾的0
        res.write_u16::<BigEndian>(rr_list[i].TYPE).unwrap();
        res.write_u16::<BigEndian>(rr_list[i].CLASS).unwrap();
        res.write_u32::<BigEndian>(rr_list[i].TTL).unwrap();
        res.write_u16::<BigEndian>(rr_list[i].RDLENGTH).unwrap();
        for &c in rr_list[i].RDATA.iter(){
            res.write_u8(c).unwrap();
        }
    }
}


//                                    1  1  1  1  1  1
//      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                      ID                       |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                    QDCOUNT                    |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                    ANCOUNT                    |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                    NSCOUNT                    |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                    ARCOUNT                    |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#[derive(Debug,PartialOrd, PartialEq)]
pub struct DNSHeader {
    pub ID:u16,
    pub second_line:u16,
    pub QDCOUNT:u16,
    pub ANCOUNT:u16,
    pub NSCOUNT:u16,
    pub ARCOUNT:u16,
}

impl DNSHeader {
    pub fn new()->DNSHeader{
        DNSHeader{
            ID:0,
            second_line:0,
            QDCOUNT:0,
            ANCOUNT:0,
            NSCOUNT:0,
            ARCOUNT:0,
        }
    }

    pub fn extract_from_message(buffer:&[u8]) -> DNSHeader {
        let mut cursor = Cursor::new(buffer);
        let dns_header = DNSHeader{
            ID:cursor.read_u16::<BigEndian>().unwrap(),
            second_line:cursor.read_u16::<BigEndian>().unwrap(),
            QDCOUNT:cursor.read_u16::<BigEndian>().unwrap(),
            ANCOUNT:cursor.read_u16::<BigEndian>().unwrap(),
            NSCOUNT:cursor.read_u16::<BigEndian>().unwrap(),
            ARCOUNT:cursor.read_u16::<BigEndian>().unwrap(),
        };
        dns_header
    }

    pub fn set_second_line(&mut self,QR:u16,Opcode:u16,
                           AA:u16,TC:u16,RD:u16,RA:u16,
                           Z:u16,RCODE:u16){
        //    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
        let mut res:u16 = 0;
        res |= QR << 15;
        res |= Opcode << 11;
        res |= AA << 10;
        res |= TC << 9;
        res |= RD << 8;
        res |= RA << 7;
        res |= Z << 4;
        res |= RCODE;
        self.second_line = res;
    }

    pub fn QR(&self)->u16{
        self.second_line >> 15
    }

    pub fn Opcode(&self)->u16{
        // (self.second_line  & 0b0_1111_0000_000_0000) >> 11
        (self.second_line  << 1) >> 11
    }

    pub fn AA(&self)->u16{
        // (self.second_line & 0b0_0000_1000_000_0000) >> 10
        (self.second_line << 5) >> 10
    }

    pub fn TC(&self)->u16{
        // (self.second_line & 0b0_0000_0100_000_0000) >> 9
        (self.second_line << 6) >> 9
    }

    pub fn RD(&self)->u16{
        // (self.second_line & 0b0_0000_0010_000_0000) >> 8
        (self.second_line << 7) >> 8
    }

    pub fn RA(&self)->u16{
        // (self.second_line & 0b0_0000_0001_000_0000) >> 7
        (self.second_line << 8) >> 7
    }

    pub fn Z(&self)->u16{
        // (self.second_line & 0b0_0000_0000_111_0000) >> 4
        (self.second_line << 9) >> 4
    }

    pub fn RCODE(&self)->u16{
        // (self.second_line & 0b0_0000_0000_000_1111)
        (self.second_line << 12)
    }
}

//                                    1  1  1  1  1  1
//      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                                               |
//    /                     QNAME                     /
//    /                                               /
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                     QTYPE                     |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                     QCLASS                    |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#[derive(Debug,PartialOrd, PartialEq)]
pub struct Question {
    pub QNAME:Vec<u8>,
    pub QTYPE:u16,
    pub QCLASS:u16,
}

impl Question {
    pub fn new(QNAME:Vec<u8>,QTYPE:u16,QCLASS:u16) -> Self{
        Question{
            QNAME,
            QTYPE,
            QCLASS,
        }
    }
}

//                                    1  1  1  1  1  1
//      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                                               |
//    /                                               /
//    /                      NAME                     /
//    |                                               |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                      TYPE                     |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                     CLASS                     |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                      TTL                      |
//    |                                               |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                   RDLENGTH                    |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
//    /                     RDATA                     /
//    /                                               /
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#[derive(Debug,PartialOrd, PartialEq)]
pub struct ResourceRecord {
    pub NAME:Vec<u8>,
    pub TYPE:u16,
    pub CLASS:u16,
    pub TTL:u32,
    pub RDLENGTH:u16,
    pub RDATA:Vec<u8>,
}

impl ResourceRecord {
    pub fn new(NAME:Vec<u8>,
               TYPE:u16,
               CLASS:u16,
               TTL:u32,
               RDLENGTH:u16,
               RDATA:Vec<u8>)->Self{
        ResourceRecord {
            NAME,
            TYPE,
            CLASS,
            TTL,
            RDLENGTH,
            RDATA,
        }
    }

}


/*  +---------------------+
	|        Header       |
	+---------------------+
	|       Question      | the question for the name server
	+---------------------+
	|        Answer       | RRs answering the question
	+---------------------+
	|      Authority      | RRs pointing toward an authority
	+---------------------+
	|      Additional     | RRs holding additional information
	+---------------------+  */
#[derive(Debug)]
pub struct Message{
    pub dnsheader:DNSHeader,
    pub question:Vec<Question>,
    pub answer:Vec<ResourceRecord>,
    pub authority:Vec<ResourceRecord>,
    pub additional:Vec<ResourceRecord>,
    pub sender_addr:SocketAddr,
}
impl Message {
    pub fn new()->Message{
        Message{
            dnsheader:DNSHeader::new(),
            question:vec![],
            answer:vec![],
            authority:vec![],
            additional:vec![],
            sender_addr:SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
        }
    }

    pub fn construct(dnsheader:DNSHeader,
           question:Vec<Question>,
           answer:Vec<ResourceRecord>,
           authority:Vec<ResourceRecord>,
           additional:Vec<ResourceRecord>,
           sender_addr:SocketAddr) -> Message {
        Message{
            dnsheader,
            question,
            answer,
            authority,
            additional,
            sender_addr,
        }
    }

}

#[cfg(test)]
mod test{
    use super::*;
    #[test]
    fn dns_header(){
        let mut buffer:&[u8] = &[95, 158, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, 119, 119, 119, 5, 98, 97, 105, 100, 117, 3, 99, 111, 109, 0, 0, 1, 0, 1, 0, 0];
        let dns_header = DNSHeader::extract_from_message(buffer);
        assert_eq!(dns_header,DNSHeader{ID:24478,second_line:0x0100,QDCOUNT:1,ANCOUNT: 0, NSCOUNT: 0, ARCOUNT: 0 });
    }

    #[test]
    fn extract_and_construct(){
        let mut buffer:&[u8] = &[90, 225, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 5, 98, 97, 105, 100, 117, 3, 99, 111, 109, 0, 0, 1, 0, 1];
        println!("{:?}",&buffer);
        let (dns_header,question_list,answer_list,authority_list,additional_list) = extract_all_message(&buffer);
        let message = Message::construct(dns_header,
                                         question_list,
                                         answer_list,
                                         authority_list,
                                         additional_list,
                                         SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080));
        let bytestream = construct_bytestream(&message);
        println!("{:?}",&bytestream);
        let (dns_header,question_list,answer_list,authority_list,additional_list) = extract_all_message(bytestream.as_slice());
        let second_message = Message::construct(dns_header,
                                                question_list,
                                                answer_list,
                                                authority_list,
                                                additional_list,
                                                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080));
        // Message并没有实现partial_eq(因为SocketAddr没有实现partial_eq),故无法比较
        assert_eq!(buffer,bytestream.as_slice());
    }
}