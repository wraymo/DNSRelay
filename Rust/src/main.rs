use std::{net::{SocketAddr}};
mod const_value;
use const_value::*;
mod dns_struct;
use dns_struct::*;
mod thread_pool;
use chrono::prelude::Local;
mod singleton;
use singleton::*;

fn main() {
    init();
    let playground = false;
    if playground {

    }else{
        let pool = thread_pool::ThreadPool::new(1);
        loop{
            pool.execute( ||{
                receive_message();
                println!("");
            });
        }
    }
}

fn init(){
    ServerSocket::get_instance();
    NameTable::get_instance();
    ReceiveTable::get_instance();
    CurrentState::get_instance();
    NameTable::read_from_cache();
}

fn receive_message()->Result<(),()>{
    // 等待客户端发送信息
    let mut buffer:[u8;MAX_BUFFERSIZE] = [0;MAX_BUFFERSIZE];
    let (_len,client_socket_addr) = ServerSocket::get_instance().lock().unwrap().recv_from(&mut buffer).expect("我的错?");
    println!("于{}从{}接受到一条消息.",Local::now().date(),client_socket_addr);

    // 解析所得信息.如果无法解析直接结束当前线程
    // TODO:目前仅支持RFC中A类RR
    let (dns_header,question_list,answer_list,authority_list,additional_list) = extract_all_message(&buffer)?;

    let mut message = Message::construct(dns_header,
                               question_list,
                               answer_list,
                               authority_list,
                               additional_list,
                               client_socket_addr);

    if message.dnsheader.QR() == 0 && message.dnsheader.Opcode() == 0 {
        // 1. 客户端发来的信息
        println!("接收到来自客户端的请求");
        send_answer(&mut message,client_socket_addr);
        Ok(())
    }else if message.dnsheader.QR() == 1{
        // 2. 服务端发来的信息
        println!("接收到来自远端服务器的回应");
        analyze_response(&mut message);
        Ok(())
    }else{
        // 3. 本机无法处理的信息
        println!("本机无法处理该数据包");
        Err(())
    }
}

fn send_answer( message: &mut Message,client_socket_addr:SocketAddr){
    // 无论有多少个问题暂且只先回答第一个
    if message.dnsheader.QDCOUNT == 1
        && message.question[0].QTYPE==1
        && message.question[0].QCLASS==1 {

        // 在nametable中查询对应IP地址
        let mut name = String::new();
        for &c in message.question[0].QNAME.iter() {
            if c.is_ascii_alphanumeric() {
                name.push(c as char);
            }else{
                name.push('.');
            }
        }
        name.drain(..1);

        let target_ip = NameTable::get_instance().lock().unwrap()
            .get(&name).unwrap_or(&"".to_string()).clone();
        if target_ip.is_empty() {
            // 1. 若未找到对应的IP地址,则将信息转发给远端服务器,并将客户端ID保存本地表项
            println!("未找到 {} 的ip地址.",name);
            // 使用新的ID转发给远端服务器
            let new_id = CurrentState::get_unique_id();
            ReceiveTable::insert(new_id,Record::new(client_socket_addr,message.dnsheader.ID,name));
            message.dnsheader.ID=new_id;
            let response = construct_bytestream(&message);
            ServerSocket::get_instance().lock().unwrap()
                .send_to(response.as_slice(),server_socket_addr()).unwrap();
        } else{
            // 2. 若找到对应的IP地址,则生成应答转换成字节流发回客户端
            println!("{} 的ip地址是 {}.",name,target_ip);
            let response = construct_response(&message,target_ip.as_str());
            ServerSocket::get_instance().lock().unwrap()
                .send_to(response.as_ref(),client_socket_addr).unwrap();
        }
    }else{
        // 3. 本机无法处理的信息
        println!("Cannot handle this message");
    }
}

fn construct_response(client_message:&Message,ip:&str) -> Vec<u8>{
    let mut dns_header = DNSHeader::new();
    dns_header.ID = client_message.dnsheader.ID;
    let mut message = Message::new();
    if ip == "0.0.0.0" {
        dns_header.set_second_line(1,3,0,0,0,0,0,0);
    }else{
        dns_header.set_second_line(1,0,1,0,0,1,0,0);
        dns_header.ANCOUNT = 1;

        let rdata:Vec<u8> = pton(ip);
        let qname = String::from_utf8(client_message.question[0].QNAME.clone()).unwrap();
        let answer = ResourceRecord::new(
            Vec::from(qname.clone().as_bytes()),
            1,1,86400,4,rdata);

        let answer_list = vec![answer];
        message.answer = answer_list;
    }
    message.dnsheader = dns_header;

    construct_bytestream(&message)
}

fn analyze_response(message:&mut Message){
    // 查询recor_table里记录的客户端ID号,缓存域名信息并转发给原客户端
    let record = ReceiveTable::get_instance();
    let record = record.lock().unwrap();
    let record = record.get(&message.dnsheader.ID);
     match record {
         None => {
             // do_nothing.(收取到了不正确的response
         },
         Some(record) => {
             for answer in message.answer.iter(){
                 if answer.TYPE == 1 && answer.CLASS == 1 {
                     let ip = answer.RDATA.clone();
                     let ip = ntop(ip);
                     NameTable::insert(record.name.clone(),ip);
                     break;
                 }
             }
             // 将原ID替换远端服务器发来的response发还给客户端
             message.dnsheader.ID = record.id;
             ServerSocket::get_instance().lock().unwrap()
                 .send_to(construct_bytestream(&message).as_slice(),record.sender_addr).unwrap();
         }
     }
}
