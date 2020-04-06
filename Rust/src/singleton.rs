use crate::const_value::*;
use std::{fs,
          net::{UdpSocket,SocketAddr},
          collections::HashMap,
          sync::{Arc,Mutex}};


// 作为全局变量的单例模式
pub struct ServerSocket;
impl ServerSocket{
    pub fn get_instance() -> Arc<Mutex<UdpSocket>>{
        static mut SERVER_SOCKET: Option<Arc<Mutex<UdpSocket>>> = None;
        unsafe {// Rust中使用可变静态变量都是unsafe的
            SERVER_SOCKET.get_or_insert_with(|| {
                Arc::new(Mutex::new(UdpSocket::bind(HOST_UDP_SOCKET).unwrap()))}).clone()
        }
    }
}
pub struct CurrentState {
    pub current_id:u16,
    pub count:i32,
}
impl CurrentState {
    pub fn get_instance() -> Arc<Mutex<CurrentState>> {
        static mut CURRENT_STATE: Option<Arc<Mutex<CurrentState>>> = None;
        unsafe {// Rust中使用可变静态变量都是unsafe的
            CURRENT_STATE.get_or_insert_with(|| {
                Arc::new(Mutex::new(
                    CurrentState{
                        current_id:0,
                        count:0,
                    }
                ))}).clone()
        }
    }
    pub fn get_unique_id()->u16{
        let tmp = CurrentState::get_instance();
        let tmp = tmp.lock().unwrap();
        tmp.current_id
    }
}

pub struct Record {
    pub sender_addr:SocketAddr,
    pub id:u16,
    pub name:String,
}

impl Record{
    pub fn new(sender_addr:SocketAddr,
               id:u16,
               name:String)->Record{
        Record {
            sender_addr,
            id,
            name,
        }
    }
}

pub struct ReceiveTable;
impl ReceiveTable {
    pub fn get_instance() -> Arc<Mutex<HashMap<u16,Record>>> {
        static mut RECEIVE_TABLE: Option<Arc<Mutex<HashMap<u16,Record>>>> = None;
        unsafe {// Rust中使用可变静态变量都是unsafe的
            RECEIVE_TABLE.get_or_insert_with(|| {
                Arc::new(Mutex::new(HashMap::new()))
            }).clone()
        }
    }

    pub fn insert(k:u16,v:Record){
        let receive_table = Self::get_instance();
        receive_table.lock().unwrap().insert(k,v);
    }

}

pub struct NameTable;
impl NameTable {
    pub fn get_instance() -> Arc<Mutex<HashMap<String,String>>> {
        static mut NAME_TABLE: Option<Arc<Mutex<HashMap<String,String>>>> = None;
        unsafe {// Rust中使用可变静态变量都是unsafe的
            NAME_TABLE.get_or_insert_with(|| {
                Arc::new(Mutex::new(HashMap::new()))
            }).clone()
        }
    }

    pub fn read_from_cache(){
        let name_table = Self::get_instance();
        let mut name_table = name_table.lock().unwrap();

        let cache = fs::read_to_string(CACHE_FILE_NAME).unwrap();
        let mut table:HashMap<String,String>= HashMap::new();
        for line in cache.lines() {
            let line = line.to_string();
            let mid = line.find(' ').unwrap();
            table.insert(line[mid+1..].to_string(),line[0..mid].to_string());
        }
        *name_table = table;
    }

    pub fn insert(k:String,v:String){
        let name_table = Self::get_instance();
        name_table.lock().unwrap().insert(k,v);
    }

    pub fn print_table(){
        let nt = NameTable::get_instance();
        let nt = nt.lock().unwrap();
        println!("{:#?}",nt);
    }
}