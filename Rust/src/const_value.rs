#![allow(dead_code)]
// 有关服务器物理硬件的相关配置
pub const MAX_BUFFERSIZE:usize = 1024;

// 有关系统配置
pub const CACHE_FILE_NAME:&str = "dns_relay.txt";
pub const HOST_UDP_SOCKET:&str= "192.168.1.15:53";
pub const SERVER_SOCKET_ADDR:&str= "192.168.1.1:53";

use std::net::{SocketAddr, Ipv4Addr, IpAddr};
pub fn server_socket_addr() -> SocketAddr {
//     不想为这个全局变量再开单例了
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 53)
}

