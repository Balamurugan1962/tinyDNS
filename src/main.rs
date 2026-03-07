use std::net::UdpSocket;

fn main() {
    let server = UdpSocket::bind("localhost:1053").unwrap();
    println!("UDP Server has been started");
    let mut buf = [0u8; 512];
    server.recv_from(&mut buf).unwrap();
    println!("Received: {:?}", buf);

    let str = String::from_utf8_lossy(&buf);
    println!("Received: {}", str);
}
