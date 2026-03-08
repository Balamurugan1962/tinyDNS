use std::net::UdpSocket;

// need to fetch from the system.
const UPSTREAM_DNS: &str = "8.8.8.8:53";

// Todo:
// Implement policy system.
fn is_blocked(domain: &str) -> bool {
    // need to fetch from a .policy custom file
    let blocked = ["facebook.com", "instagram.com"];
    blocked.iter().any(|d| domain.contains(d))
}

fn extract_domain(packet: &[u8]) -> String {
    let mut pos = 12;
    let mut domain = String::new();

    while pos < packet.len() {
        let len = packet[pos] as usize;
        if len == 0 {
            break;
        }

        pos += 1;

        if !domain.is_empty() {
            domain.push('.');
        }

        domain.push_str(std::str::from_utf8(&packet[pos..pos + len]).unwrap_or(""));

        pos += len;
    }

    domain
}

fn main() -> std::io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:1053")?;
    println!("DNS proxy running on port 1053");

    let upstream = UdpSocket::bind("0.0.0.0:0")?;

    let mut buf = [0u8; 512];

    loop {
        let (size, src) = socket.recv_from(&mut buf)?;
        let request = &buf[..size];

        let domain = extract_domain(request);
        println!("Query for {}", domain);

        if is_blocked(&domain) {
            println!("Blocked {}", domain);

            // simple NXDOMAIN response
            let mut response = request.to_vec();
            response[2] |= 0x80; // response flag
            response[3] = 0x83; // NXDOMAIN

            socket.send_to(&response, src)?;
            continue;
        }

        // forward to upstream
        upstream.send_to(request, UPSTREAM_DNS)?;

        let mut upstream_buf = [0u8; 512];
        let (up_size, _) = upstream.recv_from(&mut upstream_buf)?;

        socket.send_to(&upstream_buf[..up_size], src)?;
    }
}
