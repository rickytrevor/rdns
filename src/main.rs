use std::{collections::HashMap, fs, net::{Ipv4Addr, SocketAddrV4, UdpSocket}, sync::{Arc, Mutex}};
use std::time::{Duration, Instant};
use async_std::task;


#[derive(Debug, Clone)]
struct DnsRequest {
    id: u16,
    qr: u8,
    opcode: u8,
    aa: u8,
    tc: u8,
    rd: u8,
    ra: u8,
    z: u8,
    rcode: u8,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
    qname: String,
    qtype: u16,
    qclass: u16,
    response_data: Vec<u8>,
}

#[derive(Debug, Clone)]
struct DnsResourceRecord {
    name: String,
    rr_type: u16,
    rr_class: u16,
    ttl: u32,
    rdlength: u16,
    rdata: Vec<u8>,
}

#[derive(Debug, Clone)]
struct DnsResponseData {
    id: u16,
    flags: u8,
    questions: u16,
    answers: u16,
    authority_rrs: u16,
    additional_rrs: u16,
    query: (String, u16, u16),
    answer_records: Vec<DnsResourceRecord>,
    authority_records: Vec<DnsResourceRecord>,
    additional_records: Vec<DnsResourceRecord>,
}


impl DnsRequest {
    fn new() -> DnsRequest {
        DnsRequest {
            id: 0,
            qr: 0,
            opcode: 0,
            aa: 0,
            tc: 0,
            rd: 0,
            ra: 0,
            z: 0,
            rcode: 0,
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
            qname: String::from(""),
            qtype: 0,
            qclass: 0,
            response_data: Vec::new(),
        }
    }

    fn parse(&mut self, buf: &[u8]) {
        if buf.len() < 12 {
            panic!("Buffer too short to contain a DNS header");
        }
        self.id = (buf[0] as u16) << 8 | buf[1] as u16;
        self.qr = (buf[2] & 0b10000000) >> 7;
        self.opcode = (buf[2] & 0b01111000) >> 3;
        self.aa = (buf[2] & 0b00000100) >> 2;
        self.tc = (buf[2] & 0b00000010) >> 1;
        self.rd = buf[2] & 0b00000001;
        self.ra = (buf[3] & 0b10000000) >> 7;
        self.z = (buf[3] & 0b01110000) >> 4;
        self.rcode = buf[3] & 0b00001111;
        self.qdcount = (buf[4] as u16) << 8 | buf[5] as u16;
        self.ancount = (buf[6] as u16) << 8 | buf[7] as u16;
        self.nscount = (buf[8] as u16) << 8 | buf[9] as u16;
        self.arcount = (buf[10] as u16) << 8 | buf[11] as u16;

        let mut i = 12;
        while i < buf.len() && buf[i] != 0 {
            let mut j = buf[i] as usize;
            i += 1;
            if i + j > buf.len() {
                panic!("Buffer too short to contain qname part");
            }
            while j > 0 {
                self.qname.push(buf[i] as char);
                i += 1;
                j -= 1;
            }
            self.qname.push('.');
        }
        self.qname.pop(); // remove the last dot
        i += 1;

        if i + 4 > buf.len() {
            panic!("Buffer too short to contain qtype and qclass");
        }
        self.qtype = (buf[i] as u16) << 8 | buf[i + 1] as u16;
        self.qclass = (buf[i + 2] as u16) << 8 | buf[i + 3] as u16;
        
    }

    fn parse_response(&mut self, buf: &[u8]) {
        self.parse(buf);
        self.response_data = buf.to_vec();
    }


    fn binarize(&self) -> Vec<u8> {
        if !self.response_data.is_empty() {
            let mut response = self.response_data.clone();
            response[0] = (self.id >> 8) as u8;
            response[1] = self.id as u8;
            return response;
        }

        let mut bin = Vec::new();
        bin.push((self.id >> 8) as u8);
        bin.push(self.id as u8);
        bin.push((self.qr << 7) | (self.opcode << 3) | (self.aa << 2) | (self.tc << 1) | self.rd);
        bin.push((self.ra << 7) | (self.z << 4) | self.rcode);
        bin.push((self.qdcount >> 8) as u8);
        bin.push(self.qdcount as u8);
        bin.push((self.ancount >> 8) as u8);
        bin.push(self.ancount as u8);
        bin.push((self.nscount >> 8) as u8);
        bin.push(self.nscount as u8);
        bin.push((self.arcount >> 8) as u8);
        bin.push(self.arcount as u8);
        for part in self.qname.split('.') {
            bin.push(part.len() as u8);
            for &b in part.as_bytes() {
                bin.push(b);
            }
        }
        bin.push(0);
        bin.push((self.qtype >> 8) as u8);
        bin.push(self.qtype as u8);
        bin.push((self.qclass >> 8) as u8);
        bin.push(self.qclass as u8);
        bin
    }

    fn parse_resource_record(&self, buf: &[u8], offset: &mut usize) -> DnsResourceRecord {
        let name = self.parse_name(buf, offset);
        let rr_type = (buf[*offset] as u16) << 8 | buf[*offset + 1] as u16;
        let rr_class = (buf[*offset + 2] as u16) << 8 | buf[*offset + 3] as u16;
        let ttl = (buf[*offset + 4] as u32) << 24 | (buf[*offset + 5] as u32) << 16 | (buf[*offset + 6] as u32) << 8 | buf[*offset + 7] as u32;
        let rdlength = (buf[*offset + 8] as u16) << 8 | buf[*offset + 9] as u16;
        *offset += 10;

        let rdata = buf[*offset..(*offset + rdlength as usize)].to_vec();
        *offset += rdlength as usize;

        DnsResourceRecord {
            name,
            rr_type,
            rr_class,
            ttl,
            rdlength,
            rdata,
        }
    }

    fn parse_name(&self, buf: &[u8], offset: &mut usize) -> String {
        let mut name = String::new();
        let mut jumped = false;
        let mut jump_offset = 0;

        while buf[*offset] != 0 {
            if (buf[*offset] & 0b11000000) == 0b11000000 {
                if !jumped {
                    jump_offset = *offset + 2;
                }
                *offset = (((buf[*offset] as u16) & 0b00111111) << 8 | buf[*offset + 1] as u16) as usize;
                jumped = true;
            } else {
                let len = buf[*offset] as usize;
                *offset += 1;
                name.push_str(&String::from_utf8_lossy(&buf[*offset..*offset + len]));
                *offset += len;
                name.push('.');
            }
        }
        if !jumped {
            *offset += 1;
        } else {
            *offset = jump_offset;
        }
        name.pop(); // remove the last dot
        name
    }

    fn parse_response_data(&self) -> DnsResponseData {
        let mut offset = 12;
        let flags = (self.qr << 7) | (self.opcode << 3) | (self.aa << 2) | (self.tc << 1) | self.rd;

        offset += self.qname.len() + 2 + 4; // Skip over the question section
        
        let mut answer_records = Vec::new();
        for _ in 0..self.ancount {
            let rr = self.parse_resource_record(&self.response_data, &mut offset);
            answer_records.push(rr);
        }

        let mut authority_records = Vec::new();
        for _ in 0..self.nscount {
            let rr = self.parse_resource_record(&self.response_data, &mut offset);
            authority_records.push(rr);
        }

        let mut additional_records = Vec::new();
        for _ in 0..self.arcount {
            let rr = self.parse_resource_record(&self.response_data, &mut offset);
            additional_records.push(rr);
        }

        DnsResponseData {
            id: self.id,
            flags,
            questions: self.qdcount,
            answers: self.ancount,
            authority_rrs: self.nscount,
            additional_rrs: self.arcount,
            query: (self.qname.clone(), self.qtype, self.qclass),
            answer_records,
            authority_records,
            additional_records,
        }
    }

    fn binarize_response_data(&mut self, body: DnsResponseData){
        let mut bin = Vec::new();

        // Header
        bin.push((body.id >> 8) as u8);
        bin.push(body.id as u8);
        bin.push(body.flags);
        bin.push(0); // Placeholder for the second byte of flags and rcode
        bin.push((body.questions >> 8) as u8);
        bin.push(body.questions as u8);
        bin.push((body.answers >> 8) as u8);
        bin.push(body.answers as u8);
        bin.push((body.authority_rrs >> 8) as u8);
        bin.push(body.authority_rrs as u8);
        bin.push((body.additional_rrs >> 8) as u8);
        bin.push(body.additional_rrs as u8);

        // Question section
        for part in body.query.0.split('.') {
            bin.push(part.len() as u8);
            bin.extend_from_slice(part.as_bytes());
        }
        bin.push(0); // Null byte to terminate the QNAME
        bin.push((body.query.1 >> 8) as u8);
        bin.push(body.query.1 as u8);
        bin.push((body.query.2 >> 8) as u8);
        bin.push(body.query.2 as u8);

        // Answer section
        for record in body.answer_records {
            self.binarize_record(&record, &mut bin);
        }

        // Authority section
        for record in body.authority_records {
            self.binarize_record(&record, &mut bin);
        }

        // Additional section
        for record in body.additional_records {
            self.binarize_record(&record, &mut bin);
        }

//        self.response_data = bin.clone();
        self.response_data = bin;
}

    fn binarize_record(&self, record: &DnsResourceRecord, bin: &mut Vec<u8>) {
        // Name
        for part in record.name.split('.') {
            bin.push(part.len() as u8);
            bin.extend_from_slice(part.as_bytes());
        }
        bin.push(0); // Null byte to terminate the NAME

        // Type
        bin.push((record.rr_type >> 8) as u8);
        bin.push(record.rr_type as u8);

        // Class
        bin.push((record.rr_class >> 8) as u8);
        bin.push(record.rr_class as u8);

        // TTL
        bin.push((record.ttl >> 24) as u8);
        bin.push((record.ttl >> 16) as u8);
        bin.push((record.ttl >> 8) as u8);
        bin.push(record.ttl as u8);

        // RDLENGTH
        bin.push((record.rdlength >> 8) as u8);
        bin.push(record.rdlength as u8);

        // RDATA
        bin.extend_from_slice(&record.rdata);
    }
}




type Cache = Arc<Mutex<HashMap<String, Vec<u8>>>>;

async fn remove_expired_cache(cache: Cache) {
    loop {

        task::sleep(Duration::from_secs(1)).await;
        let mut cache = cache.lock().unwrap();
        let keys: Vec<String> = cache.keys().cloned().collect();
        let now = Instant::now();

        for key in keys {
            let cached_response = cache.get(&key).cloned();
            if let Some(response_data) = cached_response {
                let mut request = DnsRequest::new();
                request.parse_response(&response_data);
                let response_data = request.parse_response_data();

                let expired = response_data.answer_records.iter().any(|record| record.ttl == 10);
                if expired {
                    cache.remove(&key);
                    println!("Took: {:?}", now.elapsed());

                }
            }
        }
    }
}

fn main() {
    let socket = UdpSocket::bind("0.0.0.0:53").unwrap();
    let google_socket = UdpSocket::bind("0.0.0.0:0").expect("Couldn't bind to Google DNS socket");
    let cache: Cache = Arc::new(Mutex::new(HashMap::new()));
    let cache_clone = Arc::clone(&cache);

    // Start the cache invalidation task
    task::spawn(remove_expired_cache(cache_clone));




    let mut testReq: DnsRequest = {
        let mut req = DnsRequest::new();
        req.id = 0x1234;
        req.qr = 1;
        req.opcode = 0;
        req.aa = 0;
        req.tc = 0;
        req.rd = 1;
        req.ra = 0;
        req.z = 0;
        req.rcode = 0;
        req.qdcount = 1;
        req.ancount = 2;
        req.nscount = 0;
        req.arcount = 0;
        req.qname = String::from("luca.civ.dev");
        req.qtype = 1;
        req.response_data = Vec::new();
        req.qclass = 1;
        req
    };
    
    // initialize a DnsResponseData struct
    let dnsRes =   DnsResponseData { id: 55804, 
        flags: 129,
         questions: 1,
          answers: 1,
           authority_rrs: 0,
            additional_rrs: 0,
             query: ("luca.civ.dev".to_string(), 1, 1),
              answer_records: 
              vec![DnsResourceRecord 
              { name: String::from("luca.civ.dev"),
               rr_type: 1,
                rr_class: 1
                , ttl: 10,
                 rdlength: 4,
                  rdata: vec![69, 69, 14, 88] }], authority_records: vec![], additional_records: vec![] 
            };
        
    // binarize the DnsResponseData struct
    testReq.binarize_response_data(dnsRes);


    {
        let mut cache = cache.lock().unwrap();
        cache.insert(String::from("luca.civ.dev"), testReq.response_data);
    }

//    remove_expired_cache(frequently_used.clone()).await;

    let mut i: u32 = 0;

    loop {
        let start = Instant::now();

        println!("Iteration: {}", i);
        i += 1;
        let mut buf = [0; 512];
        let (amt, src) = socket.recv_from(&mut buf).expect("Couldn't receive from client");
        println!("{}", src);
        let buf = &mut buf[..amt];
        let mut request = DnsRequest::new();
        
        request.parse(buf);
        let response = {
            let mut cache = cache.lock().unwrap();
            match cache.get(&request.qname) {
                Some(cached_response) => {
                    let mut cached_request = DnsRequest::new();
                    cached_request.parse_response(cached_response);

                    cached_request.id = request.id;
                    cached_request.binarize()
                }
                None => {
                    let mut res_buf = [0; 512];
                    let google_addr = SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 53);
                    google_socket.send_to(&request.binarize(), google_addr).expect("Couldn't send to Google DNS");

                    let (res_amt, _) = google_socket.recv_from(&mut res_buf).expect("Couldn't receive from Google DNS");

                    let response = res_buf[..res_amt].to_vec();
                    cache.insert(request.qname.clone(), response.clone());

                    response
                }
            }
        };
        socket.send_to(&response, src).expect("Couldn't send response to original client");

    }
}
