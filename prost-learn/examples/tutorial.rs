use prost::Message;

use prost_learn::pb::tutorial::{
    AddressBook, Person,
    person::{PhoneNumber, PhoneType},
};

fn main() {
    // 构造消息
    let mut book = AddressBook::default();
    book.people.push(Person {
        name: "Alice".to_string(),
        id: 1,
        email: "alice@example.com".to_string(),
        phones: vec![PhoneNumber {
            number: "555-1234".to_string(),
            r#type: PhoneType::Mobile as i32,
        }],
    });

    // 序列化
    let mut buf = Vec::new();
    book.encode(&mut buf).unwrap();
    println!("序列化字节数: {}", buf.len());

    // 反序列化
    let decoded = AddressBook::decode(buf.as_slice()).unwrap();
    println!("解码后人数: {}", decoded.people.len());
    println!("第一个人: {}", decoded.people[0].name);
}
