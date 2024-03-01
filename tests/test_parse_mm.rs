use std::io::Cursor;

use isakmp::{message::IsakmpMessage, session::Ikev1Session};

const DATA: &[u8] = include_bytes!("mm.bin");

#[test]
fn test_parse_main_mode() {
    let mut reader = Cursor::new(DATA);
    let mut session = Ikev1Session::new().unwrap();
    let msg = IsakmpMessage::parse(&mut reader, &mut session).unwrap();
    println!("{:#?}", msg);
}
