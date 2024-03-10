use std::io::Cursor;

use isakmp::ikev1::session::Ikev1Session;
use isakmp::{message::IsakmpMessage, model::Identity};

const DATA: &[u8] = include_bytes!("mm.bin");

#[test]
fn test_parse_main_mode() {
    let mut reader = Cursor::new(DATA);
    let mut session = Ikev1Session::new(Identity::None).unwrap();
    let msg = IsakmpMessage::parse(&mut reader, &mut session).unwrap();
    println!("{:#?}", msg);
}
