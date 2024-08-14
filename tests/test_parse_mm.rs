use std::io::Cursor;

use isakmp::{
    ikev1::{codec::Ikev1Codec, session::Ikev1Session},
    message::IsakmpMessageCodec,
    model::Identity,
};

const DATA: &[u8] = include_bytes!("mm.bin");

#[test]
fn test_parse_main_mode() {
    let mut reader = Cursor::new(DATA);
    let session = Ikev1Session::new(Identity::None).unwrap();
    let msg = Ikev1Codec::new(session).decode(&mut reader).unwrap();
    println!("{:#?}", msg);
}
