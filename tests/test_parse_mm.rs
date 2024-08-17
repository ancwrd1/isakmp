use isakmp::{
    ikev1::{codec::Ikev1Codec, session::Ikev1Session},
    message::IsakmpMessageCodec,
    model::Identity,
};

const DATA: &[u8] = include_bytes!("mm.bin");

#[test]
fn test_parse_main_mode() {
    let session = Ikev1Session::new(Identity::None).unwrap();
    let msg = Ikev1Codec::new(session).decode(DATA).unwrap();
    println!("{:#?}", msg);
}
