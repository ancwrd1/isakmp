use isakmp::{
    ikev1::{codec::Ikev1Codec, session::Ikev1Session},
    message::IsakmpMessageCodec,
    model::Identity,
    session::SessionType,
};

const DATA: &[u8] = include_bytes!("mm.bin");

#[test]
fn test_parse_main_mode() {
    let session = Box::new(Ikev1Session::new(Identity::None, SessionType::Initiator).unwrap());
    let msg = Ikev1Codec::new(session).decode(DATA).unwrap();
    println!("{msg:#?}");
}
