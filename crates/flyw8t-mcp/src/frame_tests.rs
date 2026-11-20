use super::*;

fn args() -> Arguments {
    Arguments {
        session_id: Uuid::new_v4(),
        request_id: Uuid::new_v4(),
        crop: None,
    }
}

fn clear_frame() -> Vec<u8> {
    let mut png = Vec::new();
    {
        let mut enc = png::Encoder::new(&mut png, 2, 1);
        enc.set_color(png::ColorType::Rgb);
        let mut out = enc.write_header().unwrap();
        out.write_image_data(&[255, 0, 0, 0, 255, 0]).unwrap();
    }
    let mut clear = 1234u64.to_be_bytes().to_vec();
    clear.extend_from_slice(&2u32.to_be_bytes());
    clear.extend_from_slice(&1u32.to_be_bytes());
    clear.extend_from_slice(&png);
    clear
}

fn seal(client: &RequestKey, args: &Arguments) -> Envelope {
    let sender = RequestKey::generate().unwrap();
    let public_key = sender.public_key().unwrap();
    let peer = agreement::UnparsedPublicKey::new(
        &agreement::ECDH_P256,
        STANDARD.decode(client.public_key().unwrap()).unwrap(),
    );
    let secret = agreement::agree_ephemeral(sender.0, &peer, |secret| {
        aead::UnboundKey::new(&aead::AES_256_GCM, secret)
    })
    .unwrap()
    .unwrap();
    let mut ciphertext = clear_frame();
    let iv = [42; 12];
    aead::LessSafeKey::new(secret)
        .seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(iv),
            aead::Aad::from(args.aad().as_bytes()),
            &mut ciphertext,
        )
        .unwrap();
    Envelope {
        public_key,
        iv: STANDARD.encode(iv),
        ciphertext: STANDARD.encode(ciphertext),
    }
}

#[test]
fn decodes_one_png_for_the_owning_request() {
    let args = args();
    let request = RequestKey::generate().unwrap();
    let envelope = seal(&request, &args);
    let frame = request.open(envelope, &args).unwrap();
    assert_eq!(
        (frame.width, frame.height, frame.observed_at_ms),
        (2, 1, 1234)
    );
    assert_eq!(
        STANDARD.decode(frame.png).unwrap(),
        &clear_frame()[HEADER_SIZE..]
    );
}

#[test]
fn different_session_request_and_tampered_ciphertext_are_rejected() {
    let original = args();
    for (session_id, request_id) in [
        (Uuid::new_v4(), original.request_id),
        (original.session_id, Uuid::new_v4()),
    ] {
        let request = RequestKey::generate().unwrap();
        let envelope = seal(&request, &original);
        assert!(request
            .open(
                envelope,
                &Arguments {
                    session_id,
                    request_id,
                    crop: None
                }
            )
            .is_err());
    }
    let req = RequestKey::generate().unwrap();
    let mut env = seal(&req, &original);
    let mut body = STANDARD.decode(env.ciphertext).unwrap();
    body[0] ^= 1;
    env.ciphertext = STANDARD.encode(body);
    assert!(req.open(env, &original).is_err());
}

#[test]
fn rejects_malformed_images_and_invalid_crop() {
    let mut clear = clear_frame();
    clear[11] = 3;
    assert!(Frame::parse(&clear).is_err());
    clear[11] = 2;
    clear.pop();
    assert!(Frame::parse(&clear).is_err());
    assert!(Frame::parse(&vec![0; MAX_PNG + HEADER_SIZE + 1]).is_err());
    let mut args = args();
    args.crop = Some(Crop {
        x: 0.9,
        y: 0.0,
        width: 0.2,
        height: 0.5,
    });
    assert!(args.validate().is_err());
}
