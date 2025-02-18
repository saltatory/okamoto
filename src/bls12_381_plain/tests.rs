// Copyright (c) Jeffrey Hohenstein <jeffrey.hohenstein@gmail.com>
//
// All rights reserved.

use bls12_381::{G1Affine, G1Projective, G2Projective, Scalar};
use ff::Field;
use rand::rngs::ThreadRng;
use crate::bls12_381_plain::{verify_signature, Error, KeyPair, Signer, User};

#[allow(non_snake_case)]
#[test]
fn okamoto_happy_path() -> Result<(), Error> {
    let mut rng = rand::thread_rng();

    let key_pair = KeyPair::generate(&mut rng);

    let mut user = User::<ThreadRng>::new(&key_pair.public_key, rng.clone());
    let mut signer = Signer::<ThreadRng>::new(&key_pair, rng.clone());

    let m0 = Scalar::random(&mut rng);
    let m1 = Scalar::random(&mut rng);

    user.set_message(m0, m1)?;
    signer.set_message(m0)?;
    let (W,X) = user.commit()?;
    let eta = signer.commit(W,X)?;
    let (b1,b2,b3) = user.compute_witness(&eta)?;
    signer.verify_witness(b1, b2, b3)?;
    let (Y, R, l) = signer.sign()?;
    let (sigma, alpha, beta) = user.sign(&Y, &R, &l)?;

    assert_eq!(user.public_key, &signer.key_pair.public_key);
    assert_eq!(user.public_key.g2 * signer.key_pair.secret_key, G2Projective::from(user.public_key.w2));
    assert_eq!(user.X, signer.X);
    assert_eq!(user.W, signer.W);

    let pk = &signer.key_pair.public_key;
    let y = (signer.X + signer.key_pair.public_key.v1 * l) * (signer.key_pair.secret_key + signer.r).invert().unwrap();
    let y2 = (pk.h1 * signer.m0 + pk.g1 * user.m1 + pk.u1 + pk.v1 * (user.s + l * (user.t).invert().unwrap())) * (user.t * (signer.key_pair.secret_key + signer.r).invert().unwrap());
    assert_eq!(G1Projective::from(Y),y);
    assert_eq!(Y,G1Affine::from(y));
    assert_eq!(Y, G1Affine::from(y2));


    let sigma2 = (user.public_key.h1 * user.m0 + user.public_key.g1 * user.m1 + user.public_key.u1 + user.public_key.v1 * (user.s + l * user.t.invert().unwrap())) * (user.f * signer.key_pair.secret_key + user.f * signer.r).invert().unwrap();
    assert_eq!(G1Projective::from(sigma), sigma2);

    let alpha3 = user.public_key.w2 * ((user.f - Scalar::one())) + R * user.f;
    assert_eq!(G2Projective::from(alpha), alpha3);
    let alpha2 = user.public_key.g2 * ((user.f - Scalar::one()) * signer.key_pair.secret_key + (user.f * signer.r));
    assert_eq!(G2Projective::from(alpha), alpha2);

    verify_signature(&user.public_key, &user.m0, &user.m1, &sigma, &alpha, &beta)?;
    verify_signature(&signer.key_pair.public_key, &signer.m0, &user.m1, &sigma, &alpha, &beta)?;

    Ok(())
}
