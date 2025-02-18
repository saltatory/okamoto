// Copyright (c) Jeffrey Hohenstein <jeffrey.hohenstein@gmail.com>
//
// All rights reserved.

use std::time::Duration;
use bls12_381::Scalar;
use criterion::{criterion_group, criterion_main, Criterion};
use ff::Field;
use rand::prelude::ThreadRng;
use simple_logger::SimpleLogger;
use okamoto::bls12_381_plain::{verify_signature, KeyPair, Signer, User};

#[allow(non_snake_case)]
fn bench(criterion: &mut Criterion) {
    let _ = SimpleLogger::new().init();

    let mut group = criterion.benchmark_group("okamoto");
    group.measurement_time(Duration::from_secs(120));
    group.sample_size(1000);

    group.bench_function("generate", |b| {
        let mut rng = ThreadRng::default();
        b.iter(|| {
            let _ = KeyPair::generate(&mut rng);
        });
    });

    group.bench_function("sign", |b| {
        let mut rng = rand::thread_rng();
        let key_pair = KeyPair::generate(&mut rng);
        let m0 = Scalar::random(&mut rng);
        let m1 = Scalar::random(&mut rng);

        b.iter(|| {
            let mut user = User::new(&key_pair.public_key, rng.clone());
            let mut signer = Signer::new(&key_pair, rng.clone());
            user.set_message(m0, m1).unwrap();
            signer.set_message(m0).unwrap();
            let (W,X) = user.commit().unwrap();
            let eta = signer.commit(W, X).unwrap();
            let (b1, b2, b3) = user.compute_witness(&eta).unwrap();
            signer.verify_witness(b1, b2, b3).unwrap();
            let (Y,R,l) = signer.sign().unwrap();
            user.sign(&Y,&R,&l).unwrap();
        });
    });

    group.bench_function("verify", |b| {
        let mut rng = rand::thread_rng();
        let key_pair = KeyPair::generate(&mut rng);
        let mut rng = rand::thread_rng();
        let m0 = Scalar::random(&mut rng);
        let m1 = Scalar::random(&mut rng);
        let mut user = User::new(&key_pair.public_key, rng.clone());
        let mut signer = Signer::new(&key_pair, rng.clone());
        user.set_message(m0, m1).unwrap();
        signer.set_message(m0).unwrap();
        let (W,X) = user.commit().unwrap();
        let eta = signer.commit(W, X).unwrap();
        let (b1, b2, b3) = user.compute_witness(&eta).unwrap();
        signer.verify_witness(b1, b2, b3).unwrap();
        let (Y,R,l) = signer.sign().unwrap();
        let (sigma, alpha, beta) = user.sign(&Y,&R,&l).unwrap();

        b.iter(|| {
            verify_signature(&key_pair.public_key, &m0, &m1, &sigma, &alpha, &beta).unwrap();
        });
    });

}

criterion_group!(benches, bench);
criterion_main!(benches);
