// Copyright (c) Jeffrey Hohenstein <jeffrey.hohenstein@gmail.com>
//
// All rights reserved.

use std::thread::scope;

use bls12_381::{G1Affine, G2Affine, Scalar};
use ff::Field;
use rand::RngCore;

#[derive(Default, Debug, Copy, Clone, PartialEq)]
pub struct PublicKey {
    pub g1: G1Affine,
    pub h1: G1Affine,
    pub u1: G1Affine,
    pub v1: G1Affine,
    pub g2: G2Affine,
}

pub const C0_INV: usize = 3;

pub struct SecretKey {}

pub struct KeyPair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

impl KeyPair {
    pub fn generate(mut rng: &mut impl RngCore) -> KeyPair {
        let x = Self::random_scalar(&mut rng);

        let mut public_key = PublicKey::default();

        let g1 = Self::random_generator_g1(&mut rng);
        let h1 = Self::random_generator_g1(&mut rng);
        let u1 = Self::random_generator_g1(&mut rng);
        let v1 = Self::random_generator_g1(&mut rng);
        let g2 = Self::random_generator_g2(&mut rng);

        KeyPair {
            public_key: PublicKey { g1, h1, u1, v1, g2 },
            secret_key: SecretKey {},
        }
    }

    /// Generate a random scalar that is neither 0 nor 1
    fn random_scalar(mut rng: &mut impl RngCore) -> Scalar {
        let mut x: Scalar;
        loop {
            x = Scalar::random(&mut rng);
            if x != Scalar::ONE && x != Scalar::ZERO {
                break;
            }
        }
        x
    }

    /// Compute a random generator in $G_1$
    fn random_generator_g1(mut rng: &mut impl RngCore) -> G1Affine {
        let mut generator: G1Affine;
        loop {
            let scalar = Self::random_scalar(&mut rng);
            generator = G1Affine::from((G1Affine::generator() * scalar));
            if generator != G1Affine::identity() {
                break;
            }
        }
        generator
    }

    /// Compute a random generator in $G_2$
    fn random_generator_g2(mut rng: &mut impl RngCore) -> G2Affine {
        let mut generator: G2Affine;
        loop {
            let scalar = Self::random_scalar(&mut rng);
            generator = G2Affine::from((G2Affine::generator() * scalar));
            if generator != G2Affine::identity() {
                break;
            }
        }
        generator
    }

    /// Generate a prime $p$ of order $r$ where $r$ is the prime order of the subgroup of $G_1$ and $G_2$
    fn generate_prime_order_r(mut rng: &mut impl RngCore) -> Scalar {
        todo!()
    }
}
