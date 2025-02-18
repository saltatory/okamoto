// Copyright (c) Jeffrey Hohenstein <jeffrey.hohenstein@gmail.com>
//
// All rights reserved.

//! Okamoto Partially Blind Signatures implemented over the BLS12-381 Elliptic Curve
//!
//! # Example
//! ```rust
//! #![allow(non_snake_case)]
//! use bls12_381::Scalar;
//! use ff::Field;
//! use okamoto::bls12_381_plain::{Error, KeyPair, Signer, User};
//!
//! fn happy_path() -> Result<(), Error> {
//!     // Setup
//!     let mut rng = rand::thread_rng();
//!     let key_pair = KeyPair::generate(rng.clone());
//!     let mut user = User::new(&key_pair.public_key, rng.clone());
//!     let mut signer = Signer::new(&key_pair, rng.clone());
//!
//!     // Step 0: out-of-band, the [User] and the [Signer] perform application logic necessary to agree on $m_0$
//!     let m0 = Scalar::random(&mut rng);
//!     let m1 = Scalar::random(&mut rng);
//!
//!
//!     // Step 1: User and Signer both commit to messages
//!     user.set_message(m0, m1)?;
//!     signer.set_message(m0)?;
//!
//!     // Step 2: User generates a proof of commitment that is verified by Signer
//!     let (W,X) = user.commit()?;
//!     let eta = signer.commit(W,X)?;
//!
//!     // Step 3: User generates proof of knowledge of variables $s,t \in \mathbb{Z}_p^{*}$.
//!     // Signer verifies the proof.
//!     let (b1, b2, b3) = user.compute_witness(&eta)?;
//!     signer.verify_witness(b1,b2,b3)?;
//!
//!     // Step 4: Signer send a partial signature to the User. User generates a completed signature.
//!     let (Y,R,l) = signer.sign()?;
//!     let (sigma, alpha, beta) = user.sign(&Y,&R,&l)?;
//!
//!     Ok(())
//! }
//!
//! happy_path().expect("successful completion");
//!
//!
//! ```

use bls12_381::{G1Affine, G1Projective, G2Projective, Scalar, G2Affine};
use ff::Field;
use rand::RngCore;

pub type SecretKey = Scalar;

/// The public key for this signing protocol consists of several generators in $\mathbb{G_1}$ and
/// matching generators for the pairing operation in $\mathbb{G_2}$.
#[derive(Copy, Clone, Debug, PartialEq, Default)]
pub struct PublicKey {
    pub g1: G1Affine,
    pub h1: G1Affine,
    pub u1: G1Affine,
    pub v1: G1Affine,
    pub g2: G2Affine,
    pub h2: G2Affine,
    pub u2: G2Affine,
    pub v2: G2Affine,
    /// ${g_2}^{x}$
    pub w2: G2Affine,
}

/// A pair of secret and public keys for the signing protocol
pub struct KeyPair {
    pub public_key: PublicKey,
    /// The exponent $x \in $\mathbb{Z}_p^{*}$ in ${g_2}^{x}$
    secret_key: SecretKey,
}

impl KeyPair {
    pub fn generate(mut rng: impl RngCore) -> KeyPair {
        let secret_key: SecretKey = Scalar::random(&mut rng);

        let mut public_key = PublicKey::default();

        let mut g1_r: Scalar;
        let mut h1_r: Scalar;
        let mut u1_r: Scalar;
        let mut v1_r: Scalar;

        loop {
            g1_r = Scalar::random(&mut rng);
            if g1_r.is_zero().into() {
                continue;
            }
            public_key.g1 = G1Affine::from(G1Affine::generator() * g1_r);
            // TODO test whether element is identity
            if public_key.g1 == G1Affine::generator() {
                continue;
            }
            break;
        }

        loop {
            h1_r = Scalar::random(&mut rng);
            if h1_r.is_zero().into() {
                continue;
            }
            public_key.h1 = G1Affine::from(G1Affine::generator() * h1_r);
            if public_key.h1 == G1Affine::generator() {
                continue;
            }
            // TODO test whether element is identity
            if public_key.h1 != public_key.g1 {
                break;
            }
        }

        loop {
            u1_r = Scalar::random(&mut rng);
            if u1_r.is_zero().into() {
                continue;
            }
            public_key.u1 = G1Affine::from(G1Affine::generator() * u1_r);
            if public_key.u1 == G1Affine::generator() {
                continue;
            }
            // TODO test whether element is identity
            if public_key.u1 != public_key.g1 && public_key.u1 != public_key.h1 {
                break;
            }
        }

        loop {
            v1_r = Scalar::random(&mut rng);
            if v1_r.is_zero().into() {
                continue;
            }
            public_key.v1 = G1Affine::from(G1Affine::generator() * v1_r);
            if public_key.v1 == G1Affine::generator() {
                continue;
            }
            // TODO test whether element is identity
            if public_key.v1 != public_key.g1
                && public_key.v1 != public_key.h1
                && public_key.v1 != public_key.u1
            {
                break;
            }
        }

        public_key.g2 = G2Affine::from(G2Projective::generator() * g1_r);
        public_key.h2 = G2Affine::from(G2Projective::generator() * h1_r);
        public_key.u2 = G2Affine::from(G2Projective::generator() * u1_r);
        public_key.v2 = G2Affine::from(G2Projective::generator() * v1_r);
        public_key.w2 = G2Affine::from(public_key.g2 * secret_key);

        let key_pair = KeyPair {
            secret_key,
            public_key,
        };

        key_pair
    }
}

#[derive(Debug)]
pub enum Error {
    /// A method was called in the incorrect state
    InvalidState,
    /// A provided signature could not be validated given the [PublicKey]
    InvalidSignature,
    /// Given point is not on the curve
    PointNotOnCurve,
    /// The given witness was invalid
    InvalidWitness,
    /// A given [Scalar] value was zero
    ScalarIsZero,
}

pub enum SignerState {
    /// Step 1, ready to call [Signer::set_message]
    ReadyToSetMessage,
    /// Step 2, ready to call [Signer::commit]
    ReadyToCommit,
    /// Step 3, ready to call [Signer::verify_witness]
    ReadyToVerifyWitness,
    /// Step 4, ready to call [Signer::sign]
    ReadyToSign,
    /// End, the message has been signed
    Signed,
    /// An error occurred during the signing process
    Aborted,
}

/// Signer is a single, stateful interaction with a [User] to sign a shared message $m_0$ (aka info)
/// and a blinded message $m_1$ (aka message).
///
/// A Signer can be used for any number of [Signer::verify_signature] operations but can only be used for a single
/// signing flow.
#[allow(non_snake_case)]
#[allow(dead_code)]
pub struct Signer<'a, R: RngCore> {
    key_pair: &'a KeyPair,
    rng: R,
    state: SignerState,
    m0: Scalar,
    W: G1Projective,
    X: G1Projective,
    #[cfg(test)]
    l: Scalar,
    #[cfg(test)]
    r: Scalar,
    eta: Scalar,
    #[cfg(test)]
    b1: Scalar,
    #[cfg(test)]
    b2: Scalar,
    #[cfg(test)]
    b3: Scalar,
}

impl<'a, R: RngCore> Signer<'a, R> {
    /// Create a fresh [Signer] in the starting state given a [KeyPair]
    pub fn new(key_pair: &'a KeyPair, rng: R) -> Self {
        Self {
            key_pair,
            rng,
            state: SignerState::ReadyToSetMessage,
            m0: Scalar::zero(),
            W: Default::default(),
            X: Default::default(),
            #[cfg(test)]
            l: Default::default(),
            #[cfg(test)]
            r: Default::default(),
            eta: Default::default(),
            #[cfg(test)]
            b1: Default::default(),
            #[cfg(test)]
            b2: Default::default(),
            #[cfg(test)]
            b3: Default::default(),
        }
    }

    /// Get the current [SignerState]
    pub fn get_state(&self) -> &SignerState {
        &self.state
    }

    /// Step 1. In the first stage of the negotiation, Signer and User agree on $m_0$ (aka `info`).
    /// The rules for agreement are up to the application.
    ///
    /// $m_0 \in \mathbb{Z}_p^{*}$.
    ///
    /// It is up to the application to hash the byte array of the message to the finite field:
    ///
    /// $H: {0..1}^* \rightarrow \mathbb{Z}_p^{*}$
    pub fn set_message(&mut self, m0: Scalar) -> Result<(), Error> {
        match self.state {
            SignerState::ReadyToSetMessage => {}
            _ => return Err(Error::InvalidState),
        }

        self.m0 = m0;
        self.state = SignerState::ReadyToCommit;

        Ok(())
    }

    /// Step 2. The [User] commits to the messages and random values for the generators and presents
    /// a witness that will be used in the next step to prove the witness.
    ///
    /// * Verify that $W \in \mathbb{G1}$
    /// * Verify that $X \in \mathbb{G1}$
    /// * Verify that $a1, a2, a3 \in \mathbb{Z}_p^{*}$
    /// * Store $W$ and $X$
    ///
    /// # Returns
    /// $\eta$ a value used in the next step to prove to the [Signer] that she
    /// knows $s,t \in \mathbb{Z}_p^{*}$
    #[allow(non_snake_case)]
    pub fn commit(&mut self, W: G1Affine, X: G1Affine) -> Result<&Scalar, Error> {
        match self.state {
            SignerState::ReadyToCommit => {}
            _ => return Err(Error::InvalidState),
        }

        if !bool::from(W.is_on_curve()) || !bool::from(X.is_on_curve()) {
            self.state = SignerState::Aborted;
            return Err(Error::PointNotOnCurve);
        }

        self.eta = Scalar::random(&mut self.rng);
        self.W = G1Projective::from(W);
        self.X = G1Projective::from(X);
        self.state = SignerState::ReadyToVerifyWitness;

        Ok(&self.eta)
    }

    /// Step 3. Verify that the [User] has knowledge of $s,t \in \mathbb{Z}_p^{*}$
    ///
    /// Verify that $({h_1}^{m_0})^{b_2}{g_1}^{b_1}{u_1}^{b_2}{v_1}^{b_3} = WX^{\eta}$
    pub fn verify_witness(&mut self, b1: Scalar, b2: Scalar, b3: Scalar) -> Result<(), Error> {
        match self.state {
            SignerState::ReadyToVerifyWitness => {}
            _ => return Err(Error::InvalidState),
        }

        let pk = &self.key_pair.public_key;

        let rhs = self.W + self.X * self.eta;
        let lhs = pk.h1 * (self.m0 * b2) + pk.g1 * b1 + pk.u1 * b2 + pk.v1 * b3;

        if rhs != lhs {
            self.state = SignerState::Aborted;
            return Err(Error::InvalidWitness);
        }

        self.state = SignerState::ReadyToSign;

        Ok(())
    }

    /// Step 4. (counter) sign and return the wrapped signature.
    ///
    /// $Y \leftarrow (Xv_1^l)^{1/{(x+r)}}$
    ///
    /// $R \leftarrow g_2^r$
    ///
    /// $l \leftarrow \mathbb{Z}_p^{*}$
    ///
    /// # Returns
    /// $(Y, R, l)$
    pub fn sign(&mut self) -> Result<(G1Affine, G2Affine, Scalar), Error> {
        match self.state {
            SignerState::ReadyToSign => {}
            _ => return Err(Error::InvalidState),
        }

        let pk = &self.key_pair.public_key;

        let l = Scalar::random(&mut self.rng);
        let r = Scalar::random(&mut self.rng);
        #[allow(non_snake_case)]
        let R = pk.g2 * r;
        #[allow(non_snake_case)]
        let Y = (self.X + (pk.v1 * l)) * (self.key_pair.secret_key + r).invert().unwrap();

        #[cfg(test)]
        {
            self.l = l;
            self.r = r;
        }

        self.state = SignerState::Signed;

        Ok((G1Affine::from(Y), G2Affine::from(R), l))
    }

    /// Abort the protocol preventing further use of the values
    pub fn abort(&mut self) {
        self.state = SignerState::Aborted
    }
}

pub enum UserState {
    ReadyToSetMessage,
    ReadyToCommit,
    ReadyToComputeWitness,
    ReadyToSign,
    Signed,
    Aborted,
}

/// User is a single stateful interaction with a [Signer] to sign a shared message $m_0$ (aka `info`)
/// and a blinded message $m_1$ (aka `message`).
///
/// User can be used to verify any number of signatures but can be used to sign at most on message.
#[allow(non_snake_case)]
pub struct User<'a, R: RngCore> {
    public_key: &'a PublicKey,
    state: UserState,
    rng: R,
    m0: Scalar,
    m1: Scalar,
    a1: Scalar,
    a2: Scalar,
    a3: Scalar,
    #[cfg(test)]
    f: Scalar,
    s: Scalar,
    t: Scalar,
    #[cfg(test)]
    W: G1Projective,
    #[cfg(test)]
    X: G1Projective,
}

/// User is a stateful single instance of the User side of the (partially) blind signing protocol.
impl<'a, R: RngCore> User<'a, R> {
    pub fn new(public_key: &'a PublicKey, rng: R) -> Self {
        Self {
            public_key,
            state: UserState::ReadyToSetMessage,
            rng,
            m0: Default::default(),
            m1: Default::default(),
            a1: Default::default(),
            a2: Default::default(),
            a3: Default::default(),
            #[cfg(test)]
            f: Default::default(),
            s: Default::default(),
            t: Default::default(),
            #[cfg(test)]
            X: Default::default(),
            #[cfg(test)]
            W: Default::default(),
        }
    }

    pub fn get_state(&self) -> &UserState {
        &self.state
    }

    /// Step 1. Commit to the values of $m_0$ and $m_1$
    pub fn set_message(&mut self, m0: Scalar, m1: Scalar) -> Result<(), Error> {
        match self.state {
            UserState::ReadyToSetMessage => {}
            _ => return Err(Error::InvalidState),
        }

        if m0.is_zero().into() || m1.is_zero().into() {
            return Err(Error::ScalarIsZero);
        }

        self.m0 = m0;
        self.m1 = m1;
        self.state = UserState::ReadyToCommit;

        Ok(())
    }

    /// Step 2. Generate a commitment that can be sent to [Signer] to commit the [User] to
    /// $m_0,m_1 \in \mathbb{G_1}$ and $s,t \in {Z}_p^{*}$.
    ///
    /// $W \leftarrow ({h_1}^{m_0})^{a_2}{g_1}^{a_1}{u_1}^{a_2}{v_1}^{a_3}$
    ///
    /// $X \leftarrow {h_1}^{m_0t}{g_1}^{m_1t}{u_1}^{t}{v_1}^{st}$
    ///
    ///
    /// # Returns
    /// ($W$,$X$)
    pub fn commit(&mut self) -> Result<(G1Affine, G1Affine), Error> {
        match self.state {
            UserState::ReadyToCommit => {}
            _ => return Err(Error::InvalidState),
        }

        let a1 = Scalar::random(&mut self.rng);
        let a2 = Scalar::random(&mut self.rng);
        let a3 = Scalar::random(&mut self.rng);
        let s = Scalar::random(&mut self.rng);
        let t = Scalar::random(&mut self.rng);
        let pk = &self.public_key;
        #[allow(non_snake_case)]
        let X = pk.h1 * (self.m0 * t) + pk.g1 * (self.m1 * t) + pk.u1 * t + pk.v1 * (s * t);
        #[allow(non_snake_case)]
        let W = pk.h1 * (self.m0 * a2) + pk.g1 * a1 + pk.u1 * a2 + pk.v1 * a3;

        #[cfg(test)]
        {
            self.X = X.clone();
            self.W = W.clone();
        }

        self.a1 = a1;
        self.a2 = a2;
        self.a3 = a3;
        self.t = t;
        self.s = s;

        self.state = UserState::ReadyToComputeWitness;

        Ok((G1Affine::from(W), G1Affine::from(X)))
    }

    /// Step 3. Compute a witness that proves that the [User] knows values $s,t \in \mathbb{Z}_p^{*}$ that
    /// were mixed into the values of $W,X$.
    ///
    /// $b_1, b_2, b_3 \in \mathbb{Z}_p^{*}$
    ///
    /// $b_1 \leftarrow a_1 + \eta{m}_1t \mod p$
    ///
    /// $b_2 \leftarrow a_2 + \eta{t} \mod p$
    ///
    /// $b_3 \leftarrow a_  + \eta{s}t \mod p$
    ///
    /// # Returns
    /// $b_1, b_2, b_3 \in \mathbb{Z}_p^{*}$
    pub fn compute_witness(&mut self, eta: &Scalar) -> Result<(Scalar, Scalar, Scalar), Error> {
        match self.state {
            UserState::ReadyToComputeWitness => {}
            _ => return Err(Error::InvalidState),
        }

        let b1 = self.a1 + eta * self.m1 * self.t;
        let b2 = self.a2 + eta * self.t;
        let b3 = self.a3 + eta * self.s * self.t;

        self.state = UserState::ReadyToSign;

        Ok((b1, b2, b3))
    }

    /// Step 4 (final). Compute the final signature $(\sigma, \alpha, \beta)$
    ///
    /// # Returns
    /// $(\sigma, \alpha, \beta)$
    #[allow(non_snake_case)]
    pub fn sign(
        &mut self,
        Y: &G1Affine,
        R: &G2Affine,
        l: &Scalar,
    ) -> Result<(G1Affine, G2Affine, Scalar), Error> {
        match self.state {
            UserState::ReadyToSign => {}
            _ => return Err(Error::InvalidState),
        }

        let pk = &self.public_key;
        let f = Scalar::random(&mut self.rng);
        let tau = (f * self.t).invert().unwrap();
        let sigma = Y * tau;
        let alpha = pk.w2 * (f - Scalar::one()) + (R * f);
        let beta = self.s + l * self.t.invert().unwrap();

        #[cfg(test)]
        {
            self.f = f;
        }

        self.state = UserState::Signed;

        Ok((G1Affine::from(sigma), G2Affine::from(alpha), beta))
    }

    /// Abort the instance of the protocol preventing further use of the values
    pub fn abort(&mut self) {
        self.state = UserState::Aborted;
    }
}

/// Verify that a signature is valid
///
/// # Checks
/// * $m_0 \in \mathbb{Z}_p^{*}$
///
/// * $m_1 \in \mathbb{Z}_p^{*}$
///
/// * $\sigma \in \mathbb{G}_1$
///
/// * $\alpha \in \mathbb{G}_2$
///
/// * $\beta \in \mathbb{Z}_p$
///
/// * $e(\sigma,w_2\alpha) = e(g_1,{h_2}^{m_0}{g_2}^{m_1}{u_2}{v_2}^{\beta})$
///
pub fn verify_signature(
    public_key: &PublicKey,
    m0: &Scalar,
    m1: &Scalar,
    sigma: &G1Affine,
    alpha: &G2Affine,
    beta: &Scalar,
) -> Result<(), Error> {
    let lhs2 = G2Affine::from(G2Projective::from(public_key.w2) + alpha);
    let rhs2 = G2Affine::from(
        public_key.h2 * m0 + public_key.g2 * m1 + public_key.u2 + public_key.v2 * beta,
    );
    let lhs = bls12_381::pairing(&sigma, &lhs2);
    let rhs = bls12_381::pairing(&public_key.g1, &rhs2);

    if sigma == &G1Affine::identity() {
        return Err(Error::InvalidSignature);
    }

    if !bool::from(sigma.is_on_curve()) {
        return Err(Error::InvalidSignature);
    }

    if !bool::from(alpha.is_on_curve()) {
        return Err(Error::InvalidSignature);
    }

    if lhs != rhs {
        return Err(Error::InvalidSignature);
    }

    Ok(())
}

#[cfg(test)]
mod tests;
