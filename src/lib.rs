// Copyright (c) Jeffrey Hohenstein <jeffrey.hohenstein@gmail.com>
//
// All rights reserved.

//! Okamoto Blind Signatures
//!
//! # References
//! * Based on [Efficient Blind and Partially Blind Signatures Without Random Oracles](https://link.springer.com/content/pdf/10.1007/11681878_5.pdf)

#[cfg(feature = "bls12_381_plain")]
pub mod bls12_381_plain;
#[cfg(feature = "bls12_381_crs")]
pub mod bls12_381_crs;
