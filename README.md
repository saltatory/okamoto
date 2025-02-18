# Okamoto (2006) Blind Signatures
## Efficient Blind and Partially Blind Signatures Without Random Oracles

Implementations of blind and partially blind signatures over elliptic curves as described in [Efficient Blind and Partially Blind Signatures Without Random Oracles](https://link.springer.com/content/pdf/10.1007%2F11681878_5.pdf).

This library provides a usable implementation of the algorithm without regard to its eventual use. Uses such as in a "mint", are left to the implementor.

The key innovation of the paper and therefore of this library is in permitting *partially* blind signatures where the signer and the user share some component of the message (potentially the null string) openly. This would make it useful, for example, in a mint application where the mint (bank) executes out-of-band logic to verify the user's balance before signing an ATM-like withdrawal of an agreed denomination.

# Features

* `bls12_381_plain` (default): Plain implementation over the [BLS12-128](http://docs.rs/bls12_381) elliptic curve secure against constant-depth concurrent adversaries (not secure against fully concurrent adversaries)
* `bls12_381_crs` (default): Common reference string (CRS) implementation over the [BLS12-128](http://docs.rs/bls12_381) elliptic curve secure fully concurrent adversaries


# Sequence - Plain

```mermaid
sequenceDiagram
participant User
participant Signer
participant Verifier
alt Setup
Signer ->> Signer: Generate(KeyPair)
Signer ->> User: (KeyPair.PublicKey)
end

alt Negotiate Message
    User ->> Signer: m0
end

alt Sign
User ->> Signer: (X,W)
Signer ->> User: (eta)
User ->> Signer: (b1, b2, b3)
Signer ->> Signer: Verify(X,W,eta,b1,b2,b3)
Signer ->> User: (Y,R,l)
User ->> User: (sigma,alpha,beta)
end
alt Verify
User ->> Verifier: (m0,m1,sigma,alpha,beta)
end
```

# References

Using algorithms from:
* [Efficient Blind and Partially Blind Signatures Without Random Oracles](https://link.springer.com/content/pdf/10.1007%2F11681878_5.pdf).
* [bls12_381 Rust Crate](https://docs.rs/bls12_381/latest/bls12_381/)
* [Efficient Implementation of Pairing-Based Cryptosystems](https://link.springer.com/content/pdf/10.1007/s00145-004-0311-z.pdf)
* [Efficient Algorithms for Pairing-Based Cryptosystems](https://www.researchgate.net/profile/Hae-Kim-10/publication/40721105_Efficient_Algorithms_for_Pairing-Based_Cryptosystems/links/00463516819ba229e8000000/Efficient-Algorithms-for-Pairing-Based-Cryptosystems.pdf)
* [Pairing Friendly Curves](https://www.ietf.org/archive/id/draft-irtf-cfrg-pairing-friendly-curves-10.html#name-for-128-bit-security)

# Licensing

* [Business Source License (BUSL)](./LICENSE.md)
* Commercial licensing available upon request

# Copyright

Copyright (c) Jeffrey Hohenstein <jeffrey.hohenstein@gmail.com>

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you shall be licensed as above, without any additional terms or
conditions.
