use sha2::{Sha256, Digest};
use crate::{arithmetic::traits::*, cryptographic_primitives::proofs::{quadratic_residue::*, quadratic_residue_dlog::*}};
use crate::BigInt;
use serde::{Deserialize, Serialize};
use super::ProofError;

pub const T: u32 = 128;
pub const L: u32 = 80;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct RangeProof {
    capital_c: BigInt,
    d: BigInt,
    capital_d: BigInt,
    z1: BigInt,
    z2: BigInt,
    z3: BigInt,
    h: BigInt,
    g: BigInt,
}

impl RangeProof {    
    pub fn prove(
        pk: &BigInt, 
        nn: &BigInt, 
        q: &BigInt, 
        c: &BigInt, 
        x: &BigInt, 
        r: &BigInt, 
    ) -> RangeProof {
        let n = pk;
        
        // for Pedersen commitment parameter h, g
        let witness = BigInt::sample_below(&n);
        let h = BigInt::mod_pow(&witness, &BigInt::from(2), &n);
        let alpha = BigInt::sample_below(&n);
        let g = BigInt::mod_pow(&h, &alpha, &n);

        // h, g -> proof needed
        let qr_proof = QRProof::prove(&pk); // for h
        let qrdl_proof = QRdlProof::prove(&pk); // for g

        let verif_qr = QRProof::verify(&qr_proof, &n);
        let verif_qrdl = QRdlProof::verify(&qrdl_proof, &n);

        // prover's 1st message
        let alpha = BigInt::sample_below(&n);
        let beta = BigInt::sample_below(&(BigInt::from(2).pow(T+L) * n));
        let y = BigInt::sample_below(&(BigInt::from(2).pow(T+L) * q.clone()));
        let rd = BigInt::sample_below(&n);

        // Pedersen commitment of "x" with randomness "alpha" mod n
        let capital_c = BigInt::mod_mul( // C = g^x * h^alpha mod n
            &BigInt::mod_pow(&g, &x, &n),
            &BigInt::mod_pow(&h, &alpha, &n),
            &n,
        );

        let d = BigInt::mod_mul( // d = rd^n * (1 + ny) mod nn
            &BigInt::mod_pow(&rd, &n, &nn),
            &((BigInt::one() + n * y.clone()) % nn.clone()), // (1 + ny) mod nn
            &nn,
        );
        
        // Pedersen commitment of "y" with randomness "beta" mod n
        let capital_d = BigInt::mod_mul( // D = g^y * h^beta mod n
            &BigInt::mod_pow(&g, &y, &n),
            &BigInt::mod_pow(&h, &beta, &n), 
            &n,
        );

        // hashing e as non-interactive / e in 2^T
        let mut hasher = Sha256::new();
        hasher.update(n.to_string().as_bytes());
        hasher.update(q.to_string().as_bytes());
        hasher.update(c.to_string().as_bytes());
        hasher.update(capital_c.to_string().as_bytes());
        hasher.update(d.to_string().as_bytes());
        hasher.update(capital_d.to_string().as_bytes());
        let result = hasher.finalize();
        let modulus: BigInt = BigInt::from(2).pow(T);
        let e = BigInt::from_bytes(&result) % modulus;

        //prover's 2nd message
        let z1 = y.clone() + (e.clone() * x.clone()); // integer
        let z2 = BigInt::mod_mul(
            &rd,
            &BigInt::mod_pow(&r, &e.clone(), &n),
            &n,
        );
        let z3 = beta.clone() + (alpha.clone() * e.clone()); // integer

        RangeProof {capital_c, d, capital_d, z1, z2, z3, h, g}
    }

    pub fn verify(
        range_proof: &RangeProof, 
        n: &BigInt,
        nn: &BigInt, 
        q: &BigInt, 
        c: &BigInt, 
    ) -> Result<(), ProofError> {
        let &RangeProof { ref capital_c, ref d, ref capital_d, ref z1, ref z2, ref z3, ref h, ref g } = range_proof;

        // generating hash e as non-interactive
        let mut hasher = Sha256::new();
        hasher.update(n.to_string().as_bytes());
        hasher.update(q.to_string().as_bytes());
        hasher.update(c.to_string().as_bytes());
        hasher.update(capital_c.to_string().as_bytes());
        hasher.update(d.to_string().as_bytes());
        hasher.update(capital_d.to_string().as_bytes());
        let result = hasher.finalize();
        let modulus: BigInt = BigInt::from(2).pow(T);
        let e = BigInt::from_bytes(&result) % modulus;

        let lhs1 = BigInt::mod_mul(
            &BigInt::mod_pow(&z2, n, nn), // z2^n mod nn
            &((BigInt::one() + n * z1.clone()) % nn), // (1+n)^z1 mod nn
            nn,
        );
        let rhs1 = BigInt::mod_mul(
            &d,
            &BigInt::mod_pow(&c, &e, nn), 
            nn
        );

        let lhs2 = BigInt::mod_mul(
            &BigInt::mod_pow(&g, &z1, &n), // g^z1 mod n
            &BigInt::mod_pow(&h, &z3, &n), // h^z3 mod n
            &n,
        );
        let rhs2 = BigInt::mod_mul(
            &capital_d,
            &BigInt::mod_pow(&capital_c, &e, &n), // C^e mod n
            &n,
        );

        let verif3 = // range cheek for z1
        z1 >= &(BigInt::from(2).pow(T) * q) && 
        z1 < &{BigInt::from(2).pow(T + L) * q};

        if lhs1 == rhs1 && lhs2 == rhs2 && verif3 == true {
            Ok(())
        } else {
            Err(ProofError)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub struct Keypair {
        #[serde(with = "crate::serialize::bigint")]
        pub p: BigInt, // TODO[Morten] okay to make non-public?
    
        #[serde(with = "crate::serialize::bigint")]
        pub q: BigInt, // TODO[Morten] okay to make non-public?
    }

    impl Keypair {
        /// Generate default encryption and decryption keys.
        pub fn keys(&self) -> (EncryptionKey, DecryptionKey) {
            let p = self.p.clone();
            let q = self.q.clone();
            (EncryptionKey{n: p.clone()*q.clone()}, DecryptionKey{p, q})
        }
    }

    /// Public encryption key.
    #[derive(Clone, Debug, PartialEq)]
    pub struct EncryptionKey {
        pub n: BigInt,  // the modulus
    }

    /// Private decryption key.
    #[derive(Clone, Debug, PartialEq)]
    pub struct DecryptionKey {
        pub p: BigInt, // first prime
        pub q: BigInt, // second prime
    }
    

    fn keypair_blum_with_modulus_size(bit_length: usize) -> Keypair {
        let mut p = BigInt::new();
        let mut q = BigInt::new();
        loop {
            p = BigInt::sample_prime(bit_length / 2);
            if &p % 4 != BigInt::from(3) {
                continue;
            }

            q = BigInt::sample_prime(bit_length / 2);
            if &q % 4 != BigInt::from(3) {
                continue;
            }
            if BigInt::gcd(&p, &q) != BigInt::one() {
                continue;
            } // check that p and q are coprime (ensures q^-1 mod p exists)

            let n = &p * &q;
            let phi_n = (&p - BigInt::one()) * (&q - BigInt::one());
            if BigInt::gcd(&n, &phi_n) != BigInt::one() {
                continue; // N과 φ(N)이 서로소가 아니라면 다시 샘플링
            }

            break;
        } // mod 4에서 3이되는 prime(p, q) 선정 -> n = pq
        Keypair { p, q }
    }

    #[test]
    pub fn test_range_proof() {
        // let n = BigInt::sample(3072);
        // let nn = n.clone() * n.clone();
        // let q = BigInt::sample(256); // temporary q as 256-bit

        let (ek, dk) = keypair_blum_with_modulus_size(3072).keys();
        let n = ek.n.clone();
        let nn = n.clone() * n.clone();
        let q = dk.q.clone();

        let x = BigInt::sample_below(&q); // secret witness / like message a, b
        let r = BigInt::sample_below(&n); // secret witness / randomness
        let c = BigInt::mod_mul( // temporary c as 3072-bit enc of x with r
            &BigInt::mod_pow(&r, &n, &nn),
            &BigInt::mod_pow(&(BigInt::from(1) + n.clone()), &x, &nn),
            &nn
        );

        // 여기 ek위치에 capital C 넣어야하는거 아니에여?? 
        let range_proof = RangeProof::prove(&ek, &nn, &q, &c, &x, &r);

        match RangeProof::verify(&range_proof, &n, &nn, &q, &c, ) {
            Ok(res) => println!("Verification_range_proof result: {:?}", res),
            Err(error ) => panic!("Problem opening the file: {:?}", error.to_string()),
        }; 
    }
}
