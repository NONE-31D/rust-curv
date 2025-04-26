use sha2::{Sha256, Digest};
use crate::{arithmetic::traits::*, cryptographic_primitives::proofs::{quadratic_residue::*, quadratic_residue_dlog::*}};
use crate::BigInt;
use serde::{Deserialize, Serialize};
use super::ProofError;

pub const S: u32 = 128;
pub const T: u32 = 128;
pub const L: u32 = 80;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct AffineProof {
    capital_a: BigInt,
    capital_b1: BigInt,
    capital_b2: BigInt,
    capital_b3: BigInt,
    capital_b4: BigInt,
    z1: BigInt,
    z2: BigInt,
    z3: BigInt,
    z4: BigInt,
    h: BigInt,
    g: BigInt,
}

impl AffineProof {    
    pub fn prove(
        pk: &BigInt,
        nn: &BigInt,
        q: &BigInt,
        c: &BigInt,
        ca: &BigInt,
        a: &BigInt,

    ) -> AffineProof {
        let n = pk;

        let witness: BigInt = BigInt::sample_below(&n);
        let h = BigInt::mod_pow(&witness, &BigInt::from(2), &n);
        let alpha = BigInt::sample_below(&n);
        let g = BigInt::mod_pow(&h, &alpha, &n);
    
        // h, g -> proof needed
        let qr_proof = QRProof::prove(&pk); // for h
        let qrdl_proof = QRdlProof::prove(&pk); // for g
    
        let verif_qr = QRProof::verify(&qr_proof, &n);
        let verif_qrdl = QRdlProof::verify(&qrdl_proof, &n);

        // prover's 1st message
        let k_big: BigInt = BigInt::from(2).pow(T+L+S) * q.pow(2);
        let b = BigInt::sample_below(&(BigInt::from(2).pow(T+L) * q.clone()));
        let beta = BigInt::sample_below(&(BigInt::from(2).pow(T+L) * k_big));
        let rho1 = BigInt::sample_below(&(BigInt::from(2).pow(T+L) * n));
        let rho2 = BigInt::sample_below(&(BigInt::from(2).pow(T+L) * n));
        let rho3 = BigInt::sample_below(&(n));
        let rho4 = BigInt::sample_below(&(n));

        let capital_a = BigInt::mod_mul( // A = c^b * (1 + n*beta) mod nn
            &(BigInt::mod_pow(&c, &b, &nn)),
            &((BigInt::one() + n * beta.clone()) % nn),
            &nn
        );
        let capital_b1 = BigInt::mod_mul( // B1 = g^b * h^rho1 mod n
            &(BigInt::mod_pow(&g, &b, &n)),
            &(BigInt::mod_pow(&h, &rho1, &n)),
            &n
        );
        let capital_b2 = BigInt::mod_mul( // B2 = g^beta * h^rho2 mod n
            &(BigInt::mod_pow(&g, &beta, &n)),
            &(BigInt::mod_pow(&h, &rho2, &n)),
            &n
        );
        let capital_b3 = BigInt::mod_mul( // B3 = g^a * h^rho3 mod n
            &(BigInt::mod_pow(&g, &a, &n)),
            &(BigInt::mod_pow(&h, &rho3, &n)),
            &n
        );
        let capital_b4 = BigInt::mod_mul( // B4 = g^alpha * h^rho4 mod n
            &(BigInt::mod_pow(&g, &alpha, &n)),
            &(BigInt::mod_pow(&h, &rho4, &n)),
            &n
        );

        // hashing e as non-interactive / e in 2^T
        let mut hasher = Sha256::new();
        hasher.update(n.to_string().as_bytes());
        hasher.update(q.to_string().as_bytes());
        hasher.update(ca.to_string().as_bytes());
        hasher.update(c.to_string().as_bytes());
        hasher.update(capital_a.to_string().as_bytes());
        hasher.update(capital_b1.to_string().as_bytes());
        hasher.update(capital_b2.to_string().as_bytes());
        hasher.update(capital_b3.to_string().as_bytes());
        hasher.update(capital_b4.to_string().as_bytes());
        let result = hasher.finalize();
        let modulus = BigInt::from(2).pow(T);
        let e = BigInt::from_bytes(&result) % modulus;

        // prover's 2nd message
        let z1 = b.clone() + e.clone() * a.clone();
        let z2 = beta.clone() + e.clone() * alpha.clone();
        let z3 = rho1.clone() + e.clone() * rho3.clone();
        let z4 = rho2.clone() + e.clone() * rho4.clone();

        AffineProof {capital_a, capital_b1, capital_b2, capital_b3, capital_b4, z1, z2, z3, z4, h, g}
    }

    pub fn verify(
        affine_proof: &AffineProof, 
        n: &BigInt,
        nn: &BigInt,
        q: &BigInt,
        c: &BigInt,
        ca: &BigInt,

    ) -> Result<(), ProofError> {
        // getting proof for affran from prover
        let big_k: BigInt = BigInt::from(2).pow(T+L+S) * q.pow(2);
        let &AffineProof { ref capital_a, ref capital_b1, ref capital_b2, ref capital_b3, ref capital_b4, ref z1, ref z2, ref z3, ref z4, ref h, ref g } = affine_proof;
        
        // hashing e as non-interactive    
        let mut hasher = Sha256::new();
        hasher.update(n.to_string().as_bytes());
        hasher.update(q.to_string().as_bytes());
        hasher.update(ca.to_string().as_bytes());
        hasher.update(c.to_string().as_bytes());
        hasher.update(capital_a.to_string().as_bytes());
        hasher.update(capital_b1.to_string().as_bytes());
        hasher.update(capital_b2.to_string().as_bytes());
        hasher.update(capital_b3.to_string().as_bytes());
        hasher.update(capital_b4.to_string().as_bytes());
        let result = hasher.finalize();
        let modulus: BigInt = BigInt::from(2).pow(T);
        let e = BigInt::from_bytes(&result) % modulus;

        // verifiers verification 1-5
        let verif1 = // range check for z1
        z1 >= &(BigInt::from(2).pow(T) * q) && 
        z1 < &(BigInt::from(2).pow(T+L) * q);

        let verif2 = // range check for z2
        z2 >= &(BigInt::from(2).pow(T) * big_k.clone()) &&
        z2 < &(BigInt::from(2).pow(T+L) * big_k.clone());

        let lhs3 = BigInt::mod_mul(
            &(BigInt::mod_pow(&c, &z1, &nn)),
            &(BigInt::one() + n * z2.clone()), 
            &nn
        );
        let rhs3 = BigInt::mod_mul(
            &capital_a,
            &(BigInt::mod_pow(&ca, &e, &nn)),
            &nn,
        );

        let lhs4 = BigInt::mod_mul(
            &(BigInt::mod_pow(&g, &z1, &n)),
            &(BigInt::mod_pow(&h, &z3, &n)),
            &n
        );
        let rhs4 = BigInt::mod_mul(
            &capital_b1,
            &(BigInt::mod_pow(&capital_b3, &e, &n)),
            &n
        );

        let lhs5 = BigInt::mod_mul(
            &(BigInt::mod_pow(&g, &z2, &n)),
            &(BigInt::mod_pow(&h, &z4, &n)),
            &n
        );
        let rhs5 = BigInt::mod_mul(
            &capital_b2,
            &(BigInt::mod_pow(&capital_b4, &e, &n)),
            &n
        );
        if verif1 && verif2 && lhs3 == rhs3 && lhs4 == rhs4 && lhs5 == rhs5 {
            Ok(())
        } else {
            Err(ProofError)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_affine_proof() {
        // let n = BigInt::sample(3072);
        
        let (ek, dk) = Paillier::keypair_with_modulus_size(3072);
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

        // generating public ca with a, alpha
        let a = BigInt::sample_below(&q); // n
        let alpha = BigInt::sample_below(&n);
        let ca: BigInt = BigInt::mod_mul(
            &(BigInt::mod_pow(&c, &a, &nn)),
            &(BigInt::one() + n.clone() * alpha.clone()),
            &nn
        );

        let affine_proof = AffineProof::prove(ek, &nn, &q, &c, &ca, &a);

        match AffineProof::verify(&affine_proof, &n, &nn, &q, &c, &ca) {
            Ok(res) => println!("Verification_range_proof result: {:?}", res),
            Err(error ) => panic!("Problem opening the file: {:?}", error.to_string()),
        }; 
    }
}