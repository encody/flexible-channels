use ark_bls12_381::{Bls12_381, Fr};
use ark_crypto_primitives::crh::sha256::constraints::{DigestVar, Sha256Gadget};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::prelude::*;
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_snark::SNARK;
use ark_std::rand::{self, SeedableRng, rngs::StdRng};

#[derive(Clone)]
struct PreimageKnowledge {
    pub preimage: Vec<u8>,
    pub image: Vec<u8>,
}

impl Default for PreimageKnowledge {
    fn default() -> Self {
        Self {
            preimage: vec![0u8; 1],
            image: vec![0u8; 32],
        }
    }
}

// Implementing the constraint system
impl ConstraintSynthesizer<Fr> for PreimageKnowledge {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let mut hasher = Sha256Gadget::default();

        hasher.update(&UInt8::new_witness_vec(
            ns!(cs, "preimage"),
            &self.preimage,
        )?)?;

        let digest = hasher.finalize()?;

        DigestVar::new_input(ns!(cs, "image"), || Ok(self.image.clone()))?
            .enforce_equal(&digest)?;

        Ok(())
    }
}

fn generate_keys(preimage: Vec<u8>, image: Vec<u8>) -> ProvingKey<Bls12_381> {
    Groth16::<Bls12_381>::generate_random_parameters_with_reduction(
        PreimageKnowledge { preimage, image },
        &mut rand::prelude::StdRng::seed_from_u64(0u64),
    )
    .unwrap()
}

fn create_proof(pk: &ProvingKey<Bls12_381>, preimage: Vec<u8>, image: Vec<u8>) -> Proof<Bls12_381> {
    let circuit = PreimageKnowledge { preimage, image };

    Groth16::<Bls12_381>::create_random_proof_with_reduction(
        circuit,
        pk,
        &mut StdRng::seed_from_u64(0),
    )
    .unwrap()
}

fn to_bits_le(byte: u8) -> [u8; 8] {
    let mut bits = [0u8; 8];
    for i in 0..8 {
        bits[i] = (byte >> i) & 1;
    }
    bits
}

fn verify(vk: &VerifyingKey<Bls12_381>, proof: &Proof<Bls12_381>, image_bytes: &[u8]) -> bool {
    let public_inputs = image_bytes
        .iter()
        .cloned()
        .flat_map(to_bits_le)
        .map(Fr::from)
        .collect::<Vec<_>>();
    Groth16::<Bls12_381>::verify(vk, &public_inputs, proof).unwrap()
}

fn main() {
    let preimage = b"A".to_vec();
    let image =
        hex::decode("559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd").unwrap();
    println!("Generating keys...");
    let pk = generate_keys(preimage.clone(), image.clone());
    println!("Generating proof...");
    println!("image len: {}", image.len());
    let proof = create_proof(&pk, preimage, image.clone());

    println!("vk len: {}", pk.vk.gamma_abc_g1.len());

    if verify(&pk.vk, &proof, &image) {
        println!("Proof is valid!");
    } else {
        println!("Proof verification failed.");
    }
}
