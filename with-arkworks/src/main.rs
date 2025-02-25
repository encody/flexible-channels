use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_relations::{
    lc, ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, serialize_to_vec};
use ark_snark::SNARK;
use ark_std::rand::{self, SeedableRng, rngs::StdRng};

#[derive(Clone)]
struct MultiplyCircuit {
    pub x: Option<Fr>, // Private input
    pub y: Option<Fr>, // Private input
    pub z: Fr,         // Public output (x * y)
}

// Implementing the constraint system
impl ConstraintSynthesizer<Fr> for MultiplyCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let x = cs.new_witness_variable(|| self.x.ok_or(SynthesisError::AssignmentMissing))?;
        let y = cs.new_witness_variable(|| self.y.ok_or(SynthesisError::AssignmentMissing))?;
        let z = cs.new_input_variable(|| Ok(self.z))?;

        // Enforce x * y = z
        cs.enforce_constraint(lc!() + x, lc!() + y, lc!() + z)?;

        Ok(())
    }
}

fn generate_keys() -> ProvingKey<Bls12_381> {
    let circuit = MultiplyCircuit {
        x: None,
        y: None,
        z: Fr::from(12001u32), // Publicly known output
    };

    Groth16::<Bls12_381>::generate_random_parameters_with_reduction(
        circuit,
        &mut rand::prelude::StdRng::seed_from_u64(0u64),
    )
    .unwrap()
}

fn create_proof(pk: &ProvingKey<Bls12_381>) -> Proof<Bls12_381> {
    let circuit = MultiplyCircuit {
        x: Some(Fr::from(3u32)), // Secret input
        y: Some(Fr::from(4u32)), // Secret input
        z: Fr::from(12u32),      // Publicly known output
    };

    Groth16::<Bls12_381>::create_random_proof_with_reduction(
        circuit,
        pk,
        &mut StdRng::seed_from_u64(0),
    )
    .unwrap()
}

fn verify(vk: &VerifyingKey<Bls12_381>, proof: &Proof<Bls12_381>) -> bool {
    let public_inputs = vec![Fr::from(12u32)]; // Public input
    Groth16::<Bls12_381>::verify(vk, &public_inputs, proof).unwrap()
}

fn main() {
    println!("Generating keys...");
    let pk = generate_keys();
    println!("Generating proof...");
    let proof = create_proof(&pk);

    let serialized = serialize_to_vec!(proof).unwrap();
    println!("Serialized length: {} bytes", serialized.len());

    let deserialized = Proof::<Bls12_381>::deserialize_uncompressed(&serialized[..]).unwrap();

    if verify(&pk.vk, &deserialized) {
        println!("Proof is valid!");
    } else {
        println!("Proof verification failed.");
    }
}
