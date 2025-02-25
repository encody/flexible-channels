pub mod channel;
pub mod combined;
pub mod group;
pub mod key_registry;
pub mod message;
pub mod message_repository;
pub mod messenger;
pub mod wallet;

#[cfg(test)]
mod tests {
    use data_encoding::BASE64;
    use rand::rngs::OsRng;

    #[test]
    #[ignore = "Use to generate test keys"]
    fn generate_messenger_secret_key() {
        let messenger_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let secret_key_b64 = BASE64.encode(messenger_secret_key.as_bytes());
        println!("\"{secret_key_b64}\"");
    }
}
