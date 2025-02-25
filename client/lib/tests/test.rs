use std::sync::Arc;

use data_encoding::BASE64;
use fc_client::{combined::CombinedMessageStream, messenger::Messenger, wallet::Wallet};
use near_workspaces::{network::Sandbox, Account, AccountId, Contract, Worker};
use rand::rngs::OsRng;
use serde_json::json;
use tokio::sync::OnceCell;

enum ContractWasm {
    MessageRepository,
    KeyRegistry,
}

impl ContractWasm {
    async fn load(&self) -> &'static [u8] {
        static MESSAGE_REPOSITORY_WASM: OnceCell<&'static [u8]> = OnceCell::const_new();
        static KEY_REGISTRY_WASM: OnceCell<&'static [u8]> = OnceCell::const_new();

        let (cell, path) = match self {
            ContractWasm::MessageRepository => (
                &MESSAGE_REPOSITORY_WASM,
                "../../contract/message-repository/",
            ),
            ContractWasm::KeyRegistry => (&KEY_REGISTRY_WASM, "../../contract/key-registry/"),
        };

        cell.get_or_init(|| async {
            Box::new(near_workspaces::compile_project(path).await.unwrap()).leak()
                as &'static [u8]
        })
        .await
    }
}

async fn prefixed_account(worker: &Worker<Sandbox>, prefix: &str) -> Account {
    assert!(
        prefix.len() <= AccountId::MAX_LEN,
        "prefix longer than max account ID length",
    );

    let (old_id, sk) = worker.dev_generate().await;
    let id: AccountId = format!("{prefix}{}", &old_id.as_str()[prefix.len()..])
        .parse()
        .unwrap();

    worker.create_tla(id, sk).await.unwrap().result
}

async fn deploy_with_prefix_and_init(
    worker: &Worker<Sandbox>,
    prefix: &str,
    wasm: &[u8],
) -> Contract {
    let contract = prefixed_account(worker, prefix)
        .await
        .deploy(wasm)
        .await
        .unwrap()
        .result;

    contract
        .call("new")
        .args_json(json!({}))
        .transact()
        .await
        .unwrap()
        .unwrap();

    contract
}

async fn create_messenger(
    worker: &Worker<Sandbox>,
    key_registry_contract_id: &AccountId,
    message_repository_contract_id: &AccountId,
    account: &Account,
) -> Arc<Messenger> {
    let signer = near_crypto::InMemorySigner::from_secret_key(
        account.id().clone(),
        account.secret_key().to_string().parse().unwrap(),
    );

    let wallet = Arc::new(Wallet::new(
        worker.rpc_addr(),
        signer.account_id.clone(),
        signer.into(),
    ));

    let messenger_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);

    let messenger = Arc::new(Messenger::new(
        Arc::clone(&wallet),
        messenger_key.clone(),
        key_registry_contract_id,
        message_repository_contract_id,
    ));

    messenger.sync_key().await.unwrap();

    messenger
}

#[tokio::test]
async fn happy_path() {
    let (worker, message_repository_wasm, key_registry_wasm) = tokio::join!(
        async { near_workspaces::sandbox().await.unwrap() },
        async { ContractWasm::MessageRepository.load().await },
        async { ContractWasm::KeyRegistry.load().await },
    );

    let (message_repository_contract, key_registry_contract, alice, bob) = tokio::join!(
        deploy_with_prefix_and_init(&worker, "msgrepo", message_repository_wasm),
        deploy_with_prefix_and_init(&worker, "keyreg", key_registry_wasm),
        prefixed_account(&worker, "alice"),
        prefixed_account(&worker, "bob"),
    );

    println!("Creating messengers & syncing keys...");

    let (alice_messenger, bob_messenger) = tokio::join!(
        create_messenger(
            &worker,
            key_registry_contract.id(),
            message_repository_contract.id(),
            &alice
        ),
        create_messenger(
            &worker,
            key_registry_contract.id(),
            message_repository_contract.id(),
            &bob
        ),
    );

    let key_registry = KeyRegistry::new(&key_registry_contract);
    assert_eq!(
        key_registry.get_public_key(alice.id()).await,
        alice_messenger.public_key().as_bytes(),
    );
    assert_eq!(
        key_registry.get_public_key(bob.id()).await,
        bob_messenger.public_key().as_bytes(),
    );
    println!("Keys synced!");

    let alice_group_with_bob = alice_messenger.direct_message(bob.id()).await.unwrap();
    let bob_group_with_alice = bob_messenger.direct_message(alice.id()).await.unwrap();
    let mut bob_group_receive = CombinedMessageStream::new(bob_group_with_alice.streams());

    alice_group_with_bob.send("dm 1").await.unwrap();

    let (bob_received_dm_1_from, bob_received_dm_1_message) =
        bob_group_receive.next().await.unwrap().unwrap();

    assert_eq!(
        &**bob_received_dm_1_from,
        alice_messenger.public_key().as_bytes(),
    );
    assert_eq!(
        String::from_utf8(bob_received_dm_1_message.bytes).unwrap(),
        "dm 1",
    );

    let mut alice_group_receive = CombinedMessageStream::new(alice_group_with_bob.streams());

    let (alice_received_dm_1_from, alice_received_dm_1_message) =
        alice_group_receive.next().await.unwrap().unwrap();

    assert_eq!(
        &**alice_received_dm_1_from,
        alice_messenger.public_key().as_bytes(),
    );
    assert_eq!(
        String::from_utf8(alice_received_dm_1_message.bytes).unwrap(),
        "dm 1",
    );
}

struct KeyRegistry<'a> {
    contract: &'a Contract,
}

impl<'a> KeyRegistry<'a> {
    pub fn new(contract: &'a Contract) -> Self {
        Self { contract }
    }

    pub async fn get_public_key(&self, account_id: &AccountId) -> Vec<u8> {
        let encoded = self
            .contract
            .view("get_public_key")
            .args_json(json!({
                "account_id": account_id,
            }))
            .await
            .unwrap()
            .json::<String>()
            .unwrap();

        BASE64.decode(encoded.as_bytes()).unwrap()
    }
}
