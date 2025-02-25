use std::{collections::HashMap, sync::Arc};

use anyhow::bail;
use near_primitives::types::AccountId;
use tokio::sync::RwLock; // TODO: can we remove?
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{
    channel::CorrespondentId, group::Group, key_registry::KeyRegistry,
    message_repository::MessageRepository, wallet::Wallet,
};

pub struct Messenger {
    secret_key: StaticSecret,
    key_registry: KeyRegistry,
    correspondent_map: Arc<RwLock<HashMap<CorrespondentId, AccountId>>>,
    pub message_repository: Arc<MessageRepository>,
}

impl Messenger {
    pub fn new(
        wallet: Arc<Wallet>,
        messenger_secret_key: StaticSecret,
        key_registry_account_id: &AccountId,
        message_repository_account_id: &AccountId,
    ) -> Self {
        let mut correspondent_map = HashMap::new();
        correspondent_map.insert(
            PublicKey::from(&messenger_secret_key).to_bytes().into(),
            wallet.account_id.clone(),
        );

        Self {
            secret_key: messenger_secret_key,
            key_registry: KeyRegistry::new(Arc::clone(&wallet), key_registry_account_id),
            correspondent_map: Arc::new(RwLock::new(correspondent_map)),
            message_repository: Arc::new(MessageRepository::new(
                Arc::clone(&wallet),
                message_repository_account_id,
            )),
        }
    }

    pub async fn resolve_correspondent_id(
        &self,
        correspondent_id: &CorrespondentId,
    ) -> Option<AccountId> {
        self.correspondent_map
            .read()
            .await
            .get(correspondent_id)
            .cloned()
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey::from(&self.secret_key)
    }

    pub async fn sync_key(&self) -> anyhow::Result<()> {
        self.key_registry
            .set_my_key(&PublicKey::from(&self.secret_key))
            .await
    }

    pub async fn direct_message(&self, account_id: &AccountId) -> anyhow::Result<Group> {
        let correspondent_public_key = self.key_registry.get_key_for(account_id).await?;
        let correspondent_public_key: [u8; 32] = match correspondent_public_key.try_into() {
            Ok(a) => a,
            Err(e) => bail!("Invalid key length {}", e.len()),
        };
        let correspondent_id: CorrespondentId = correspondent_public_key.into();
        self.correspondent_map
            .write()
            .await
            .insert(correspondent_id, account_id.clone());
        let shared_secret = self
            .secret_key
            .diffie_hellman(&correspondent_public_key.into())
            .to_bytes();
        let group = Group::new(
            Arc::clone(&self.message_repository),
            self.public_key().to_bytes().into(),
            vec![correspondent_public_key.into()],
            shared_secret,
            &[2], // no context for direct message (?)
        );

        Ok(group)
    }
}
