use anyhow::bail;
use base64ct::{Base64, Encoding};
use near_primitives::{
    transaction::{Action, FunctionCallAction},
    types::AccountId,
};
use serde_json::json;

use crate::{
    channel::Channel,
    wallet::{Wallet, ONE_NEAR, ONE_TERAGAS},
};

pub struct MessageRepository<'a> {
    wallet: &'a Wallet,
    account_id: AccountId,
}

impl<'a> MessageRepository<'a> {
    pub fn new(wallet: &'a Wallet, account_id: &'_ AccountId) -> Self {
        Self {
            wallet,
            account_id: account_id.clone(),
        }
    }

    pub async fn get_message(&self, sequence_hash: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
        let base64_encoded_message: Option<String> = self
            .wallet
            .view::<Option<String>>(
                self.account_id.clone(),
                "get_message",
                json!({ "sequence_hash": Base64::encode_string(sequence_hash) }),
            )
            .await?;

        let base64_encoded_message = match base64_encoded_message {
            Some(r) => r,
            _ => return Ok(None),
        };

        let message = match Base64::decode_vec(&base64_encoded_message) {
            Ok(d) => d,
            Err(e) => bail!("Error decoding from base64: {}", e),
        };

        Ok(Some(message))
    }

    pub async fn publish_message(
        &self,
        sequence_hash: &[u8],
        ciphertext: &[u8],
    ) -> anyhow::Result<()> {
        self.wallet
            .transact(
                self.account_id.clone(),
                vec![Action::FunctionCall(FunctionCallAction {
                    method_name: "publish".to_string(),
                    args: json!({
                        "sequence_hash": Base64::encode_string(sequence_hash),
                        "message": Base64::encode_string(ciphertext),
                    })
                    .to_string()
                    .into_bytes()
                    .into(),
                    gas: 300 * ONE_TERAGAS,
                    deposit: ONE_NEAR,
                })],
            )
            .await?;

        Ok(())
    }

    pub async fn discover_first_unused_nonce(&self, channel: &Channel) -> anyhow::Result<u32> {
        // stupid linear search for now.
        // obviously should use some sort of exponential bounds discovery and then binary search,
        // but too lazy to do that now.
        for i in 0.. {
            let sequence_hash = channel.sequence_hash(i);
            if let None = self.get_message(&*sequence_hash).await? {
                return Ok(i);
            }
        }

        bail!("Somehow you've sent {} messages", u32::MAX);
    }
}
