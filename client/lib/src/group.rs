use std::{borrow::Borrow, sync::Arc};

use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, RwLock};

use crate::{
    channel::{Channel, CorrespondentId, SequenceHashProducer},
    message::{
        chunk::ChunkedReadStream,
        cleartext::CleartextMessage,
        stream::{ReadStream, SingleCorrespondentStream, WriteStream},
        to_message_bytes::ToMessageBytes,
    },
    message_repository::MessageRepository,
};

pub struct Group {
    message_repository: Arc<MessageRepository>,
    send_messages_from_member_index: usize,
    members: Vec<CorrespondentId>,
    next_message_read_index: RwLock<Vec<u32>>,
    next_message_write_index: RwLock<Vec<u32>>,
    shared_secret: [u8; 32],
    identifier: [u8; 256],
}

impl Group {
    pub fn new(
        message_repository: Arc<MessageRepository>,
        send_messages_from_member: CorrespondentId,
        mut other_members: Vec<CorrespondentId>,
        shared_secret: [u8; 32],
        context: &[u8],
    ) -> Self {
        other_members.push(send_messages_from_member.clone());
        let mut members = other_members;
        members.sort();
        let send_messages_from_member_index = members
            .iter()
            .position(|m| m == &send_messages_from_member)
            .unwrap(); // unwrap ok because we know this item exists in the vec

        let mut members_hash = <Sha256 as Digest>::new();
        for member in members.iter() {
            members_hash.update(member);
        }
        let members_hash = members_hash.finalize();

        let context_hash = <Sha256 as Digest>::new().chain_update(context).finalize();

        let mut identifier = [0u8; 256];
        identifier[0..32].copy_from_slice(&members_hash);
        identifier[64..96].copy_from_slice(&shared_secret);
        identifier[96..128].copy_from_slice(&context_hash);

        let nmi = members
            .iter()
            .enumerate()
            .map(|(i, _)| i as u32)
            .collect::<Vec<_>>();
        let next_message_read_index = RwLock::new(nmi.clone());
        let next_message_send_index = RwLock::new(nmi);

        Self {
            message_repository,
            members,
            send_messages_from_member_index,
            next_message_read_index,
            next_message_write_index: next_message_send_index,
            shared_secret,
            identifier,
        }
    }

    pub fn get_correspondent_index(&self, correspondent_id: &CorrespondentId) -> Option<u32> {
        self.members
            .iter()
            .position(|m| m == correspondent_id)
            .map(|i| i as u32)
    }

    pub fn nonce_for_message(&self, message_index: u32, correspondent_index: u32) -> u32 {
        self.members.len() as u32 * message_index + correspondent_index
    }

    pub async fn receive_next_for(
        &self,
        correspondent_index: u32,
    ) -> anyhow::Result<Option<CleartextMessage>> {
        let message_index = self.next_message_read_index.read().await[correspondent_index as usize];
        let nonce = self.nonce_for_message(message_index, correspondent_index);
        let sequence_hash = self.sequence_hash(nonce);

        let response = self.message_repository.get_message(&*sequence_hash).await?;

        let Some(ciphertext) = response else {
            return Ok(None);
        };

        let cleartext = self.decrypt(nonce, &ciphertext.message)?;

        let ci = correspondent_index as usize;
        let mut next_message_read_index = self.next_message_read_index.write().await;
        next_message_read_index[ci] += 1;
        let mut next_message_write_index = self.next_message_write_index.write().await;
        next_message_write_index[ci] =
            u32::max(next_message_write_index[ci], next_message_read_index[ci]);

        Ok(Some(CleartextMessage {
            bytes: cleartext,
            block_timestamp_ms: ciphertext.block_timestamp_ms,
        }))
    }

    pub fn read_stream(
        self: &Arc<Self>,
    ) -> impl ReadStream<Output = (CorrespondentId, CleartextMessage)> {
        MultiplexedReadStream::new(self.members.iter().enumerate().map(|(i, _)| {
            ChunkedReadStream::new(GroupCorrespondentReadStream {
                group: Arc::clone(self),
                target_correspondent_index: i as u32,
            })
        }))
    }
}

impl<T: Borrow<Group>> WriteStream for T {
    async fn send<I: ToMessageBytes>(&self, input: I) -> anyhow::Result<()> {
        let s: &Group = self.borrow();

        let mut next_message_write_index = s.next_message_write_index.write().await;
        let message_index = next_message_write_index[s.send_messages_from_member_index];
        next_message_write_index[s.send_messages_from_member_index] += 1;

        let nonce = s.nonce_for_message(message_index, s.send_messages_from_member_index as u32);
        let sequence_hash = s.sequence_hash(nonce);
        let ciphertext = s.encrypt(nonce, &input.to_message_bytes())?;
        s.message_repository
            .publish_message(&*sequence_hash, &ciphertext)
            .await?;

        Ok(())
    }
}

impl Channel for Group {
    fn secret_identifier(&self) -> &[u8; 256] {
        &self.identifier
    }

    fn shared_secret(&self) -> &[u8; 32] {
        &self.shared_secret
    }
}

pub struct GroupCorrespondentReadStream {
    group: Arc<Group>,
    target_correspondent_index: u32,
}

impl ReadStream for GroupCorrespondentReadStream {
    type Output = CleartextMessage;

    async fn receive_next(&self) -> anyhow::Result<Option<Self::Output>> {
        self.group
            .receive_next_for(self.target_correspondent_index)
            .await
    }
}

impl SingleCorrespondentStream for GroupCorrespondentReadStream {
    fn correspondent_id(&self) -> CorrespondentId {
        self.group.members[self.target_correspondent_index as usize].clone()
    }
}

struct BufferedReadStream<T: ReadStream> {
    stream: T,
    next_message: Option<CleartextMessage>,
}

impl<T: ReadStream> BufferedReadStream<T> {
    pub fn new(stream: T) -> Self {
        Self {
            stream,
            next_message: None,
        }
    }
}

pub struct MultiplexedReadStream<T: ReadStream> {
    streams: Mutex<Vec<BufferedReadStream<T>>>,
}

impl<T: ReadStream> MultiplexedReadStream<T> {
    pub fn new(streams: impl IntoIterator<Item = T>) -> Self {
        Self {
            streams: Mutex::new(streams.into_iter().map(BufferedReadStream::new).collect()),
        }
    }
}

impl<T: ReadStream<Output = CleartextMessage> + SingleCorrespondentStream + Send> ReadStream
    for MultiplexedReadStream<T>
{
    type Output = (CorrespondentId, CleartextMessage);

    async fn receive_next(&self) -> anyhow::Result<Option<Self::Output>> {
        let mut stream_index_with_oldest_message = None;

        let mut streams = self.streams.lock().await;

        for (i, stream) in streams.iter_mut().enumerate() {
            let next_message_timestamp = if let Some(next_message) = &stream.next_message {
                Some(next_message.block_timestamp_ms)
            } else {
                let next_message = stream.stream.receive_next().await?;
                if let Some(next_message) = next_message {
                    let timestamp = next_message.block_timestamp_ms;
                    stream.next_message = Some(next_message);
                    Some(timestamp)
                } else {
                    None
                }
            };

            if let Some(next_message_timestamp) = next_message_timestamp {
                match stream_index_with_oldest_message {
                    Some((oldest_timestamp, _)) if oldest_timestamp < next_message_timestamp => {}
                    _ => {
                        stream_index_with_oldest_message = Some((next_message_timestamp, i));
                    }
                }
            }
        }

        Ok(if let Some((_, i)) = stream_index_with_oldest_message {
            let stream = &mut streams[i];
            let next_message = stream.next_message.take().unwrap();
            Some((stream.stream.correspondent_id().clone(), next_message))
        } else {
            None
        })
    }
}
