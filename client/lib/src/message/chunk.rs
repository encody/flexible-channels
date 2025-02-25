use std::num::NonZeroU64;

use tokio::sync::Mutex;

use crate::channel::CorrespondentId;

use super::{
    cleartext::CleartextMessage,
    stream::{ReadStream, SingleCorrespondentStream, WriteStream},
    to_message_bytes::ToMessageBytes,
};

#[derive(Clone, Debug)]
pub struct MessageChunk {
    pub remaining_chunks: u8,
    pub bytes: Vec<u8>,
}

impl ToMessageBytes for MessageChunk {
    fn to_message_bytes(&self) -> Vec<u8> {
        self.to_bytes()
    }
}

impl MessageChunk {
    pub fn to_chunks(bytes: &[u8], chunk_size: usize) -> impl Iterator<Item = Self> + '_ {
        // -1 to account for MessageChunk::remaining_chunks.
        let chunks = bytes.chunks(chunk_size - 1);
        let length = u8::try_from(chunks.len()).expect("Message too long (number of chunks > 255)");

        chunks.enumerate().map(move |(i, chunk)| MessageChunk {
            remaining_chunks: length - i as u8 - 1,
            bytes: chunk.to_vec(),
        })
    }

    // pub fn try_from_chunks(chunks: &[MessageChunk]) -> Option<Vec<u8>> {
    //     let mut bytes = Vec::new();
    //     for chunk in chunks {
    //         bytes.extend(&chunk.bytes);
    //     }
    //     bytes
    // }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + self.bytes.len());
        buf.extend(self.remaining_chunks.to_le_bytes());
        buf.extend(&self.bytes);
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let remaining_chunks = bytes[0];
        let bytes = bytes[1..].to_vec();
        Self {
            remaining_chunks,
            bytes,
        }
    }
}

#[derive(Default)]
pub struct ChunkedReadStream<T> {
    inner: T,
    partial_message: Mutex<PartialMessage>,
}

impl<T> ChunkedReadStream<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            partial_message: Default::default(),
        }
    }
}

#[derive(Default)]
struct PartialMessage {
    block_timestamp_ms: Option<NonZeroU64>,
    buffer: Vec<u8>,
}

impl<T: SingleCorrespondentStream> SingleCorrespondentStream for ChunkedReadStream<T> {
    fn correspondent_id(&self) -> CorrespondentId {
        self.inner.correspondent_id()
    }
}

impl<T: ReadStream<Output = CleartextMessage> + SingleCorrespondentStream + Sync> ReadStream
    for ChunkedReadStream<T>
{
    type Output = CleartextMessage;

    async fn receive_next(&self) -> anyhow::Result<Option<Self::Output>> {
        loop {
            let Some(next) = self.inner.receive_next().await? else {
                return Ok(None);
            };
            let mut partial_message = self.partial_message.lock().await;
            if partial_message.block_timestamp_ms.is_none() && next.block_timestamp_ms != 0 {
                partial_message.block_timestamp_ms =
                    Some(next.block_timestamp_ms.try_into().unwrap());
            }
            let next = MessageChunk::from_bytes(&next.to_message_bytes());

            // dbg!(&next);
            partial_message.buffer.extend(next.bytes);

            if next.remaining_chunks == 0 {
                let block_timestamp_ms = partial_message
                    .block_timestamp_ms
                    .take()
                    .map(Into::into)
                    .unwrap_or(0);
                return Ok(Some(CleartextMessage {
                    block_timestamp_ms,
                    bytes: partial_message.buffer.drain(..).collect(),
                }));
            }
        }
    }
}

pub struct ChunkedWriteStream<T> {
    inner: T,
    chunk_size: usize,
}

impl<T> ChunkedWriteStream<T> {
    pub fn new(inner: T, chunk_size: usize) -> Self {
        Self { inner, chunk_size }
    }
}

impl<T: WriteStream> WriteStream for ChunkedWriteStream<T> {
    async fn send<I: ToMessageBytes>(&self, input: I) -> anyhow::Result<()> {
        for chunk in MessageChunk::to_chunks(&input.to_message_bytes(), self.chunk_size) {
            self.inner.send(chunk).await?;
        }

        Ok(())
    }
}
