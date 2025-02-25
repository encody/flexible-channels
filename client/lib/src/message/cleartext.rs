use super::to_message_bytes::ToMessageBytes;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CleartextMessage {
    pub block_timestamp_ms: u64,
    pub bytes: Vec<u8>,
}

impl ToMessageBytes for CleartextMessage {
    fn to_message_bytes(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }
}
