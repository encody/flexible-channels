use std::future::Future;

use crate::channel::CorrespondentId;

use super::to_message_bytes::ToMessageBytes;

pub trait ReadStream {
    type Output;

    fn receive_next(&self) -> impl Future<Output = anyhow::Result<Option<Self::Output>>> + Send;
}

pub trait WriteStream {
    fn send<I: ToMessageBytes>(&self, input: I) -> impl Future<Output = anyhow::Result<()>>;
}

pub trait SingleCorrespondentStream {
    fn correspondent_id(&self) -> CorrespondentId;
}
