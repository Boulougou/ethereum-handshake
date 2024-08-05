use anyhow::Result;
use bytes::Bytes;

pub struct AckMessage {
}

impl AckMessage {
    pub fn decode(_bytes: &Bytes) -> Result<AckMessage> {
        todo!()
    }
}
