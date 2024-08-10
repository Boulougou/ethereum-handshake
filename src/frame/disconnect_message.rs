use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use rlp::Rlp;

#[derive(Debug)]
pub struct DisconnectMessage {
    pub reason: u8
}

const DISCONNECT_MESSAGE_ID : u8 = 1;

impl DisconnectMessage {

    pub fn decode(bytes: &Bytes) -> Result<DisconnectMessage> {
        let rlp_msg = Rlp::new(&bytes[..1]);
        let message_id : u8 = rlp_msg.as_val()?;
        if message_id != DISCONNECT_MESSAGE_ID {
            return Err(anyhow!("Received message is not a Disconnect message, message-id: {message_id}"));
        }

        let rlp_msg = Rlp::new(&bytes[1..]);
        let reason: u8 = rlp_msg.as_val().context("failed to parse reason")?;

        Ok(DisconnectMessage {
            reason
        })
    }
}
