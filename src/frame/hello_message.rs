use bytes::{Bytes, BytesMut};
use rlp::{Rlp, RlpStream};
use anyhow::{anyhow, Context, Result};

#[derive(Debug)]
pub struct HelloMessage {
    pub protocol_version: u16,
    pub client_id: String,
    pub capabilities: Vec<(String, usize)>,
    pub listen_port: u16,
    pub node_id: secp256k1::PublicKey,
}

const HELLO_MESSAGE_ID : u8 = 0;

impl HelloMessage {
    pub fn new(node_public_key: &secp256k1::PublicKey) -> HelloMessage {
        HelloMessage {
            protocol_version: 5,
            client_id: String::from("Boulougou-Ethereum/0.1.0"),
            capabilities: vec!((String::from("eth"), 68)),
            listen_port: 0, // unused legacy field according to spec
            node_id: *node_public_key
        }
    }
    pub fn encode(&self) -> BytesMut {
        let mut rlp_stream = RlpStream::new();
        rlp_stream.append(&HELLO_MESSAGE_ID);

        rlp_stream.begin_unbounded_list();
        rlp_stream.append(&self.protocol_version);
        rlp_stream.append(&self.client_id);
        self.encode_capabilities(&mut rlp_stream);
        rlp_stream.append(&self.listen_port);
        self.encode_node_id(&mut rlp_stream);
        rlp_stream.finalize_unbounded_list();

        rlp_stream.out()
    }

    fn encode_node_id(&self, rlp_stream: &mut RlpStream) {
        rlp_stream.append(&self.node_id.serialize_uncompressed()[1..].to_vec());
    }

    fn encode_capabilities(&self, rlp_stream: &mut RlpStream) {
        rlp_stream.begin_list(self.capabilities.len());
        for cap in &self.capabilities {
            rlp_stream.begin_list(2);
            rlp_stream.append(&cap.0);
            rlp_stream.append(&cap.1);
        }
    }

    pub fn decode(bytes: &Bytes) -> Result<HelloMessage> {
        let rlp_msg = Rlp::new(&bytes[..1]);
        Self::decode_and_verify_message_id(rlp_msg)?;

        let rlp_msg = Rlp::new(&bytes[1..]);
        let protocol_version = Self::decode_protocol_version(&rlp_msg)?;
        let client_id = Self::decode_client_id(&rlp_msg)?;
        let capabilities = Self::decode_capabilities(&rlp_msg)?;
        let listen_port = Self::decode_listening_port(&rlp_msg)?;
        let node_id = Self::decode_public_key(&rlp_msg)?;

        Ok(HelloMessage {
            protocol_version,
            client_id,
            capabilities,
            listen_port,
            node_id
        })
    }

    fn decode_and_verify_message_id(rlp_msg: Rlp) -> Result<()> {
        let message_id: u8 = rlp_msg.as_val().context("failed to decode message id")?;
        if message_id != HELLO_MESSAGE_ID {
            return Err(anyhow!("Received message is not a Hello message, message-id: {message_id}"));
        }

        Ok(())
    }

    fn decode_listening_port(rlp_msg: &Rlp) -> Result<u16> {
        let listen_port: u16 = rlp_msg.val_at(3).context("failed to parse listening port")?;
        Ok(listen_port)
    }

    fn decode_client_id(rlp_msg: &Rlp) -> Result<String> {
        let client_id: String = rlp_msg.val_at(1).context("failed to parse client id")?;
        Ok(client_id)
    }

    fn decode_protocol_version(rlp_msg: &Rlp) -> Result<u16> {
        let protocol_version: u16 = rlp_msg.val_at(0).context("failed to parse protocol version")?;
        Ok(protocol_version)
    }

    fn decode_capabilities(rlp_msg: &Rlp) -> Result<Vec<(String, usize)>> {
        let nested_list = rlp_msg.at(2).context("failed to get nested capabilities list")?;
        let mut capabilities = Vec::new();
        for val in nested_list.iter() {
            let capability: String = val.val_at(0).context("failed to parse capability name")?;
            let version: usize = val.val_at(1).context("failed to parse capability version")?;
            capabilities.push((capability, version));
        }
        Ok(capabilities)
    }

    fn decode_public_key(rlp_msg: &Rlp) -> Result<secp256k1::PublicKey> {
        let public_key_bytes: Bytes = rlp_msg.val_at(4)?;

        let mut uncompressed_key_bytes = Vec::with_capacity(65);
        uncompressed_key_bytes.push(0x04);
        uncompressed_key_bytes.extend_from_slice(&public_key_bytes);

        let public_key = secp256k1::PublicKey::from_slice(&uncompressed_key_bytes).
            context("failed to parse public key")?;

        Ok(public_key)
    }
}
