use std::time::SystemTime;

use anyhow::Result;
use p2panda_core::{Body, Extension, Header, Operation, PrivateKey};
use p2panda_engine::extensions::PruneFlag;
use p2panda_store::{LogStore, MemoryStore, OperationStore};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Extensions {
    #[serde(rename = "s")]
    pub log_id: u64,

    #[serde(rename = "p", skip_serializing_if = "Option::is_none")]
    pub prune_flag: Option<PruneFlag>,
}

impl Extension<u64> for Extensions {
    fn extract(&self) -> Option<u64> {
        Some(self.log_id)
    }
}

impl Extension<PruneFlag> for Extensions {
    fn extract(&self) -> Option<PruneFlag> {
        self.prune_flag
            .clone()
            .or_else(|| Some(PruneFlag::default()))
    }
}

pub fn encode_payload<E>(header: Header<E>, body: Option<Body>) -> Result<Vec<u8>>
where
    E: Clone + Serialize,
{
    let operation: (Header<E>, Option<Body>) = (header, body);
    let mut bytes = Vec::new();
    ciborium::into_writer(&operation, &mut bytes)?;
    Ok(bytes)
}

pub fn decode_payload<E>(bytes: &[u8]) -> Result<(Header<E>, Option<Body>)>
where
    E: DeserializeOwned,
{
    let raw_operation = ciborium::from_reader(bytes)?;
    Ok(raw_operation)
}

pub async fn create_operation(
    store: &mut MemoryStore<u64, Extensions>,
    private_key: &PrivateKey,
    log_id: u64,
    body: Option<&[u8]>,
    prune_flag: bool,
) -> Result<Operation<Extensions>> {
    let body = body.map(Body::new);

    let public_key = private_key.public_key();

    let latest_operation = store.latest_operation(&public_key, &log_id).await?;

    let (seq_num, backlink) = match latest_operation {
        Some(operation) => (operation.header.seq_num + 1, Some(operation.hash)),
        None => (0, None),
    };

    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs();

    let extensions = Extensions {
        log_id,
        prune_flag: Some(PruneFlag::new(prune_flag)),
    };

    let mut header = Header {
        version: 1,
        public_key,
        signature: None,
        payload_size: body.as_ref().map_or(0, |body| body.size()),
        payload_hash: body.as_ref().map(|body| body.hash()),
        timestamp,
        seq_num,
        backlink,
        previous: vec![],
        extensions: Some(extensions),
    };
    header.sign(private_key);

    let operation = Operation {
        hash: header.hash(),
        header,
        body,
    };

    store.insert_operation(&operation, &log_id).await?;

    if prune_flag {
        assert!(
            operation.header.seq_num > 0,
            "can't prune from first operation in log"
        );
        store
            .delete_operations(
                &operation.header.public_key,
                &log_id,
                operation.header.seq_num,
            )
            .await?;
    }

    Ok(operation)
}
