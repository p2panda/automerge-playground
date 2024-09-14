use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use anyhow::{anyhow, Context, Result};
use async_stream::stream;
use automerge::transaction::Transactable;
use automerge::{AutoCommit, ObjType};
use futures::StreamExt;
use p2panda_core::{
    validate_backlink, validate_operation, Body, Extension, Header, Operation, OperationError,
    PrivateKey,
};
use p2panda_net::network::{InEvent, OutEvent};
use p2panda_net::{LocalDiscovery, NetworkBuilder};
use p2panda_store::{LogStore, MemoryStore, OperationStore};
use p2panda_sync::protocols::log_height::LogHeightSyncProtocol;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::task;
use tokio_stream::wrappers::{BroadcastStream, ReceiverStream};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

const NETWORK_ID: [u8; 32] = [
    88, 32, 213, 152, 167, 24, 186, 1, 3, 254, 88, 233, 132, 3, 250, 122, 6, 92, 186, 200, 3, 56,
    15, 250, 97, 54, 147, 196, 19, 200, 72, 168,
];

const TEST_TOPIC_ID: [u8; 32] = [1; 32];

#[derive(Clone, Debug, Hash, Default, Eq, PartialEq, Serialize, Deserialize)]
struct LogId(pub u64);

#[derive(Clone, Debug, Hash, Default, Eq, PartialEq, Serialize, Deserialize)]
struct PruneFlag(pub bool);

impl PruneFlag {
    fn is_set(&self) -> bool {
        self.0
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
struct Extensions {
    #[serde(rename = "l")]
    pub log_id: LogId,

    #[serde(
        rename = "p",
        skip_serializing_if = "std::ops::Not::not",
        default = "default_prune_flag"
    )]
    pub prune_flag: bool,
}

fn default_prune_flag() -> bool {
    false
}

impl Extension<LogId> for Extensions {
    fn extract(&self) -> Option<LogId> {
        Some(self.log_id.clone())
    }
}

impl Extension<PruneFlag> for Extensions {
    fn extract(&self) -> Option<PruneFlag> {
        Some(PruneFlag(self.prune_flag))
    }
}

#[derive(Clone)]
struct Store(Arc<RwLock<MemoryStore<LogId, Extensions>>>);

impl Store {
    pub fn new() -> Self {
        Self(Arc::new(RwLock::new(MemoryStore::new())))
    }
}

fn input_loop(line_tx: mpsc::Sender<String>) -> Result<()> {
    let mut buffer = String::new();
    let stdin = std::io::stdin();
    loop {
        stdin.read_line(&mut buffer)?;
        line_tx.blocking_send(buffer.clone())?;
        buffer.clear();
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(EnvFilter::from_default_env())
        .try_init()
        .ok();

    let mut doc = AutoCommit::new();
    let contacts = doc.put_object(automerge::ROOT, "contacts", ObjType::List)?;
    let doc = Arc::new(RwLock::new(doc));

    let (line_tx, mut line_rx) = mpsc::channel(1);
    std::thread::spawn(move || input_loop(line_tx));

    let private_key = PrivateKey::new();
    let store = Store::new();
    let log_id = LogId(1);

    println!("me: {}", private_key.public_key());

    let mut sync_map = HashMap::new();
    sync_map.insert(TEST_TOPIC_ID, log_id.clone());

    let network = NetworkBuilder::new(
        NETWORK_ID,
        LogHeightSyncProtocol {
            log_ids: sync_map,
            store: store.0.clone(),
        },
    )
    .private_key(private_key.clone())
    .discovery(LocalDiscovery::new()?)
    .build()
    .await?;

    let (tx, rx) = network.subscribe(TEST_TOPIC_ID).await?;

    {
        let mut store = store.clone();
        let doc = doc.clone();

        task::spawn(async move {
            while let Some(text) = line_rx.recv().await {
                let parts: Vec<_> = text.split(' ').collect();

                if parts.len() != 3 && parts.len() != 4 {
                    continue;
                }

                let Ok(index) = usize::from_str(parts[0]) else {
                    continue;
                };

                let prune_flag = parts.len() == 4 && parts[3] == "prune";

                let bytes = {
                    let mut doc = doc.write().unwrap();
                    let item = doc.insert_object(&contacts, index, ObjType::Map).unwrap();
                    doc.put(&item, "name", parts[1]).unwrap();
                    doc.put(&item, "age", parts[2]).unwrap();

                    if prune_flag {
                        doc.save()
                    } else {
                        doc.save_incremental()
                    }
                };

                let operation =
                    create_operation(&mut store, &private_key, &log_id, Some(&bytes), prune_flag)
                        .await
                        .expect("creating operation");

                println!(
                    "created operation {} {}",
                    operation.header.seq_num, operation.header.public_key
                );
                let bytes =
                    encode_operation(operation.header, operation.body).expect("encoding operation");

                tx.send(InEvent::Message { bytes })
                    .await
                    .expect("sending message");
            }
        });
    }

    task::spawn(async move {
        let stream = BroadcastStream::new(rx);

        let stream = stream.filter_map(|event| async {
            match event {
                Ok(OutEvent::Ready) => None,
                Ok(OutEvent::Message { bytes, .. }) => match decode_operation(&bytes) {
                    Ok((header, body)) => {
                        println!(
                            "received operation {} {}",
                            header.seq_num, header.public_key
                        );

                        Some((header, body))
                    }
                    Err(err) => {
                        eprintln!("failed decoding operation: {err}");
                        None
                    }
                },
                Err(err) => {
                    eprintln!("failed receiver: {err}");
                    None
                }
            }
        });

        tokio::pin!(stream);

        let (buf_tx, buf_rx) = mpsc::channel::<Operation<Extensions>>(128);
        let mut buf_stream = ReceiverStream::new(buf_rx);
        let stream = stream! {
            loop {
                tokio::select! {
                    biased;

                    Some((header, body)) = stream.next() => {
                        yield (header, body);
                    }
                    Some(operation) = buf_stream.next() => {
                        yield (operation.header, operation.body);
                    }
                }
            }
        };

        let stream = tokio_stream::StreamExt::chunks_timeout(
            stream,
            10,
            std::time::Duration::from_millis(50),
        );

        let stream = stream.map(|operations| async {
            let mut store = store.clone();

            let mut validated_operations = vec![];

            for (header, body) in operations {
                // @TODO: Would be nice to pass arguments in by reference for the store. The
                // trait should not dictate that (for memory it'll be cloned though)
                match ingest_operation(&mut store, header.clone(), body.clone()).await {
                    Ok(IngestResult::Success(operation)) => validated_operations.push(operation), // store and forward,
                    Ok(IngestResult::Retry(operation)) => buf_tx
                        .send(operation)
                        .await
                        .expect("channel receiver closed"), // push to buffer
                    Ok(IngestResult::Invalid(_)) => (),
                    Err(err) => {
                        eprintln!("failed ingesting operation: {err}");
                    }
                }
            }

            futures::stream::iter(validated_operations)
        });

        let stream = stream.buffered(10);
        let stream = stream.flatten();

        tokio::pin!(stream);

        loop {
            if let Some(operation) = stream.next().await {
                if let Some(body) = operation.body {
                    let mut doc = doc.write().unwrap();
                    doc.load_incremental(&body.to_bytes()).unwrap();
                    let serialized =
                        serde_json::to_string(&automerge::AutoSerde::from(&doc.clone())).unwrap();
                    println!("{serialized}");
                }
            }
        }
    });

    tokio::signal::ctrl_c().await?;

    Ok(())
}

async fn create_operation(
    store: &mut Store,
    private_key: &PrivateKey,
    log_id: &LogId,
    body: Option<&[u8]>,
    prune_flag: bool,
) -> Result<Operation<Extensions>> {
    let body = body.map(Body::new);

    let public_key = private_key.public_key();

    let mut store = store.0.write().unwrap();

    let latest_operation = store.latest_operation(public_key, log_id.to_owned())?;

    let (seq_num, backlink) = match latest_operation {
        Some(operation) => (operation.header.seq_num + 1, Some(operation.hash)),
        None => (0, None),
    };

    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs();

    let extensions = Extensions {
        log_id: log_id.to_owned(),
        prune_flag,
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

    store.insert_operation(operation.clone(), log_id.to_owned())?;

    if prune_flag {
        assert!(
            operation.header.seq_num > 0,
            "can't prune from first operation in log"
        );
        store.delete_operations(
            operation.header.public_key,
            log_id.to_owned(),
            operation.header.seq_num,
        )?;
    }

    Ok(operation)
}

enum IngestResult {
    Success(Operation<Extensions>),
    Retry(Operation<Extensions>),
    #[allow(dead_code)]
    Invalid(OperationError),
}

async fn ingest_operation(
    store: &mut Store,
    header: Header<Extensions>,
    body: Option<Body>,
) -> Result<IngestResult> {
    let operation = Operation {
        hash: header.hash(),
        header,
        body,
    };

    if let Err(err) = validate_operation(&operation) {
        return Ok(IngestResult::Invalid(err));
    }

    let mut store = store.0.write().unwrap();

    let already_exists = store.get_operation(operation.hash)?.is_some();
    if !already_exists {
        let log_id: LogId = operation
            .header
            .extract()
            .ok_or(anyhow!("missing 'log_id' field in header"))?;
        let prune_flag: PruneFlag = operation
            .header
            .extract()
            .ok_or(anyhow!("missing 'prune_flag' field in header"))?;

        // @TODO: Move this into `p2panda-core`
        if !prune_flag.is_set() && operation.header.seq_num > 0 {
            let latest_operation = store
                .latest_operation(operation.header.public_key, log_id.to_owned())
                .context("critical store failure")?;

            match latest_operation {
                Some(latest_operation) => {
                    if let Err(err) = validate_backlink(&latest_operation.header, &operation.header)
                    {
                        match err {
                            // These errors signify that the sequence number is incremental
                            // however the backlink does not match
                            OperationError::BacklinkMismatch
                            | OperationError::BacklinkMissing
                            // A log can only contain operations from one author
                            | OperationError::TooManyAuthors => {
                                return Ok(IngestResult::Invalid(err))
                            }
                            // We observe a gap in the log and therefore can't validate the
                            // backlink yet
                            OperationError::SeqNumNonIncremental(_, _) => {
                                return Ok(IngestResult::Retry(operation))
                            }
                            _ => unreachable!(),
                        }
                    }
                }
                None => return Ok(IngestResult::Retry(operation)),
            }
        }

        let log = store.get_log(operation.header.public_key, log_id.clone())?;
        println!(
            "log_len={}, public_key={}",
            log.len(),
            operation.header.public_key
        );

        store
            .insert_operation(operation.clone(), log_id.clone())
            .context("critical store failure")?;

        if prune_flag.is_set() {
            store.delete_operations(
                operation.header.public_key,
                log_id,
                operation.header.seq_num,
            )?;
        }
    }

    Ok(IngestResult::Success(operation))
}

fn decode_operation(bytes: &[u8]) -> Result<(Header<Extensions>, Option<Body>)> {
    let header_and_body = ciborium::from_reader::<(Header<Extensions>, Option<Body>), _>(bytes)?;
    Ok(header_and_body)
}

fn encode_operation(header: Header<Extensions>, body: Option<Body>) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&(header, body), &mut bytes)?;
    Ok(bytes)
}
