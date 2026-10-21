//! Real loopback tests; all keys below are public deterministic test fixtures.
use raptr_shared_transport::{AsyncLimits, Auth, ByteAccounting, Channel, Context, Service};
use shared_crypto::{Keypair, PublicKey, SecretKey};
use shared_network::{Authentication, Transport, TransportSettings};
use std::io::Read;
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::time::Duration;

fn auth(id: u32) -> Auth {
    let keys: Vec<_> = (0..2)
        .map(|i| {
            let secret = SecretKey::from_bytes(&[i + 1; 32]).unwrap();
            Arc::new(Keypair {
                public: PublicKey::from(&secret),
                secret,
            })
        })
        .collect();
    Auth::new(
        id,
        Context {
            instance: [7; 32],
            configuration: [8; 32],
        },
        keys.iter().map(|k| k.public).collect(),
        keys[id as usize].clone(),
        128,
    )
    .unwrap()
}
fn addresses() -> Vec<SocketAddr> {
    let sockets: Vec<_> = (0..2)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    sockets.iter().map(|s| s.local_addr().unwrap()).collect()
}
fn start(
    id: u32,
    addresses: Vec<SocketAddr>,
    limits: AsyncLimits,
) -> (
    Service<Auth>,
    raptr_shared_transport::Sender,
    raptr_shared_transport::Receiver,
) {
    let transport = Transport::bind(id, auth(id), addresses, TransportSettings::default()).unwrap();
    Service::start(transport, id, 128, limits).unwrap()
}

#[tokio::test]
async fn four_frames_reach_peer_before_any_ack() {
    let mut addresses = addresses();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    addresses[1] = listener.local_addr().unwrap();
    let (mut service, tx, _rx) = start(0, addresses, AsyncLimits::default());
    let peer = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        for expected in 1..=4 {
            let mut size = [0; 4];
            stream.read_exact(&mut size).unwrap();
            let mut body = vec![0; u32::from_le_bytes(size) as usize];
            stream.read_exact(&mut body).unwrap();
            let (meta, payload) = auth(1).decode_frame(1, &body).unwrap();
            assert_eq!(meta.sequence, expected);
            assert_eq!(payload, vec![expected as u8; 64]);
            // Deliberately send no ACK: all four frames must already be pipelined.
        }
    });
    for i in 1..=4 {
        tokio::time::timeout(
            Duration::from_millis(100),
            tx.send(
                1,
                Channel::Consensus,
                vec![i; 64],
                ByteAccounting::default(),
            ),
        )
        .await
        .unwrap()
        .unwrap();
    }
    tokio::task::spawn_blocking(move || peer.join().unwrap())
        .await
        .unwrap();
    let snapshot = tx.snapshot();
    assert_eq!(
        snapshot.transport.peers[&1].layers[&Channel::Consensus].acknowledged_frames,
        0
    );
    assert!(snapshot.transport.peers[&1].layers[&Channel::Consensus].full_frames_written >= 4);
    service.shutdown();
}

#[tokio::test]
async fn remote_fifo_keeps_byte_lease_through_consumer_and_releases_on_drop() {
    let addresses = addresses();
    let (mut a, tx, _arx) = start(0, addresses.clone(), AsyncLimits::default());
    let (mut b, btx, mut rx) = start(
        1,
        addresses,
        AsyncLimits {
            inbox_frames: 1,
            inbox_bytes: 128,
            ..AsyncLimits::default()
        },
    );
    for i in 1..=3 {
        tx.send(
            1,
            Channel::QuorumStore,
            vec![i; 128],
            ByteAccounting::default(),
        )
        .await
        .unwrap();
    }
    let first = tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.frame.payload, vec![1; 128]);
    assert_eq!(btx.snapshot().leased_bytes, 128);
    assert!(tokio::time::timeout(Duration::from_millis(20), rx.recv())
        .await
        .is_err());
    drop(first);
    for i in 2..=3 {
        let next = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(next.frame.payload, vec![i; 128]);
        assert_eq!(next.frame.sequence, i as u64);
    }
    let snapshot = btx.snapshot();
    assert_eq!(snapshot.leased_bytes, 0);
    assert!(snapshot.maximum_leased_bytes <= 128);
    assert!(snapshot.maximum_pending_bytes <= 128);
    a.shutdown();
    b.shutdown();
}

#[tokio::test]
async fn self_delivery_has_no_tcp_bytes_and_exhaustion_is_explicit() {
    let (mut service, tx, mut rx) = start(
        0,
        addresses(),
        AsyncLimits {
            inbox_frames: 1,
            inbox_bytes: 128,
            ..AsyncLimits::default()
        },
    );
    tx.send(
        0,
        Channel::Consensus,
        vec![1; 128],
        ByteAccounting::default(),
    )
    .await
    .unwrap();
    assert!(tx
        .send(0, Channel::Consensus, vec![2; 1], ByteAccounting::default())
        .await
        .is_err());
    let first = rx.recv().await.unwrap();
    assert_eq!(first.frame.sequence, 1);
    assert!(tx
        .send(0, Channel::Consensus, vec![2; 1], ByteAccounting::default())
        .await
        .is_err());
    drop(first);
    tx.send(0, Channel::Consensus, vec![2; 1], ByteAccounting::default())
        .await
        .unwrap();
    let next = rx.recv().await.unwrap();
    assert_eq!(next.frame.sequence, 2);
    drop(next);
    let snapshot = tx.snapshot();
    assert_eq!(snapshot.self_frames, 2);
    assert_eq!(
        snapshot.transport.peers[&1]
            .written_categories
            .total_written_bytes,
        0
    );
    tx.fail("injected terminal driver error".into());
    assert_eq!(
        rx.recv().await.unwrap_err(),
        "injected terminal driver error"
    );
    assert!(tx
        .send(0, Channel::Consensus, vec![], ByteAccounting::default())
        .await
        .is_err());
    service.shutdown();
}

#[tokio::test]
async fn cancelled_receive_does_not_consume_the_next_message() {
    let (mut service, tx, mut rx) = start(0, addresses(), AsyncLimits::default());
    assert!(tokio::time::timeout(Duration::from_millis(2), rx.recv())
        .await
        .is_err());
    tx.send(0, Channel::Consensus, vec![9], ByteAccounting::default())
        .await
        .unwrap();
    assert_eq!(rx.recv().await.unwrap().frame.payload, vec![9]);
    service.shutdown();
    assert!(rx.recv().await.is_err());
}

#[test]
fn excessive_poll_interval_cannot_hold_shutdown_open() {
    let transport = Transport::bind(0, auth(0), addresses(), TransportSettings::default()).unwrap();
    let result = Service::start(
        transport,
        0,
        128,
        AsyncLimits {
            poll_interval: Duration::from_secs(3600),
            ..AsyncLimits::default()
        },
    );
    assert!(result.is_err());
}
