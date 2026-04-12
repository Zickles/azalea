use std::{
    io::Cursor,
    net::SocketAddr,
    sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}},
};

use aes::Aes128;
use azalea_crypto::Aes128CfbDec;
use azalea_protocol::{
    packets::login::{
        ClientboundHello, ClientboundLoginFinished, ClientboundLoginPacket,
        ServerboundLoginPacket,
    },
    packets::handshake::ServerboundHandshakePacket,
    read::{deserialize_packet, read_raw_packet},
    write::{encode_to_network_packet, serialize_packet, write_raw_packet},
};
use bevy_app::prelude::*;
use bevy_ecs::prelude::*;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey, pkcs8::EncodePublicKey};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream, tcp::{OwnedReadHalf, OwnedWriteHalf}},
    sync::mpsc,
};
use tracing::{debug, error, info, warn};

use crate::connection::RawConnection;

pub type Aes128CfbEnc = cfb8::Encryptor<Aes128>;

// ── Plugin ────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ProxyPlugin {
    pub bind_addr: SocketAddr,
}

impl ProxyPlugin {
    pub fn new(bind_addr: SocketAddr) -> Self {
        Self { bind_addr }
    }
}

impl Plugin for ProxyPlugin {
    fn build(&self, app: &mut App) {
        let (client_tx, client_rx) = mpsc::unbounded_channel::<PendingClient>();

        let mut rng = rand::rng();
        let private_key = Arc::new(RsaPrivateKey::new(&mut rng, 2048).unwrap());
        let public_key = RsaPublicKey::from(private_key.as_ref());

        let state = ProxyState {
            attached: Arc::new(Mutex::new(None)),
            client_rx: Mutex::new(client_rx),
        };

        let bind_addr = self.bind_addr;
        bevy_tasks::IoTaskPool::get()
            .spawn(run_listener(bind_addr, private_key, public_key, client_tx))
            .detach();

        app.insert_resource(state)
            .add_systems(PreUpdate, (accept_client, forward_server_to_client).chain())
            .add_systems(PostUpdate, forward_client_to_server);
    }
}

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Resource)]
pub struct ProxyState {
    pub attached: Arc<Mutex<Option<AttachedClient>>>,
    client_rx: Mutex<mpsc::UnboundedReceiver<PendingClient>>,
}

/// Handed off from the handshake task to ECS after login completes.
pub struct PendingClient {
    /// Raw decoded (decrypted+decompressed) serverbound packets from the client.
    pub serverbound_rx: mpsc::UnboundedReceiver<Box<[u8]>>,
    /// Sender for raw decoded clientbound packets to forward to the client.
    /// The write task handles re-encoding with the client's cipher.
    pub clientbound_tx: mpsc::UnboundedSender<Box<[u8]>>,
    pub disconnected: Arc<AtomicBool>,
    /// The client's AES key — needed so we can re-encode outbound packets
    /// with the client's own cipher, not the server's.
    pub client_enc_key: [u8; 16],
}

pub struct AttachedClient {
    pub serverbound_rx: mpsc::UnboundedReceiver<Box<[u8]>>,
    pub clientbound_tx: mpsc::UnboundedSender<Box<[u8]>>,
    pub disconnected: Arc<AtomicBool>,
}

// ── ECS systems ───────────────────────────────────────────────────────────────

fn accept_client(state: Res<ProxyState>) {
    let Ok(mut rx) = state.client_rx.try_lock() else { return };
    let Ok(pending) = rx.try_recv() else { return };

    info!("Vanilla client attached");

    *state.attached.lock().unwrap() = Some(AttachedClient {
        serverbound_rx: pending.serverbound_rx,
        clientbound_tx: pending.clientbound_tx,
        disconnected: pending.disconnected,
    });
}

fn forward_server_to_client(
    state: Res<ProxyState>,
    mut conn_query: Query<&mut RawConnection>,
) {
    let mut attached = state.attached.lock().unwrap();
    let Some(client) = attached.as_mut() else { return };

    if client.disconnected.load(Ordering::Relaxed) {
        info!("Vanilla client detached");
        *attached = None;
        return;
    }

    for mut conn in conn_query.iter_mut() {
        for raw in conn.take_tapped_packets() {
            // raw is already decrypted+decompressed packet bytes.
            // The write task in do_handshake will re-encode with the client cipher.
            let _ = client.clientbound_tx.send(raw);
        }
    }
}

fn forward_client_to_server(
    state: Res<ProxyState>,
    mut conn_query: Query<&mut RawConnection>,
) {
    let mut attached = state.attached.lock().unwrap();
    let Some(client) = attached.as_mut() else { return };
    let Ok(mut conn) = conn_query.single_mut() else { return };

    loop {
        match client.serverbound_rx.try_recv() {
            Ok(raw) => {
                if let Some(net) = conn.net_conn() {
                    // write_raw handles compression+encryption for the server side
                    if let Err(e) = net.write_raw(&raw) {
                        error!("Proxy: server write failed: {e}");
                        break;
                    }
                }
            }
            Err(mpsc::error::TryRecvError::Empty) => break,
            Err(mpsc::error::TryRecvError::Disconnected) => {
                *attached = None;
                break;
            }
        }
    }
}

// ── Listener + handshake ──────────────────────────────────────────────────────

async fn run_listener(
    bind_addr: SocketAddr,
    private_key: Arc<RsaPrivateKey>,
    public_key: RsaPublicKey,
    client_tx: mpsc::UnboundedSender<PendingClient>,
) {
    let listener = TcpListener::bind(bind_addr).await
        .expect("ProxyPlugin: failed to bind");
    info!("ProxyPlugin listening on {bind_addr}");

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                debug!("Proxy: client from {addr}");
                let pk = private_key.clone();
                let pubk = public_key.clone();
                let tx = client_tx.clone();
                tokio::spawn(async move {
                    if let Err(e) = do_handshake(stream, pk, pubk, tx).await {
                        warn!("Proxy handshake error: {e}");
                    }
                });
            }
            Err(e) => error!("Proxy accept error: {e}"),
        }
    }
}

async fn do_handshake(
    stream: TcpStream,
    private_key: Arc<RsaPrivateKey>,
    public_key: RsaPublicKey,
    client_tx: mpsc::UnboundedSender<PendingClient>,
) -> anyhow::Result<()> {
    let (mut read, mut write) = stream.into_split();
    let mut buf = Cursor::new(Vec::new());
    let mut dec: Option<Aes128CfbDec> = None;
    let mut enc: Option<Aes128CfbEnc> = None;

    // Handshake + login start
    let raw = read_raw_packet(&mut read, &mut buf, None, &mut dec).await?;
    let _ = deserialize_packet::<ServerboundHandshakePacket>(&mut Cursor::new(&raw as &[u8]))?;

    let raw = read_raw_packet(&mut read, &mut buf, None, &mut dec).await?;
    let pkt = deserialize_packet::<ServerboundLoginPacket>(&mut Cursor::new(&raw as &[u8]))?;
    let (username, profile_id) = match &pkt {
        ServerboundLoginPacket::Hello(p) => (p.name.clone(), p.profile_id),
        _ => anyhow::bail!("expected Hello"),
    };

    // Encryption request
    let verify_token: [u8; 4] = rand::random();
    let pub_key_der = public_key.to_public_key_der()?.to_vec();
    let pub_key_der_for_hash = pub_key_der.clone();

    let pkt = ClientboundLoginPacket::Hello(ClientboundHello {
        server_id: "".to_string(),
        public_key: pub_key_der,
        challenge: verify_token.to_vec(),
        should_authenticate: true,
    });
    write_raw_packet(&serialize_packet(&pkt)?, &mut write, None, &mut enc).await?;

    // Encryption response
    let raw = read_raw_packet(&mut read, &mut buf, None, &mut dec).await?;
    let pkt = deserialize_packet::<ServerboundLoginPacket>(&mut Cursor::new(&raw as &[u8]))?;
    let (enc_secret, enc_challenge) = match &pkt {
        ServerboundLoginPacket::Key(p) => (p.key_bytes.clone(), p.encrypted_challenge.clone()),
        _ => anyhow::bail!("expected Key"),
    };

    let shared_secret = private_key.decrypt(Pkcs1v15Encrypt, &enc_secret)?;
    let decrypted_challenge = private_key.decrypt(Pkcs1v15Encrypt, &enc_challenge)?;
    anyhow::ensure!(decrypted_challenge == verify_token, "challenge mismatch");

    // Enable encryption with the CLIENT's key
    use aes::cipher::KeyIvInit;
    let client_key: [u8; 16] = shared_secret.as_slice().try_into()?;
    dec = Some(Aes128CfbDec::new(&client_key.into(), &client_key.into()));
    enc = Some(Aes128CfbEnc::new(&client_key.into(), &client_key.into()));

    // Mojang auth
    let server_hash = azalea_crypto::hex_digest(&azalea_crypto::digest_data(
        b"",
        &pub_key_der_for_hash,
        &shared_secret,
    ));
    let url = format!(
        "https://sessionserver.mojang.com/session/minecraft/hasJoined?username={}&serverId={}",
        username, server_hash
    );
    let resp = reqwest::get(&url).await?;
    anyhow::ensure!(resp.status().as_u16() != 204, "Mojang auth failed");
    let profile_json: serde_json::Value = resp.json().await?;
    let uuid = uuid::Uuid::parse_str(profile_json["id"].as_str().unwrap_or(""))
        .unwrap_or(profile_id);
    let name = profile_json["name"].as_str().unwrap_or(&username).to_string();
    info!("Proxy: authenticated {name}");

    // Login success — send back the client's own profile
    // (they expect to see their own UUID/name, not the bot's)
    let game_profile = azalea_auth::game_profile::GameProfile {
        uuid,
        name,
        properties: Arc::new(azalea_auth::game_profile::GameProfileProperties {
            map: Default::default(),
        }),
    };
    let pkt = ClientboundLoginPacket::LoginFinished(ClientboundLoginFinished { game_profile });
    write_raw_packet(&serialize_packet(&pkt)?, &mut write, None, &mut enc).await?;

    // Login ack
    let raw = read_raw_packet(&mut read, &mut buf, None, &mut dec).await?;
    let _ = deserialize_packet::<ServerboundLoginPacket>(&mut Cursor::new(&raw as &[u8]))?;

    // Channels
    let (sb_tx, sb_rx) = mpsc::unbounded_channel::<Box<[u8]>>();
    let (cb_tx, cb_rx) = mpsc::unbounded_channel::<Box<[u8]>>();
    let disconnected = Arc::new(AtomicBool::new(false));

    // Write task: takes decoded packet bytes, re-encodes with CLIENT cipher, writes to TCP
    let disc_w = disconnected.clone();
    let key = client_key;
    tokio::spawn(async move {
        client_write_task(write, key, cb_rx, disc_w).await;
    });

    // Read task: reads from client TCP, decrypts with CLIENT cipher, sends decoded bytes
    let disc_r = disconnected.clone();
    tokio::spawn(async move {
        client_read_task(read, dec, buf, sb_tx, disc_r).await;
    });

    client_tx.send(PendingClient {
        serverbound_rx: sb_rx,
        clientbound_tx: cb_tx,
        disconnected,
        client_enc_key: client_key,
    })?;

    Ok(())
}

/// Receives raw decoded packet bytes, re-encodes them with the client's AES
/// cipher (no compression), and writes to the TCP stream.
async fn client_write_task(
    mut write: OwnedWriteHalf,
    key: [u8; 16],
    mut rx: mpsc::UnboundedReceiver<Box<[u8]>>,
    disconnected: Arc<AtomicBool>,
) {
    use aes::cipher::KeyIvInit;
    // Fresh enc cipher — owned by this task, never shared
    let mut enc: Option<Aes128CfbEnc> =
        Some(Aes128CfbEnc::new(&key.into(), &key.into()));

    while let Some(raw_packet) = rx.recv().await {
        // encode_to_network_packet: prepends varint length, optionally compresses,
        // then encrypts. We pass compression=None and our client enc cipher.
        let network_bytes = encode_to_network_packet(
            &raw_packet,
            None,          // no compression to client
            &mut enc,
        );
        if let Err(e) = write.write_all(&network_bytes).await {
            debug!("Proxy: client write ended: {e}");
            break;
        }
    }

    disconnected.store(true, Ordering::Relaxed);
}

/// Reads from the client TCP stream, decrypts with the client's cipher,
/// and sends raw decoded packet bytes upstream to the ECS.
async fn client_read_task(
    mut read: OwnedReadHalf,
    mut dec: Option<Aes128CfbDec>,
    mut buf: Cursor<Vec<u8>>,
    tx: mpsc::UnboundedSender<Box<[u8]>>,
    disconnected: Arc<AtomicBool>,
) {
    loop {
        // read_raw_packet handles varint framing + decryption + decompression.
        // We pass compression=None because the client never compresses to us.
        match read_raw_packet(&mut read, &mut buf, None, &mut dec).await {
            Ok(raw) => {
                if tx.send(raw).is_err() {
                    break;
                }
            }
            Err(e) => {
                debug!("Proxy: client read ended: {e}");
                break;
            }
        }
    }
    disconnected.store(true, Ordering::Relaxed);
}