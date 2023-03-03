use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
};

use base64ct::{Base64, Encoding};

use console::style;
use near_jsonrpc_client::{NEAR_MAINNET_RPC_URL, NEAR_TESTNET_RPC_URL};
use near_primitives::types::AccountId;
use serde::{Deserialize, Serialize};
use tokio::{select, sync::mpsc};
use x25519_dalek::StaticSecret;

use crate::{messenger::Messenger, wallet::Wallet};

pub mod channel;
pub mod key_registry;
pub mod message_repository;
pub mod messenger;
pub mod wallet;

#[derive(Serialize, Deserialize, Debug)]
struct Environment {
    key_file_path: PathBuf,
    network: Option<String>,
    messenger_secret_key: String,
    key_registry_account_id: AccountId,
    message_repository_account_id: AccountId,
}

fn network_rpc_url(network: Option<String>) -> String {
    network
        .map(|network| match &network.to_lowercase()[..] {
            "mainnet" => NEAR_MAINNET_RPC_URL.to_string(),
            "testnet" => NEAR_TESTNET_RPC_URL.to_string(),
            _ => network, // assume it's a URL
        })
        .unwrap_or_else(|| NEAR_TESTNET_RPC_URL.to_string())
}

// message receiver thread
fn receiver(
    messenger: Arc<Messenger>,
    sender_id: AccountId,
) -> (impl Fn(), tokio::sync::mpsc::Receiver<Vec<u8>>) {
    let alive = Arc::new(AtomicBool::new(true));
    let (send, recv) = tokio::sync::mpsc::channel(1);

    let kill = {
        let alive = Arc::clone(&alive);
        move || {
            alive.store(false, Ordering::SeqCst);
        }
    };

    tokio::spawn({
        async move {
            while alive.load(Ordering::SeqCst) {
                if let Some(received_message) =
                    messenger.receive_one_from(&sender_id).await.unwrap()
                {
                    send.send(received_message).await.unwrap();
                }
            }
        }
    });

    (kill, recv)
}

struct LineEditor {
    pub recv: mpsc::Receiver<String>,
    pub prompt: Arc<Mutex<String>>,
    buffer: Arc<Mutex<String>>,
}

impl LineEditor {
    fn prompt(prompt: &str, buffer: &str) -> String {
        let inp = buffer
            .split_once(' ')
            .map(|(command, tail)| format!("{} {}", style(command).green(), tail))
            .unwrap_or_else(|| format!("{}", style(buffer).green()));
        format!("{}{inp}", style(prompt).black().bright())
    }

    pub fn redraw_prompt(&self) {
        eprint!(
            "\r{}",
            LineEditor::prompt(&self.prompt.lock().unwrap(), &self.buffer.lock().unwrap()),
        );
    }

    pub fn set_prompt(&mut self, prompt: &str) {
        *self.prompt.lock().unwrap() = prompt.to_string();
    }

    pub fn new(prompt: &str) -> Self {
        let (send, recv) = mpsc::channel(2);
        let buffer = Arc::new(Mutex::new(String::new()));
        let prompt = Arc::new(Mutex::new(prompt.to_string()));

        thread::spawn({
            let buffer = Arc::clone(&buffer);
            let prompt = Arc::clone(&prompt);
            move || {
                let stdout = console::Term::stdout();
                loop {
                    let k = stdout.read_key().unwrap();
                    match k {
                        console::Key::Enter => {
                            let mut b = buffer.lock().unwrap();
                            let s = b.to_string();
                            b.clear();
                            drop(b);
                            eprintln!();
                            send.blocking_send(s).unwrap();
                        }
                        console::Key::Backspace => {
                            let mut buffer = buffer.lock().unwrap();
                            buffer.pop();
                            stdout.clear_line().unwrap();
                            eprint!("\r{}", LineEditor::prompt(&prompt.lock().unwrap(), &buffer));
                        }
                        console::Key::Char(c) => {
                            let mut buffer = buffer.lock().unwrap();
                            buffer.push(c);
                            eprint!("\r{}", LineEditor::prompt(&prompt.lock().unwrap(), &buffer));
                        }
                        _ => {}
                    }
                }
            }
        });

        let le = Self {
            recv,
            prompt,
            buffer,
        };

        le.redraw_prompt();

        le
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv()?;

    let env: Environment = envy::from_env()?;

    let signer = near_crypto::InMemorySigner::from_file(&env.key_file_path)?;

    let wallet = Arc::new(Wallet::new(
        network_rpc_url(env.network.clone()),
        signer.account_id.clone(),
        signer,
    ));

    let messenger_secret_key: [u8; 32] = Base64::decode_vec(&env.messenger_secret_key)
        .unwrap()
        .try_into()
        .unwrap();

    let messenger = Arc::new(Messenger::new(
        Arc::clone(&wallet),
        StaticSecret::from(messenger_secret_key),
        &env.key_registry_account_id,
        &env.message_repository_account_id,
    ));

    eprintln!(
        "Welcome to the {} (test version)",
        style("NEAR Private Data Messenger").magenta(),
    );

    eprint!("Syncing public key with key repository...");
    messenger.sync_key().await?;
    eprintln!("done.");

    let mut line_editor = LineEditor::new("");

    loop {
        eprintln!(
            "You are logged in as {}.",
            style(&wallet.account_id).cyan().bright(),
        );
        eprintln!("{} to exit.", style("/quit").green().bold());

        line_editor.set_prompt("Chat with: ");
        line_editor.redraw_prompt();
        let correspondent: AccountId = loop {
            let input = line_editor.recv.recv().await.unwrap();
            if input == "/quit" {
                return Ok(());
            }
            if let Ok(account_id) = input.parse() {
                break account_id;
            }
        };

        eprintln!(
            "{} to say, {} to leave.",
            style("/say").green().bold(),
            style("/leave").green().bold(),
        );

        messenger
            .register_correspondent(&correspondent)
            .await
            .unwrap();

        let (kill, mut recv) = receiver(Arc::clone(&messenger), correspondent.clone());

        line_editor.set_prompt(":: ");

        loop {
            line_editor.redraw_prompt();

            select! {
                send_message = line_editor.recv.recv() => {
                    let send_message = send_message.unwrap();
                    let send_message = send_message
                        .strip_suffix("\r\n")
                        .or(send_message.strip_suffix('\n'))
                        .unwrap_or(&send_message);
                    let (command, tail) = send_message
                        .split_once(' ')
                        .unwrap_or((send_message, ""));

                    match command {
                        "/say" => {
                            eprintln!("\r{}: {tail}", style(&wallet.account_id).cyan().bright());
                            messenger.send(&correspondent, tail).await.unwrap();
                        }
                        "/leave" => {
                            eprintln!("{}", style("Exiting chat.").green());
                            kill();
                            break;
                        }
                        _ => {
                            eprintln!("{}", style(format!("Unknown command: {}", command)).red());
                        }
                    }
                },
                recv_message = recv.recv() => {
                    if let Some(recv_message) = recv_message {
                        eprintln!("\r{}: {}", style(&correspondent).magenta().bright(), String::from_utf8_lossy(&recv_message));
                    } else {
                        eprintln!("\r{}", style("Error connecting to message repository.").red());
                        kill();
                        break;
                    }
                },
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use base64ct::{Base64, Encoding};
    use rand::rngs::OsRng;

    #[test]
    fn generate_messenger_secret_key() {
        let messenger_secret_key = x25519_dalek::StaticSecret::new(OsRng);
        let secret_key_b64 = Base64::encode_string(&messenger_secret_key.to_bytes());
        println!("\"{secret_key_b64}\"");
    }
}
