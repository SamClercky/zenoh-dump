use std::{
    fs::File,
    io::Stdout,
    sync::{Arc, Mutex},
    time::Instant,
};

use anyhow::anyhow;
use clap::Parser;
use pcap_file::{
    DataLink, Endianness,
    pcap::{PcapHeader, PcapPacket, PcapWriter},
};
use tokio::{signal, sync::mpsc};
use tokio_util::sync::CancellationToken;
use zenoh::sample::Sample;

#[derive(Parser, Debug)]
#[command(version)]
struct Cli {
    #[arg(long)]
    /// Query all the interfaces
    extcap_interfaces: bool,
    #[arg(long, default_value = "1.0")]
    /// Wireshark version
    extcap_version: String,
    #[arg(long, default_value = "zenoh")]
    /// Select a specific interface
    extcap_interface: String,
    #[arg(long, default_value = "false")]
    /// DLT query for a specific interface
    extcap_dtls: bool,
    #[arg(long, default_value = "false")]
    /// Query for the config of an interface
    extcap_config: bool,
    #[arg(long, default_value = "false")]
    /// Start capturing
    capture: bool,
    #[arg(long, default_value = "")]
    /// Set a capture filter
    extcap_capture_filter: String,
    #[arg(long)]
    /// Set the fifo
    fifo: Option<String>,
    #[arg(long, default_value = "*")]
    /// Channels to listen upon
    channels: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Cli::parse();
    if args.extcap_interfaces {
        extcap_interfaces();
        return Ok(());
    } else if args.extcap_dtls {
        extcap_dlts(args);
        return Ok(());
    } else if args.extcap_config {
        extcap_config(args);
        return Ok(());
    } else if args.capture {
        return capture(args).await;
    }

    return Ok(());
}

fn extcap_interfaces() {
    println!(
        "extcap {{version=1.0}}{{help=https://www.wireshark.org}}{{display=Example extcap interface}}"
    );
    println!("interface {{value=zenoh}}{{display=Listen on Zenoh P2P channel}}");
    //println!(
    //    "control {{number=0}}{{type=string}}{{display=Channels}}{{tooltip=Listen on channels}}{{placeholder=*}}{{validation=^[\\w/]+}}"
    //);
    //println!("control {{number=1}}{{type=button}}{{display=Turn on}}{{tooltip=Turn on or off}}");
}

fn extcap_config(_args: Cli) {
    println!(
        "arg {{number=0}}{{call=--channels}}{{display=Channels}}{{tooltip=Set Zenoh channels}}{{type=string}}{{default=*}}"
    )
}

fn extcap_dlts(_arg: Cli) {
    println!("dlt {{number=147}}{{name=USER0}}{{display=Demo Implementation for Extcap}}");
}

async fn capture(args: Cli) -> anyhow::Result<()> {
    let session = zenoh::open(zenoh::Config::default())
        .await
        .map_err(|err| anyhow!("Could not open zenoh session with reason: {err}"))?;

    let cancel_token = CancellationToken::new();

    let (sink_tx, mut sink_rx) = mpsc::unbounded_channel();

    // Setup all the channels
    let mut join_tokens = Vec::with_capacity(args.channels.len());
    for channel in args.channels {
        let subscriber = session
            .declare_subscriber(channel.clone())
            .await
            .map_err(|err| anyhow!("Could not open channel {channel} with reason: {err}"))?;
        let cancel_token = cancel_token.clone();
        let sink_tx = sink_tx.clone();
        let join_token = tokio::spawn(async move {
            loop {
                tokio::select! {
                    sample = subscriber.recv_async() => {
                        match sample {
                            Ok(sample) => {
                                // Send sample to sink
                                let _ = sink_tx.send(sample);
                            }
                            Err(err) => {
                                // We have an error, report and quit
                                println!("Error while listening on zenoh channel with reason: {err}");
                                break
                            }
                        }
                    }
                    _ = cancel_token.cancelled() => {
                        // Someone pressed ctrl_c, so quiting
                        break
                    }
                }
            }
        });

        join_tokens.push(join_token);
    }

    // Setup the sink
    let join_token = tokio::spawn({
        let cancel_token = cancel_token.clone();

        // Setup writer
        let mut writer = FIFOWriter::new(args.fifo)?;

        async move {
            loop {
                tokio::select! {
                    sample = sink_rx.recv() => {
                        match sample {
                            Some(sample) => {
                                // Output new sample
                                let _ = writer.write_pcap(sample).await.inspect_err(|err| eprintln!("Error while writing to pcap with reason: {err}"));
                            }
                            None => {
                                // Sink is up
                                break
                            }
                        }
                    }
                    _ = cancel_token.cancelled() => {
                        // We need to stop
                        break
                    }
                }
            }
        }
    });
    join_tokens.push(join_token);

    // Wait for ctrl_c and gracefully quit the application
    signal::ctrl_c().await?;
    cancel_token.cancel();
    for token in join_tokens {
        token.await?;
    }

    Ok(())
}

struct FIFOWriter {
    inner: Arc<Mutex<FIFOWriterInner>>,
    startup_time: Instant,
}

enum FIFOWriterInner {
    StdOut(PcapWriter<Stdout>),
    File(PcapWriter<File>),
}

impl FIFOWriter {
    pub fn new(fifo: Option<String>) -> anyhow::Result<Self> {
        let header = PcapHeader {
            version_major: 2,
            version_minor: 4,
            ts_correction: 0,
            ts_accuracy: 0,
            snaplen: u16::MAX as u32,
            datalink: DataLink::RAW,
            ts_resolution: pcap_file::TsResolution::MicroSecond,
            endianness: Endianness::native(),
        };

        let inner = match fifo {
            Some(fifo) => {
                let file = File::options().create(true).append(true).open(&fifo)?;
                let writer = PcapWriter::with_header(file, header)?;
                FIFOWriterInner::File(writer)
            }
            None => {
                let stdout = std::io::stdout();
                let writer = PcapWriter::with_header(stdout, header)?;
                FIFOWriterInner::StdOut(writer)
            }
        };

        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
            startup_time: Instant::now(),
        })
    }

    pub async fn write_pcap(&mut self, packet: Sample) -> anyhow::Result<()> {
        let inner = self.inner.clone();
        let startup_time = self.startup_time;

        let _ = tokio::task::spawn_blocking(move || {
            // Poinson errors are hard errors
            let mut inner = inner.lock().unwrap();
            let payload = packet.payload().to_bytes();
            let packet = PcapPacket::new(
                Instant::now() - startup_time,
                packet.payload().len() as u32,
                payload.as_ref(),
            );

            match &mut *inner {
                FIFOWriterInner::StdOut(w) => w.write_packet(&packet),
                FIFOWriterInner::File(w) => w.write_packet(&packet),
            }
        })
        .await?;

        Ok(())
    }
}
