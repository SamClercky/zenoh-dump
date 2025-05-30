use anyhow::anyhow;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(version)]
pub struct Cli {
    message: String,
    #[arg(long, short, default_value = "*")]
    /// Specificy the channel on which to send
    channel: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Cli::parse();

    println!("Opening Zenoh session");
    let session = zenoh::open(zenoh::Config::default())
        .await
        .map_err(|err| anyhow!("Could not open zenoh session with reason: {err}"))?;

    println!("Sending message on channel '{}'", args.channel);
    session
        .put(args.channel, args.message)
        .await
        .map_err(|err| anyhow!("Could not put message on channel with reason: {err}"))?;
    println!("Message succesfully sent");

    Ok(())
}
