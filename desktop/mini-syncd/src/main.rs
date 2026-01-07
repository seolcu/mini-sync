use clap::Parser;

#[derive(Parser)]
#[command(name = "mini-syncd", version, about = "mini-sync daemon (stub)")]
struct Args {}

fn main() {
    let _args = Args::parse();
    println!("mini-syncd stub: daemon not implemented yet");
}
