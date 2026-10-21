//! Common executable assembled with the native-compatible dependency profile.
//! Protocol-specific configuration, keys and policy remain in each core factory.
fn main() {
    if let Err(error) = common_node::execute(
        std::env::args().skip(1),
        "delugi",
        &[
            &delugi_core::factory::DelugiFactory,
            &raptr_shared_node::factory::RaptrFactory,
        ],
    ) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
