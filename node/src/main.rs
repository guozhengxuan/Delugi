fn main() {
    if let Err(error) = common_node::execute(
        std::env::args().skip(1), "delugi", &[&delugi::factory::DelugiFactory],
    ) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
