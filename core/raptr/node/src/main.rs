fn main() {
    if let Err(error) = common_node::execute(
        std::env::args().skip(1),
        "raptr",
        &[&raptr_shared_node::factory::RaptrFactory],
    ) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
