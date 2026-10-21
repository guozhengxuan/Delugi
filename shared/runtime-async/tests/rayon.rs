#[test]
fn explicit_global_rayon_profile() {
    if std::env::var_os("SHARED_RAYON_CHILD").is_some() {
        assert_eq!(
            shared_runtime_async::initialize_global_rayon(2)
                .unwrap()
                .workers,
            2
        );
        assert!(shared_runtime_async::initialize_global_rayon(2).is_err());
        return;
    }
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "explicit_global_rayon_profile", "--nocapture"])
        .env("SHARED_RAYON_CHILD", "1")
        .status()
        .unwrap();
    assert!(result.success());
}
