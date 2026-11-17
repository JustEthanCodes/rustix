use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let source = root.join("crates/rustix-init/src/main.rs");
    let linker_script = root.join("crates/rustix-init/linker.ld");
    println!("cargo:rerun-if-changed={}", source.display());
    println!("cargo:rerun-if-changed={}", linker_script.display());
    println!("cargo:rerun-if-env-changed=RUSTC");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("none") {
        return;
    }

    let rustc = env::var_os("RUSTC").expect("Cargo provides RUSTC");
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo provides OUT_DIR"))
        .join("rustix-init.elf");
    let linker_arg = format!("-T{}", linker_script.display());
    let mut command = Command::new(rustc);
    command
        .current_dir(&root)
        .arg("--crate-name")
        .arg("rustix_init")
        .arg("--edition=2021")
        .arg("--check-cfg=cfg(rustix_fault_probe)")
        .arg("--check-cfg=cfg(rustix_user_fault_ud)")
        .arg("--check-cfg=cfg(rustix_user_fault_page)")
        .arg("--check-cfg=cfg(rustix_user_fault_gp)")
        .arg("--check-cfg=cfg(rustix_user_fault_de)")
        .arg("--crate-type=bin")
        .arg("--target=x86_64-unknown-none")
        .arg("-Cpanic=abort")
        .arg("-Copt-level=2")
        .arg("-Ccode-model=small")
        .arg("-Crelocation-model=static")
        .arg("-Ctarget-feature=-avx,-avx2,-avx512f")
        .arg(format!("-Clink-arg={linker_arg}"))
        .arg("-Clink-arg=--build-id=none")
        .arg(&source)
        .arg("-o")
        .arg(&output);
    let fault_modes = [
        ("CARGO_FEATURE_PROBE_USER_FAULT", "rustix_user_fault_ud"),
        (
            "CARGO_FEATURE_PROBE_USER_PAGE_FAULT",
            "rustix_user_fault_page",
        ),
        (
            "CARGO_FEATURE_PROBE_USER_GENERAL_PROTECTION",
            "rustix_user_fault_gp",
        ),
        (
            "CARGO_FEATURE_PROBE_USER_DIVIDE_ERROR",
            "rustix_user_fault_de",
        ),
    ];
    let enabled_fault_modes: Vec<_> = fault_modes
        .iter()
        .filter(|(feature, _)| env::var_os(feature).is_some())
        .collect();
    assert!(
        enabled_fault_modes.len() <= 1,
        "only one user-fault probe feature may be enabled"
    );
    if let Some((_, mode)) = enabled_fault_modes.first() {
        command
            .arg("--cfg=rustix_fault_probe")
            .arg(format!("--cfg={mode}"));
    }
    let status = command
        .status()
        .expect("failed to invoke rustc for the init payload");
    assert!(
        status.success(),
        "failed to build the rustix-init ELF payload"
    );
}
