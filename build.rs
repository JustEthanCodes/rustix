use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let source = root.join("crates/rustix-init/src/main.rs");
    let linker_script = root.join("crates/rustix-init/linker.ld");
    let runtime_source = root.join("crates/rustix-user/src/lib.rs");
    let runtime_manifest = root.join("crates/rustix-user/Cargo.toml");
    println!("cargo:rerun-if-changed={}", source.display());
    println!("cargo:rerun-if-changed={}", linker_script.display());
    println!("cargo:rerun-if-changed={}", runtime_source.display());
    println!("cargo:rerun-if-changed={}", runtime_manifest.display());
    println!("cargo:rerun-if-env-changed=RUSTC");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("none") {
        return;
    }

    let rustc = env::var_os("RUSTC").expect("Cargo provides RUSTC");
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo provides OUT_DIR"));
    let runtime = out_dir.join("librustix_user.rlib");
    let runtime_status = Command::new(&rustc)
        .current_dir(&root)
        .arg("--crate-name")
        .arg("rustix_user")
        .arg("--edition=2021")
        .arg("--crate-type=rlib")
        .arg("--target=x86_64-unknown-none")
        .arg("-Cpanic=abort")
        .arg("-Copt-level=2")
        .arg("-Ccode-model=small")
        .arg("-Crelocation-model=static")
        .arg("-Ctarget-feature=-avx,-avx2,-avx512f")
        .arg(&runtime_source)
        .arg("--out-dir")
        .arg(&out_dir)
        .status()
        .expect("failed to invoke rustc for the rustix-user runtime");
    assert!(
        runtime_status.success(),
        "failed to build rustix-user runtime"
    );

    let child_output = out_dir.join("rustix-child.elf");
    let child_status = Command::new(&rustc)
        .current_dir(&root)
        .env("OUT_DIR", &out_dir)
        .arg("--crate-name")
        .arg("rustix_child")
        .arg("--edition=2021")
        .arg("--check-cfg=cfg(rustix_child_probe)")
        .arg("--cfg=rustix_child_probe")
        .arg("--crate-type=bin")
        .arg("--target=x86_64-unknown-none")
        .arg("-Cpanic=abort")
        .arg("-Copt-level=2")
        .arg("-Ccode-model=small")
        .arg("-Crelocation-model=static")
        .arg("-Ctarget-feature=-avx,-avx2,-avx512f")
        .arg(format!("-Clink-arg=-T{}", linker_script.display()))
        .arg("-Clink-arg=--build-id=none")
        .arg("--extern")
        .arg(format!("rustix_user={}", runtime.display()))
        .arg(&source)
        .arg("-o")
        .arg(&child_output)
        .status()
        .expect("failed to invoke rustc for the child probe payload");
    assert!(child_status.success(), "failed to build child probe ELF");

    let output = out_dir.join("rustix-init.elf");
    let linker_arg = format!("-T{}", linker_script.display());
    let mut command = Command::new(rustc);
    command
        .current_dir(&root)
        .env("OUT_DIR", &out_dir)
        .arg("--crate-name")
        .arg("rustix_init")
        .arg("--edition=2021")
        .arg("--check-cfg=cfg(rustix_fault_probe)")
        .arg("--check-cfg=cfg(rustix_child_probe)")
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
        .arg("--extern")
        .arg(format!("rustix_user={}", runtime.display()))
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
