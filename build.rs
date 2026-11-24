use std::env;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Compile one static user payload from the shared rustix-init source with the
/// given variant cfgs, linking the prebuilt rustix-user runtime.
fn build_payload(
    rustc: &OsStr,
    root: &Path,
    out_dir: &Path,
    runtime: &Path,
    source: &Path,
    linker_script: &Path,
    crate_name: &str,
    output: &Path,
    cfgs: &[&str],
) {
    let mut command = Command::new(rustc);
    command
        .current_dir(root)
        .env("OUT_DIR", out_dir)
        .arg("--crate-name")
        .arg(crate_name)
        .arg("--edition=2021")
        .arg("--check-cfg=cfg(rustix_fault_probe)")
        .arg("--check-cfg=cfg(rustix_child_probe)")
        .arg("--check-cfg=cfg(rustix_spawner_probe)")
        .arg("--check-cfg=cfg(rustix_exec_probe)")
        .arg("--check-cfg=cfg(rustix_exec_target_probe)")
        .arg("--check-cfg=cfg(rustix_user_fault_ud)")
        .arg("--check-cfg=cfg(rustix_user_fault_page)")
        .arg("--check-cfg=cfg(rustix_user_fault_gp)")
        .arg("--check-cfg=cfg(rustix_user_fault_de)")
        .arg("--check-cfg=cfg(rustix_invalid_syscall_return_probe)")
        .arg("--crate-type=bin")
        .arg("--target=x86_64-unknown-none")
        .arg("-Cpanic=abort")
        .arg("-Copt-level=2")
        .arg("-Cdebuginfo=0")
        .arg("-Ccode-model=small")
        .arg("-Crelocation-model=static")
        .arg("-Ctarget-feature=-avx,-avx2,-avx512f")
        .arg(format!("-Clink-arg=-T{}", linker_script.display()))
        .arg("-Clink-arg=--build-id=none")
        .arg("-Clink-arg=--strip-debug")
        .arg("--extern")
        .arg(format!("rustix_user={}", runtime.display()))
        .arg(source)
        .arg("-o")
        .arg(output);
    for cfg in cfgs {
        command.arg(format!("--cfg={cfg}"));
    }
    let status = command
        .status()
        .unwrap_or_else(|_| panic!("failed to invoke rustc for {crate_name}"));
    assert!(status.success(), "failed to build {crate_name} ELF");
}

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
        .arg("-Cdebuginfo=0")
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

    // Payload build order respects embedded-image dependencies: the exec
    // tester embeds the exec target, the spawner embeds the plain child, and
    // init embeds the child, spawner, and exec tester.
    build_payload(
        &rustc,
        &root,
        &out_dir,
        &runtime,
        &source,
        &linker_script,
        "rustix_child",
        &out_dir.join("rustix-child.elf"),
        &["rustix_child_probe"],
    );
    build_payload(
        &rustc,
        &root,
        &out_dir,
        &runtime,
        &source,
        &linker_script,
        "rustix_exec_target",
        &out_dir.join("rustix-exec-target.elf"),
        &["rustix_exec_target_probe"],
    );
    build_payload(
        &rustc,
        &root,
        &out_dir,
        &runtime,
        &source,
        &linker_script,
        "rustix_exec",
        &out_dir.join("rustix-exec.elf"),
        &["rustix_exec_probe"],
    );
    build_payload(
        &rustc,
        &root,
        &out_dir,
        &runtime,
        &source,
        &linker_script,
        "rustix_spawner",
        &out_dir.join("rustix-spawner.elf"),
        &["rustix_spawner_probe"],
    );

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
        (
            "CARGO_FEATURE_PROBE_USER_INVALID_SYSCALL_RETURN",
            "rustix_invalid_syscall_return_probe",
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
    let mut init_cfgs: Vec<&str> = Vec::new();
    if let Some((_, mode)) = enabled_fault_modes.first() {
        init_cfgs.push("rustix_fault_probe");
        init_cfgs.push(mode);
    }
    build_payload(
        &rustc,
        &root,
        &out_dir,
        &runtime,
        &source,
        &linker_script,
        "rustix_init",
        &out_dir.join("rustix-init.elf"),
        &init_cfgs,
    );
}
