fn main() {
    let Ok(target) = std::env::var("TARGET") else {
        println!(
            "cargo:warning=TARGET is unavailable; update checks will report target_unsupported"
        );
        return;
    };
    println!("cargo:rustc-env=CALCIFER_BUILD_TARGET={target}");
    println!("cargo:rerun-if-env-changed=TARGET");
}
