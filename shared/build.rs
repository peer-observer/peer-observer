use std::env;
use std::fs;
use std::path::Path;

fn main() {
    // Generate Rust types for the protobuf's
    if let Err(e) = prost_build::Config::new()
        .compile_well_known_types()
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .compile_protos(&["../protobuf/event.proto"], &["../protobuf/"])
    {
        println!("Error while compiling protos: {}", e);
        panic!("Failed to code-gen the Rust structs from the Protobuf definitions");
    }
    println!("cargo:rerun-if-changed=../protobuf/*");

    // Generate check functions for IP addresses
    gen_ip_match_fn(
        "ip-lists/torbulkexitlist",
        "torexitlist.rs",
        "is_tor_exit_node",
    );
    gen_ip_match_fn(
        "ip-lists/gmaxbanlist.txt",
        "gmaxbanlist.rs",
        "is_on_gmax_banlist",
    );
    gen_ip_match_fn(
        "ip-lists/monerobanlist.txt",
        "monerobanlist.rs",
        "is_on_monero_banlist",
    );
    gen_ip_match_fn(
        "ip-lists/bitprojects-io.txt",
        "bitprojects-list.rs",
        "belongs_to_bitprojects",
    );

    println!("cargo:rerun-if-changed=build.rs");
}

fn generate_ip_match(addr: &str) -> String {
    format!(" \"{}\" ", addr)
}

// generates a 'rs_file' with a 'match_fn_name' IP match function from a 'input' list
// of IP addresses
fn gen_ip_match_fn(input: &str, rs_file: &str, match_fn_name: &str) {
    let input_list = fs::read_to_string(input).expect("a valid input file path");
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let out_path = Path::new(&out_dir).join(rs_file);

    let match_statement = input_list
        .lines()
        .map(generate_ip_match)
        .collect::<Vec<String>>()
        .join("|");

    fs::write(
        &out_path,
        format!(
            "\
// DON'T CHANGE THIS FILE MANUALLY. IT WILL BE OVERWRITTEN.
// This file is generated in `build.rs`.

#[allow(dead_code)]
pub fn {}(ip: &str) -> bool {{
    matches!(ip, {})
}}

",
            match_fn_name, match_statement
        ),
    )
    .expect("can write to file");
    println!("cargo:rerun-if-changed={}", input);
}
