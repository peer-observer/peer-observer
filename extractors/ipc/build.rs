fn main() -> Result<(), Box<dyn std::error::Error>> {
    capnpc::CompilerCommand::new()
        .file("capnp/mp/proxy.capnp")
        .file("capnp/common.capnp")
        .file("capnp/echo.capnp")
        .file("capnp/mining.capnp")
        .file("capnp/init.capnp")
        .default_parent_module(vec![String::from("ipc")])
        .run()?;

    println!("cargo:rerun-if-changed=capnp/mp/proxy.capnp");
    println!("cargo:rerun-if-changed=capnp/common.capnp");
    println!("cargo:rerun-if-changed=capnp/echo.capnp");
    println!("cargo:rerun-if-changed=capnp/mining.capnp");
    println!("cargo:rerun-if-changed=capnp/init.capnp");

    Ok(())
}
