use archive::read::ArchiveReader;
use shared::protobuf::event::event::PeerObserverEvent;
use std::env;
use std::path::Path;

fn main() {
    let files: Vec<String> = env::args().skip(1).collect();
    if files.is_empty() || files.iter().any(|f| f == "--help" || f == "-h") {
        println!("Read and display peer-observer archive files");
        println!();
        println!("Usage: replayer <file.bin[.zst]> [file2.bin[.zst] ...]");
        return;
    }

    for path in &files {
        if files.len() > 1 {
            println!("=== {} ===", path);
        }

        let archive = ArchiveReader::open(Path::new(path)).unwrap();
        println!("header: {}", archive.header);

        let mut events_count = 0;
        for (n, event) in archive.enumerate() {
            let event = event.unwrap();
            let ts = event.timestamp;
            match &event.peer_observer_event {
                Some(PeerObserverEvent::EbpfExtractor(e)) => {
                    println!("[{n}] ts={ts} ebpf: {}", e.ebpf_event.as_ref().unwrap())
                }
                Some(PeerObserverEvent::RpcExtractor(r)) => {
                    println!("[{n}] ts={ts} rpc: {}", r.rpc_event.as_ref().unwrap())
                }
                Some(PeerObserverEvent::P2pExtractor(p)) => {
                    println!("[{n}] ts={ts} p2p: {}", p.p2p_event.as_ref().unwrap())
                }
                Some(PeerObserverEvent::LogExtractor(l)) => {
                    println!("[{n}] ts={ts} log: {}", l.log_event.as_ref().unwrap())
                }
                Some(PeerObserverEvent::IpcExtractor(i)) => {
                    println!("[{n}] ts={ts} ipc: {}", i.ipc_event.as_ref().unwrap())
                }
                None => println!("[{n}] ts={ts} <unknown>"),
            }
            events_count = n + 1;
        }

        println!("total: {} events", events_count);
    }
}
