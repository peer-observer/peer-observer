use std::fmt;

// structs are generated via the p2p-extractor.proto file
include!(concat!(env!("OUT_DIR"), "/p2p_extractor.rs"));

impl fmt::Display for PingDuration {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PingDuration({}ns)", self.duration)
    }
}

impl fmt::Display for AddressAnnouncement {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "AddressAnnouncement: [")?;
        let mut first = true;
        for v in &self.addresses {
            if first {
                first = false;
            } else {
                write!(f, ", ")?;
            }
            write!(f, "{}", v)?;
        }
        write!(f, "]")
    }
}

impl fmt::Display for InventoryAnnouncement {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "InventoryAnnouncement: [")?;
        let mut first = true;
        for v in &self.inventory {
            if first {
                first = false;
            } else {
                write!(f, ", ")?;
            }
            write!(f, "{}", v)?;
        }
        write!(f, "]")
    }
}

impl fmt::Display for p2p::Event {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            p2p::Event::PingDuration(duration) => write!(f, "{}", duration),
            p2p::Event::AddressAnnouncement(addresses) => {
                write!(f, "{}", addresses)
            }
            p2p::Event::InventoryAnnouncement(inventory) => {
                write!(f, "{}", inventory)
            }
            p2p::Event::FeefilterAnnouncement(feefilter) => {
                write!(f, "FeefilterAnnouncement({})", feefilter)
            }
        }
    }
}
