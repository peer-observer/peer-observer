function uint8ArrayToHexString(uint8Array) {
  return Array.from(uint8Array, (byte) =>
    byte.toString(16).padStart(2, "0")
  ).join("");
}

function removePortFromIPPort(str) {
  if (!str) {
    return ""
  }
  let port = str.split(":").slice(-1)[0];
  return str.replace(":" + port, "");
}

function connTypeToString(i) {
  switch (i) {
    case 1:
      return "inbound";
    case 2:
      return "outbound-full";
    case 3:
      return "outbound-block";
    case 4:
      return "feeler";
    default:
      return "unknown";
  }
}

const NETWORK_UNKNOWN = 0;
const NETWORK_IPV4 = 1;
const NETWORK_IPV6 = 2;
const NETWORK_ONION = 3;
const NETWORK_I2P = 4;
const NETWORK_CJDNS = 5;

function networkFromAddress(address) {
  if (address.includes(".onion") || address.includes("127.0.0.1")) {
    return NETWORK_ONION;
  } else if (address.includes(".i2p")) {
    return NETWORK_I2P;
  } else if (address.includes("[fc")) {
    return NETWORK_CJDNS;
  } else if (address.includes("[")) {
    return NETWORK_IPV6;
  } else if (address.split(".").length == 4) {
    return NETWORK_IPV4;
  }
  return NETWORK_UNKNOWN;
}

function isLinkingLion(address) {
  return (
    address.startsWith("162.218.65.") ||
    address.startsWith("209.222.252.") ||
    address.startsWith("91.198.115.") ||
    address.startsWith("[2604:d500")
  );
}

function isLikelySpy(address) {
  return (
    address.startsWith("147.229.8.240") || // anton1.fit.vutbr.cz
    address.includes("2001:67c:1220:808:") || // Brno
    address.startsWith("141.20.33.66") || // KIT DSN Bitcoin Monitoring
    address.startsWith("129.13.189.202") || // KIT DSN Bitcoin Monitoring
    address.startsWith("129.13.189.200") || // KIT DSN Bitcoin Monitoring
    address.includes("2a00:1398:4:2a03") || // KIT DSN Bitcoin Monitoring
    address.startsWith("161.53.40.241") || // AS2108 Croatian Academic and Research Network (pollux.riteh.hr)
    address.startsWith("188.166.69.73") || // DigitalOcean
    address.startsWith("24.144.98.209") || // DigitalOcean
    address.startsWith("46.101.92.98") || // DigitalOcean
    address.startsWith("24.199.125.72") || // DigitalOcean
    address.startsWith("64.227.3.73") || // DigitalOcean
    address.startsWith("68.183.38.98") || // DigitalOcean
    address.startsWith("207.154.205.24") || // DigitalOcean
    address.startsWith("64.227.74.130") || // DigitalOcean
    address.includes("2a03:b0c0:2:d0::") || // DigitalOcean
    address.includes("2a03:b0c0:1:d0::") || // DigitalOcean
    address.includes("2a03:b0c0:3:d0::") || // DigitalOcean
    address.includes("2604:a880:4:1d0::") || // DigitalOcean
    address.startsWith("88.198.10.155") || // Bitnodes
    address.startsWith("88.198.10.156") || // Bitnodes
    address.includes("2a01:4f8:222:291f") || // Bitnodes
    address.includes("2a04:3544:1000:1510:b08f:6fff:fe1b:3007") || // Upcloud
    isLinkingLion(address) // Linking Lion
  );
}

function testIsLinkingLion() {
  const testcases = [
    ["162.218.65.53", true],
    ["[2604:d500:4:1::2]", true],
    ["209.222.252.1", true],
    ["91.198.110", false],
    ["127.0.0.1", false],
    ["[2604:d500:4:1::4]", true],
  ];

  for (test of testcases) {
    if (isLinkingLion(test[0]) != test[1]) {
      alert(
        "test 'isLinkingLion' failed for address '" +
          test[0] +
          "', expected: '" +
          test[1] +
          "' but got: '" +
          isLinkingLion(test[0]) +
          "'"
      );
    }
  }
}

function testNetworkFromAddress() {
  const testcases = [
    ["162.218.65.53", NETWORK_IPV4],
    ["[2604:d500:4:1::2]", NETWORK_IPV6],
    ["abcdefghijklmno.onion", NETWORK_ONION],
    ["abcdefghijklmno.b32.i2p", NETWORK_I2P],
    ["[fcd1:c209:bc03:1a75:80d8:fake:0000:0000]", NETWORK_CJDNS],
  ];

  for (test of testcases) {
    if (networkFromAddress(test[0]) != test[1]) {
      alert(
        "test 'networkFromAddress' failed for address '" +
          test[0] +
          "', expected: '" +
          test[1] +
          "' but got: '" +
          networkFromAddress(test[0]) +
          "'"
      );
    }
  }
}

function testIsLikelySpy() {
  const testcases = [
    ["162.218.65.53", true], // LinkingLion
    ["[2604:d500:4:1::2]", true], // LinkingLion
    ["209.222.252.1", true], // LinkingLion
    ["91.198.110", false], // not LinkingLion
    ["127.0.0.1", false],
    ["129.13.189.200", true], // KIT
    ["[2a00:1398:4:2a03::1234]", true], // KIT
    ["2001:67c:1220:808:f6:d81b:74a:ae60", true], // Brno
  ];

  for (test of testcases) {
    if (isLikelySpy(test[0]) != test[1]) {
      alert(
        "test 'isLikelySpy' failed for address '" +
          test[0] +
          "', expected: '" +
          test[1] +
          "' but got: '" +
          isLikelySpy(test[0]) +
          "'"
      );
    }
  }
}

function runUnitTests() {
  console.log("running lib.js unit tests..");
  testIsLinkingLion();
  testNetworkFromAddress();
  testIsLikelySpy();
}

// These do nothing on purpose. You should override these in your tool!
function handle_ebpf_extractor_message(e) {};
function handle_ebpf_extractor_connection(e) {};
function handle_ebpf_extractor_mempool(e) {};
function handle_ebpf_extractor_addrman(e) {};
function handle_ebpf_extractor_validation(e) {};
// rpc-extractor
function handle_rpc_extractor_peerinfo(e) {};
function handle_rpc_extractor_mempoolinfo(e) {};
function handle_rpc_extractor_nettotals(e) {};
function handle_rpc_extractor_uptime(e) {};
// p2p-extractor
function handle_p2p_extractor_pingduration(e) {};
function handle_p2p_extractor_inventoryannouncement(e) {};
function handle_p2p_extractor_addressannouncement(e) {};
// TODO: there are a bunch of handling functions missing here.
// Feel free to implement them, if you need them.

function processWebsocketMessage(e) {
  const event = JSON.parse(e.data)
  if (event.hasOwnProperty("EbpfExtractor")) {
    let ebpf_event = event.EbpfExtractor.ebpf_event;
    if (ebpf_event.hasOwnProperty("Message")) {
      handle_ebpf_extractor_message(ebpf_event.Message)
    } else if (ebpf_event.hasOwnProperty("Connection")) {
      handle_ebpf_extractor_connection(ebpf_event.Connection.event)
    } else if (ebpf_event.hasOwnProperty("Mempool")) {
      handle_ebpf_extractor_mempool(ebpf_event.Mempool.event)
    } else if (ebpf_event.hasOwnProperty("Addrman")) {
      handle_ebpf_extractor_addrman(ebpf_event.Addrman.event)
    } else if (ebpf_event.hasOwnProperty("Validation")) {
      handle_ebpf_extractor_validation(ebpf_event.Validation.event)
    } else {
      console.warn("Unhandled eBPF-extractor event", ebpf_event);
    }

  } else if (event.hasOwnProperty("RpcExtractor")) {
    let rpc_event = event.RpcExtractor.rpc_event;
    if (rpc_event.hasOwnProperty("PeerInfos")) {
      handle_rpc_extractor_peerinfo(rpc_event.PeerInfos.infos)
    } else if (rpc_event.hasOwnProperty("MempoolInfo")) {
      handle_rpc_extractor_mempoolinfo(rpc_event.MempoolInfo)
    } else if (rpc_event.hasOwnProperty("NetTotals")) {
      handle_rpc_extractor_nettotals(rpc_event.NetTotals)
    } else if (rpc_event.hasOwnProperty("Uptime")) {
      handle_rpc_extractor_uptime(rpc_event.Uptime)
    } else {
      console.warn("Unhandled RPC-extractor event", rpc_event);
    }

  } else if (event.hasOwnProperty("P2pExtractor")) {
    let p2p_event = event.P2pExtractor.p2p_event;
    if (p2p_event.hasOwnProperty("PingDuration")) {
      handle_p2p_extractor_pingduration(p2p_event.PingDuration)
    } else if (p2p_event.hasOwnProperty("InventoryAnnouncement")) {
      handle_p2p_extractor_inventoryannouncement(p2p_event.InventoryAnnouncement)
    } else if (p2p_event.hasOwnProperty("AddressAnnouncement")) {
      handle_p2p_extractor_addressannouncement(p2p_event.AddressAnnouncement)      
    } else {
      console.warn("Unhandled P2P-extractor event", p2p_event);
    }

  } else if (event.hasOwnProperty("LogExtractor")) {
    console.warn("Unhandled log-extractor event", event);
    // TODO: these aren't implemented yet, but feel free to do so if you need them.
  } else {
    console.warn("Unhandled event", event);
  }
}