// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 0xB10C */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/usdt.bpf.h>

#define RINGBUFFER(name, size) struct {__uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, size); } name SEC(".maps");

// Counters for events we had to drop because a ring buffer was full. The
// extractor reads and reports them every now and then. The slot numbers must
// stay in sync with DROPPED_EVENT_NAMES in lib.rs.
#define DROP_NET_MSG_SMALL 0
#define DROP_NET_MSG_MEDIUM 1
#define DROP_NET_MSG_LARGE 2
#define DROP_NET_MSG_HUGE 3
#define DROP_NET_MSG_TOO_BIG 4
#define DROP_NET_CONN_INBOUND 5
#define DROP_NET_CONN_OUTBOUND 6
#define DROP_NET_CONN_CLOSED 7
#define DROP_NET_CONN_INBOUND_EVICTED 8
#define DROP_NET_CONN_MISBEHAVING 9
#define DROP_MEMPOOL_ADDED 10
#define DROP_MEMPOOL_REMOVED 11
#define DROP_MEMPOOL_REPLACED 12
#define DROP_MEMPOOL_REJECTED 13
#define DROP_VALIDATION_BLOCK_CONNECTED 14
#define DROP_NET_MSG_UNREADABLE 15
#define DROP_SLOT_COUNT 16

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, DROP_SLOT_COUNT);
    __type(key, u32);
    __type(value, u64);
} dropped_events SEC(".maps");

static __always_inline void count_drop(u32 slot) {
  u64 *counter = bpf_map_lookup_elem(&dropped_events, &slot);
  if (counter) {
    (*counter)++;
  }
}

// Copies a struct into a ring buffer and counts it if the buffer is full.
#define RINGBUFFER_OUTPUT(ringbuffer, value, slot) ({                       \
    long __err = bpf_ringbuf_output(&ringbuffer, &value, sizeof(value), 0); \
    if (__err) {                                                           \
      count_drop(slot);                                                    \
    }                                                                      \
    __err;                                                                 \
  })

#define MAX_PEER_ADDR_LENGTH 62 + 6
#define MAX_PEER_CONN_TYPE_LENGTH 20
#define MAX_MSG_TYPE_LENGTH 12

// We use 4 different max P2P message sizes and try to use the smallest possible.
// We expect mostly SMALL and MEDIUM messages, a few large and very few HUGE
// messages. We don't want to allocate e.g. HUGE_MSG_LENGTH bytes for a
// SMALL message.
#define MAX_SMALL_MSG_LENGTH 256
#define MAX_MEDIUM_MSG_LENGTH 4096
#define MAX_LARGE_MSG_LENGTH 65536
#define MAX_HUGE_MSG_LENGTH 4194304

// Ring buffer sizes are given in bytes. libbpf rounds them up to a
// power-of-two multiple of the page size, so we use such values directly.
#define PAGE_SIZE 4096

// NET MESSAGES

struct Metadata {
    u64     id;
    char    addr[MAX_PEER_ADDR_LENGTH];
    char    conn_type[MAX_PEER_CONN_TYPE_LENGTH];
    char    msg_type[MAX_MSG_TYPE_LENGTH];
    bool    msg_inbound;
    u64     msg_size;
};

struct SmallP2PMessage {
    struct Metadata   meta;
    u8                payload[MAX_SMALL_MSG_LENGTH];
};

struct MediumP2PMessage {
    struct Metadata   meta;
    u8                payload[MAX_MEDIUM_MSG_LENGTH];
};

struct LargeP2PMessage
{
    struct Metadata   meta;
    u8                payload[MAX_LARGE_MSG_LENGTH];
};

struct HugeP2PMessage
{
    struct Metadata   meta;
    u8                payload[MAX_HUGE_MSG_LENGTH];
};

// Each buffer holds whole messages of its size class. A message takes its
// class size plus 120 bytes of metadata and an 8 byte header.
RINGBUFFER(net_msg_small, 256 * PAGE_SIZE) // 1 MB, ~2700 messages
RINGBUFFER(net_msg_medium, 2048 * PAGE_SIZE) // 8 MB, ~1900 messages
RINGBUFFER(net_msg_large, 4096 * PAGE_SIZE) // 16 MB, ~250 messages
RINGBUFFER(net_msg_huge, 8192 * PAGE_SIZE) // 32 MB, 7 messages


// Helper function to set some of the tracepoint arguments to Metadata.
static __always_inline void set_meta_data1(struct Metadata *meta, u64 id, bool inbound, u64 msg_size) {
  meta->id = id;
  meta->msg_inbound = inbound;
  meta->msg_size = msg_size;
}

// Helper function to set some of the tracepoint arguments to Metadata.
static __always_inline void set_meta_data2(struct Metadata *meta, void *addr, void* conn_type, void* msg_type) {
  bpf_probe_read_user_str(&meta->addr, sizeof(meta->addr), addr);
  bpf_probe_read_user_str(&meta->conn_type, sizeof(meta->conn_type), conn_type);
  bpf_probe_read_user_str(&meta->msg_type, sizeof(meta->msg_type), msg_type);
}

// Puts a message into the ring buffer of the given size class and returns.
#define SUBMIT_NET_MSG(struct_name, ringbuffer, slot)                                  \
  {                                                                                    \
    struct struct_name *msg =                                                          \
        bpf_ringbuf_reserve(&ringbuffer, sizeof(struct struct_name), 0);                \
    if (!msg) {                                                                        \
      count_drop(slot);                                                                \
      return -1;                                                                       \
    }                                                                                  \
    /* the reserved memory is not blank, so clear what we may not fill in */           \
    __builtin_memset(&msg->meta, 0, sizeof(msg->meta));                                \
    set_meta_data1(&msg->meta, id, inbound, msg_size);                                 \
    set_meta_data2(&msg->meta, addr, conn_type, msg_type);                             \
    if (bpf_probe_read_user(&msg->payload, msg_size, msg_payload) < 0) {               \
      bpf_ringbuf_discard(msg, 0);                                                     \
      count_drop(DROP_NET_MSG_UNREADABLE);                                             \
      return -1;                                                                       \
    }                                                                                  \
    bpf_ringbuf_submit(msg, 0);                                                        \
    return 0;                                                                           \
  }

// Inbound and outbound messages are handled the same way apart from the
// inbound flag, so both tracepoints share this function.
static __always_inline int handle_net_msg(u64 id, void *addr, void *conn_type, void *msg_type,
                                     u64 msg_size, void *msg_payload, bool inbound) {
  if (msg_size <= MAX_SMALL_MSG_LENGTH) {
    SUBMIT_NET_MSG(SmallP2PMessage, net_msg_small, DROP_NET_MSG_SMALL)
  } else if (msg_size <= MAX_MEDIUM_MSG_LENGTH) {
    SUBMIT_NET_MSG(MediumP2PMessage, net_msg_medium, DROP_NET_MSG_MEDIUM)
  } else if (msg_size <= MAX_LARGE_MSG_LENGTH) {
    SUBMIT_NET_MSG(LargeP2PMessage, net_msg_large, DROP_NET_MSG_LARGE)
  } else if (msg_size <= MAX_HUGE_MSG_LENGTH) {
    SUBMIT_NET_MSG(HugeP2PMessage, net_msg_huge, DROP_NET_MSG_HUGE)
  }
  count_drop(DROP_NET_MSG_TOO_BIG);
  return -1;
}

SEC("usdt")
int BPF_USDT(handle_net_msg_inbound, u64 id, void *addr, void *conn_type, void *msg_type, u64 msg_size, void *msg_payload)
{
  return handle_net_msg(id, addr, conn_type, msg_type, msg_size, msg_payload, true);
}

SEC("usdt")
int BPF_USDT(handle_net_msg_outbound, u64 id, void *addr, void *conn_type, void *msg_type, u64 msg_size, void *msg_payload)
{
  return handle_net_msg(id, addr, conn_type, msg_type, msg_size, msg_payload, false);
}

// NET CONNECTIONS

#define MAX_MISBEHAVING_MESSAGE_LENGTH 128

#define NET_CONN_RINGBUFFER_SIZE (64 * PAGE_SIZE) // 256 KB

RINGBUFFER(net_conn_inbound, NET_CONN_RINGBUFFER_SIZE)
RINGBUFFER(net_conn_outbound, NET_CONN_RINGBUFFER_SIZE)
RINGBUFFER(net_conn_closed, NET_CONN_RINGBUFFER_SIZE)
RINGBUFFER(net_conn_inbound_evicted, NET_CONN_RINGBUFFER_SIZE)
RINGBUFFER(net_conn_misbehaving, NET_CONN_RINGBUFFER_SIZE)

struct Connection
{
    u64     id;
    char    addr[MAX_PEER_ADDR_LENGTH];
    char    type[MAX_PEER_CONN_TYPE_LENGTH];
    u32     network;
};

struct ClosedConnection
{
    struct Connection conn;
    u64    time_established;
};

struct InboundConnection
{
    struct  Connection conn;
    u64     existing_connections;
};

struct OutboundConnection
{
    struct  Connection conn;
    u64     existing_connections;
};

struct MisbehavingConnection
{
    u64     id;
    char    message[MAX_MISBEHAVING_MESSAGE_LENGTH];
};

// Helper function to set some of the tracepoint arguments to Connection.
static __always_inline void set_conn_data1(struct Connection *conn, u64 id, u64 network) {
  conn->id = id;
  conn->network = network;
}

// Helper function to set some of the tracepoint arguments to Connection.
static __always_inline void set_conn_data2(struct Connection *conn, void *addr, void *type) {
  bpf_probe_read_user_str(&conn->addr, sizeof(conn->addr), addr);
  bpf_probe_read_user_str(&conn->type, sizeof(conn->type), type);
}

SEC("usdt")
int BPF_USDT(handle_net_conn_inbound, u64 id, void *addr, void *type, u64 network, u64 existing_connections) {
    struct InboundConnection inbound = {};
    set_conn_data1(&inbound.conn, id, network);
    set_conn_data2(&inbound.conn, addr, type);
    inbound.existing_connections = existing_connections;
    return RINGBUFFER_OUTPUT(net_conn_inbound, inbound, DROP_NET_CONN_INBOUND);
};

SEC("usdt")
int BPF_USDT(handle_net_conn_outbound, u64 id, void *addr, void *type, u64 network, u64 existing_connections) {
    struct OutboundConnection outbound = {};
    set_conn_data1(&outbound.conn, id, network);
    set_conn_data2(&outbound.conn, addr, type);
    outbound.existing_connections = existing_connections;
    return RINGBUFFER_OUTPUT(net_conn_outbound, outbound, DROP_NET_CONN_OUTBOUND);
};

SEC("usdt")
int BPF_USDT(handle_net_conn_closed, u64 id, void *addr, void *type, u64 network, u64 time_established) {
    struct ClosedConnection closed = {};
    set_conn_data1(&closed.conn, id, network);
    set_conn_data2(&closed.conn, addr, type);
    closed.time_established = time_established;
    return RINGBUFFER_OUTPUT(net_conn_closed, closed, DROP_NET_CONN_CLOSED);
};

SEC("usdt")
int BPF_USDT(handle_net_conn_inbound_evicted, u64 id, void *addr, void *type, u64 network, u64 time_established) {
    struct ClosedConnection evicted = {};
    set_conn_data1(&evicted.conn, id, network);
    set_conn_data2(&evicted.conn, addr, type);
    evicted.time_established = time_established;
    return RINGBUFFER_OUTPUT(net_conn_inbound_evicted, evicted, DROP_NET_CONN_INBOUND_EVICTED);
};

SEC("usdt")
int BPF_USDT(handle_net_conn_misbehaving, u64 id, void *message) {
    struct MisbehavingConnection misbehaving = {};
    misbehaving.id = id;
    bpf_probe_read_user_str(&misbehaving.message, sizeof(misbehaving.message), message);
    return RINGBUFFER_OUTPUT(net_conn_misbehaving, misbehaving, DROP_NET_CONN_MISBEHAVING);
};

// MEMPOOL

// A connecting block removes every transaction it contains from the mempool
// in one go, so these need room for a few thousand events at once.
#define MEMPOOL_RINGBUFFER_SIZE (256 * PAGE_SIZE) // 1 MB

RINGBUFFER(mempool_added, MEMPOOL_RINGBUFFER_SIZE)
RINGBUFFER(mempool_removed, MEMPOOL_RINGBUFFER_SIZE)
RINGBUFFER(mempool_replaced, MEMPOOL_RINGBUFFER_SIZE)
RINGBUFFER(mempool_rejected, MEMPOOL_RINGBUFFER_SIZE)

#define TXID_LENGHT 32
#define REMOVAL_REASON_LENGTH 9
#define REJECTION_REASON_LENGTH 113

struct MempoolAdded {
    u8      txid[TXID_LENGHT];
    s32     vsize;
    s64     fee;
};

struct MempoolRemoved {
    u8      txid[TXID_LENGHT];
    char    reason[REMOVAL_REASON_LENGTH];
    s32     vsize;
    s64     fee;
    u64     entry_time;
};

struct MempoolReplaced {
    u8      replaced_txid[TXID_LENGHT];
    s32     replaced_vsize;
    s64     replaced_fee;
    u64     replaced_entry_time;
    u8      replacement_id[TXID_LENGHT];
    s32     replacement_vsize;
    s64     replacement_fee;
    bool    replaced_by_transaction;
};

struct MempoolRejected {
    u8      txid[TXID_LENGHT];
    char    reason[REJECTION_REASON_LENGTH];
};

SEC("usdt")
int BPF_USDT(handle_mempool_added, void *txid, s32 vsize, s64 fee) {
    struct MempoolAdded added = {};
    bpf_probe_read_user(&added.txid, sizeof(added.txid), txid);
    added.vsize = vsize;
    added.fee = fee;
    return RINGBUFFER_OUTPUT(mempool_added, added, DROP_MEMPOOL_ADDED);
};

SEC("usdt")
int BPF_USDT(handle_mempool_removed, void *txid, void *reason, s32 vsize, s64 fee, u64 entry_time) {
    struct MempoolRemoved removed = {};
    bpf_probe_read_user(&removed.txid, sizeof(removed.txid), txid);
    bpf_probe_read_user_str(&removed.reason, sizeof(removed.reason), reason);
    removed.vsize = vsize;
    removed.fee = fee;
    removed.entry_time = entry_time;
    return RINGBUFFER_OUTPUT(mempool_removed, removed, DROP_MEMPOOL_REMOVED);
};

SEC("usdt")
int BPF_USDT(handle_mempool_replaced,
    void *replaced_txid, s32 replaced_vsize, s64 replaced_fee, u64 replaced_entry_time,
    void *replacement_id, s32 replacement_vsize, s64 replacement_fee, bool replaced_by_transaction
) {
    struct MempoolReplaced replaced = {};
    bpf_probe_read_user(&replaced.replaced_txid, sizeof(replaced.replaced_txid), replaced_txid);
    replaced.replaced_vsize = replaced_vsize;
    replaced.replaced_fee = replaced_fee;
    replaced.replaced_entry_time = replaced_entry_time;
    bpf_probe_read_user(&replaced.replacement_id, sizeof(replaced.replacement_id), replacement_id);
    replaced.replacement_vsize = replacement_vsize;
    replaced.replacement_fee = replacement_fee;
    replaced.replaced_by_transaction = replaced_by_transaction;
    return RINGBUFFER_OUTPUT(mempool_replaced, replaced, DROP_MEMPOOL_REPLACED);
};

SEC("usdt")
int BPF_USDT(handle_mempool_rejected, void *txid, void *reason) {
    struct MempoolRejected rejected = {};
    bpf_probe_read_user(&rejected.txid, sizeof(rejected.txid), txid);
    bpf_probe_read_user_str(&rejected.reason, sizeof(rejected.reason), reason);
    return RINGBUFFER_OUTPUT(mempool_rejected, rejected, DROP_MEMPOOL_REJECTED);
};

// VALIDATION

#define VALIDATION_RINGBUFFER_SIZE (64 * PAGE_SIZE) // 256 KB

RINGBUFFER(validation_block_connected, VALIDATION_RINGBUFFER_SIZE)

#define HASH_LENGHT 32

struct BlockConnected {
  u8     hash[HASH_LENGHT];
  s32    height;
  u64    transactions;
  s32    inputs;
  u64    sigops;
  u64    connection_time;
};

SEC("usdt")
int BPF_USDT(handle_validation_block_connected, void *hash, s32 height, u64 transactions, s32 inputs, u64 sigops, u64 connection_time) {
    struct BlockConnected connected = {};
    bpf_probe_read_user(&connected.hash, sizeof(connected.hash), hash);
    connected.height = height;
    connected.transactions = transactions;
    connected.inputs = inputs;
    connected.sigops = sigops;
    connected.connection_time = connection_time;
    return RINGBUFFER_OUTPUT(validation_block_connected, connected, DROP_VALIDATION_BLOCK_CONNECTED);
};

char LICENSE[] SEC("license") = "Dual BSD/GPL";
