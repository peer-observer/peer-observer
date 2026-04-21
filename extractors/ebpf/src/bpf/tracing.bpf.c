// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 0xB10C */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/usdt.bpf.h>

#define RINGBUFFER(name, size) struct {__uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, size); } name SEC(".maps");

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

#define PAGE_SIZE 4096
#define NET_MSG_PAGES 128

// NET MESSAGES

#define METADATA_SIZE 8 + MAX_PEER_ADDR_LENGTH + MAX_PEER_CONN_TYPE_LENGTH + MAX_MSG_TYPE_LENGTH + 1 + 8

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

RINGBUFFER(net_msg_small, (MAX_SMALL_MSG_LENGTH + METADATA_SIZE) * 1024) // ~ 1 MB
RINGBUFFER(net_msg_medium, (MAX_MEDIUM_MSG_LENGTH + METADATA_SIZE) * 1024) // ~ 4.2 MB
RINGBUFFER(net_msg_large, (MAX_LARGE_MSG_LENGTH + METADATA_SIZE) * 1024) // ~ 67 MB
RINGBUFFER(net_msg_huge, (MAX_HUGE_MSG_LENGTH + METADATA_SIZE) * 128) // ~ 536 MB


// Helper function to set some of the tracepoint arguments to Metadata.
void set_meta_data1(struct Metadata *meta, u64 id, bool inbound, u64 msg_size) {
  meta->id = id;
  meta->msg_inbound = inbound;
  meta->msg_size = msg_size;
}

// Helper function to set some of the tracepoint arguments to Metadata.
void set_meta_data2(struct Metadata *meta, void *addr, void* conn_type, void* msg_type) {
  bpf_probe_read_user_str(&meta->addr, sizeof(meta->addr), addr);
  bpf_probe_read_user_str(&meta->conn_type, sizeof(meta->conn_type), conn_type);
  bpf_probe_read_user_str(&meta->msg_type, sizeof(meta->msg_type), msg_type);
}

SEC("usdt")
int BPF_USDT(handle_net_msg_inbound, u64 id, void *addr, void *conn_type, void *msg_type, u64 msg_size, void *msg_payload)
{
  bool IS_INBOUND = true;
  if (msg_size <= MAX_SMALL_MSG_LENGTH) {
    struct SmallP2PMessage *msg = bpf_ringbuf_reserve(&net_msg_small, sizeof(struct SmallP2PMessage), 0);
    if (msg) {
      set_meta_data1(&msg->meta, id, IS_INBOUND, msg_size);
      set_meta_data2(&msg->meta, addr, conn_type, msg_type);
      bpf_probe_read_user(&msg->payload, msg_size, msg_payload);
      bpf_ringbuf_submit(msg, 0);
      return 0;
    }
    bpf_printk("small inbound msg: not able to reserve. msg size is %d", msg_size);
  } else if (msg_size <= MAX_MEDIUM_MSG_LENGTH) {
    struct MediumP2PMessage *msg = bpf_ringbuf_reserve(&net_msg_medium, sizeof(struct MediumP2PMessage), 0);
    if (msg) {
      set_meta_data1(&msg->meta, id, IS_INBOUND, msg_size);
      set_meta_data2(&msg->meta, addr, conn_type, msg_type);
      bpf_probe_read_user_str(&msg->meta.msg_type, sizeof(msg->meta.msg_type), msg_type);
      bpf_probe_read_user(&msg->payload, msg_size, msg_payload);
      bpf_ringbuf_submit(msg, 0);
      return 0;
    }
    bpf_printk("medium inbound msg: not able to reserve. msg size is %d", msg_size);
  } else if (msg_size <= MAX_LARGE_MSG_LENGTH) {
    struct LargeP2PMessage *msg = bpf_ringbuf_reserve(&net_msg_large, sizeof(struct LargeP2PMessage), 0);
    if (msg) {
      set_meta_data1(&msg->meta, id, IS_INBOUND, msg_size);
      set_meta_data2(&msg->meta, addr, conn_type, msg_type);
      bpf_probe_read_user(&msg->payload, msg_size, msg_payload);
      bpf_ringbuf_submit(msg, 0);
      return 0;
    }
    bpf_printk("large inbound msg: not able to reserve. msg size is %d", msg_size);
  } else if (msg_size <= MAX_HUGE_MSG_LENGTH) {
    struct HugeP2PMessage *msg = bpf_ringbuf_reserve(&net_msg_huge, sizeof(struct HugeP2PMessage), 0);
    if (msg) {
      set_meta_data1(&msg->meta, id, IS_INBOUND, msg_size);
      set_meta_data2(&msg->meta, addr, conn_type, msg_type);
      bpf_probe_read_user(&msg->payload, msg_size, msg_payload);
      bpf_ringbuf_submit(msg, 0);
      return 0;
    }
    bpf_printk("huge inbound msg: not able to reserve. msg size is %d", msg_size);
  }
  bpf_printk("inbound msg: return -1.( msg size is %d", msg_size);
  return -1;
}

SEC("usdt")
int BPF_USDT(handle_net_msg_outbound, u64 id, void *addr, void *conn_type, void *msg_type, u64 msg_size, void *msg_payload)
{
  bool IS_INBOUND = false;
  if (msg_size <= MAX_SMALL_MSG_LENGTH) {
    struct SmallP2PMessage *msg = bpf_ringbuf_reserve(&net_msg_small, sizeof(struct SmallP2PMessage), 0);
    if (msg) {
      set_meta_data1(&msg->meta, id, IS_INBOUND, msg_size);
      set_meta_data2(&msg->meta, addr, conn_type, msg_type);
      bpf_probe_read_user(&msg->payload, msg_size, msg_payload);
      bpf_ringbuf_submit(msg, 0);
      return 0;
    }
    bpf_printk("small outbound msg: not able to reserve. msg size is %d", msg_size);
  } else if (msg_size <= MAX_MEDIUM_MSG_LENGTH) {
    struct MediumP2PMessage *msg = bpf_ringbuf_reserve(&net_msg_medium, sizeof(struct MediumP2PMessage), 0);
    if (msg) {
      set_meta_data1(&msg->meta, id, IS_INBOUND, msg_size);
      set_meta_data2(&msg->meta, addr, conn_type, msg_type);
      bpf_probe_read_user_str(&msg->meta.msg_type, sizeof(msg->meta.msg_type), msg_type);
      bpf_probe_read_user(&msg->payload, msg_size, msg_payload);
      bpf_ringbuf_submit(msg, 0);
      return 0;
    }
    bpf_printk("medium outbound msg: not able to reserve. msg size is %d", msg_size);
  } else if (msg_size <= MAX_LARGE_MSG_LENGTH) {
    struct LargeP2PMessage *msg = bpf_ringbuf_reserve(&net_msg_large, sizeof(struct LargeP2PMessage), 0);
    if (msg) {
      set_meta_data1(&msg->meta, id, IS_INBOUND, msg_size);
      set_meta_data2(&msg->meta, addr, conn_type, msg_type);
      bpf_probe_read_user(&msg->payload, msg_size, msg_payload);
      bpf_ringbuf_submit(msg, 0);
      return 0;
    }
    bpf_printk("large outbound msg: not able to reserve. msg size is %d", msg_size);
  } else if (msg_size <= MAX_HUGE_MSG_LENGTH) {
    struct HugeP2PMessage *msg = bpf_ringbuf_reserve(&net_msg_huge, sizeof(struct HugeP2PMessage), 0);
    if (msg) {
      set_meta_data1(&msg->meta, id, IS_INBOUND, msg_size);
      set_meta_data2(&msg->meta, addr, conn_type, msg_type);
      bpf_probe_read_user(&msg->payload, msg_size, msg_payload);
      bpf_ringbuf_submit(msg, 0);
      return 0;
    }
    bpf_printk("huge outbound msg: not able to reserve. msg size is %d", msg_size);
  }
  bpf_printk("outbound msg: return -1. msg size is %d", msg_size);
  return -1;
}

// NET CONNECTIONS

#define MAX_MISBEHAVING_MESSAGE_LENGTH 128

#define NET_CONN_PAGES 64

RINGBUFFER(net_conn_inbound, NET_CONN_PAGES)
RINGBUFFER(net_conn_outbound, NET_CONN_PAGES)
RINGBUFFER(net_conn_closed, NET_CONN_PAGES)
RINGBUFFER(net_conn_inbound_evicted, NET_CONN_PAGES)
RINGBUFFER(net_conn_misbehaving, NET_CONN_PAGES)

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
void set_conn_data1(struct Connection *conn, u64 id, u64 network) {
  conn->id = id;
  conn->network = network;
}

// Helper function to set some of the tracepoint arguments to Connection.
void set_conn_data2(struct Connection *conn, void *addr, void *type) {
  bpf_probe_read_user_str(&conn->addr, sizeof(conn->addr), addr);
  bpf_probe_read_user_str(&conn->type, sizeof(conn->type), type);
}

SEC("usdt")
int BPF_USDT(handle_net_conn_inbound, u64 id, void *addr, void *type, u64 network, u64 existing_connections) {
    struct InboundConnection inbound = {};
    set_conn_data1(&inbound.conn, id, network);
    set_conn_data2(&inbound.conn, addr, type);
    inbound.existing_connections = existing_connections;
    return bpf_ringbuf_output(&net_conn_inbound, &inbound, sizeof(inbound), 0);
};

SEC("usdt")
int BPF_USDT(handle_net_conn_outbound, u64 id, void *addr, void *type, u64 network, u64 existing_connections) {
    struct OutboundConnection outbound = {};
    set_conn_data1(&outbound.conn, id, network);
    set_conn_data2(&outbound.conn, addr, type);
    outbound.existing_connections = existing_connections;
    return bpf_ringbuf_output(&net_conn_outbound, &outbound, sizeof(outbound), 0);
};

SEC("usdt")
int BPF_USDT(handle_net_conn_closed, u64 id, void *addr, void *type, u64 network, u64 time_established) {
    struct ClosedConnection closed = {};
    set_conn_data1(&closed.conn, id, network);
    set_conn_data2(&closed.conn, addr, type);
    closed.time_established = time_established;
    return bpf_ringbuf_output(&net_conn_closed, &closed, sizeof(closed), 0);
};

SEC("usdt")
int BPF_USDT(handle_net_conn_inbound_evicted, u64 id, void *addr, void *type, u64 network, u64 time_established) {
    struct ClosedConnection evicted = {};
    set_conn_data1(&evicted.conn, id, network);
    set_conn_data2(&evicted.conn, addr, type);
    evicted.time_established = time_established;
    return bpf_ringbuf_output(&net_conn_inbound_evicted, &evicted, sizeof(evicted), 0);
};

SEC("usdt")
int BPF_USDT(handle_net_conn_misbehaving, u64 id, void *message) {
    struct MisbehavingConnection misbehaving = {};
    misbehaving.id = id;
    bpf_probe_read_user_str(&misbehaving.message, sizeof(misbehaving.message), message);
    return bpf_ringbuf_output(&net_conn_misbehaving, &misbehaving, sizeof(misbehaving), 0);
};

// MEMPOOL

#define MEMPOOL_PAGES 64

RINGBUFFER(mempool_added, MEMPOOL_PAGES)
RINGBUFFER(mempool_removed, MEMPOOL_PAGES)
RINGBUFFER(mempool_replaced, MEMPOOL_PAGES)
RINGBUFFER(mempool_rejected, MEMPOOL_PAGES)

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
    return bpf_ringbuf_output(&mempool_added, &added, sizeof(added), 0);
};

SEC("usdt")
int BPF_USDT(handle_mempool_removed, void *txid, void *reason, s32 vsize, s64 fee, u64 entry_time) {
    struct MempoolRemoved removed = {};
    bpf_probe_read_user(&removed.txid, sizeof(removed.txid), txid);
    bpf_probe_read_user_str(&removed.reason, sizeof(removed.reason), reason);
    removed.vsize = vsize;
    removed.fee = fee;
    removed.entry_time = entry_time;
    return bpf_ringbuf_output(&mempool_removed, &removed, sizeof(removed), 0);
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
    return bpf_ringbuf_output(&mempool_replaced, &replaced, sizeof(replaced), 0);
};

SEC("usdt")
int BPF_USDT(handle_mempool_rejected, void *txid, void *reason) {
    struct MempoolRejected rejected = {};
    bpf_probe_read_user(&rejected.txid, sizeof(rejected.txid), txid);
    bpf_probe_read_user_str(&rejected.reason, sizeof(rejected.reason), reason);
    return bpf_ringbuf_output(&mempool_rejected, &rejected, sizeof(rejected), 0);
};

// VALIDATION

#define VALIDATION_BLOCK_CONNECTED_PAGES 64

RINGBUFFER(validation_block_connected, VALIDATION_BLOCK_CONNECTED_PAGES)

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
    return bpf_ringbuf_output(&validation_block_connected, &connected, sizeof(connected), 0);
};

char LICENSE[] SEC("license") = "Dual BSD/GPL";
