#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bpf_sockops.h"

// 是 BPF 的一个回调函数，用于处理主动建立连接的套接字操作。
static inline void bpf_sock_ops_active_establish_cb(struct bpf_sock_ops *skops) {
    struct socket_4_tuple key = {};

    // 从 bpf_sock_ops socket 套接字中获取元数据
    sk_ops_extract4_key(skops, &key);
    // 如果本机地址是 Envoy 的自身的地址，则更新 map_redir 并且跳过
    if (key.local.ip4 == INBOUND_ENVOY_IP) {
        char inbound_key_local_fmt[] = "bpf_sock_ops_active_establish_cb data local ip4 and port [%x]->[%x]\n";
        bpf_trace_printk(inbound_key_local_fmt, sizeof(inbound_key_local_fmt), key.local.ip4, key.local.port);

        char inbound_key_remote_fmt[] = "bpf_sock_ops_active_establish_cb data remote ip4 and port [%x]->[%x]\n";
        bpf_trace_printk(inbound_key_remote_fmt, sizeof(inbound_key_remote_fmt), key.remote.ip4, key.remote.port);
        // 调用 BPF 辅助函数去更新套接字 map
        bpf_sock_hash_update(skops, &map_redir, &key, BPF_ANY);
        return;
    }
    // 如果本机地址与远端地址相等，则跳过
    if (key.local.ip4 == key.remote.ip4) {
        char inbound_key_local_fmt[] = "bpf_sock_ops_active_establish_cb data key.local.ip4 == key.remote.ip4 [%x]->[%x]\n";
        bpf_trace_printk(inbound_key_local_fmt, sizeof(inbound_key_local_fmt), key.local.ip4, key.local.port);
        return;
    }

    // 调用 BPF 辅助函数去更新套接字 map map_active_estab
    /* update map_active_estab*/
    bpf_map_update_elem(&map_active_estab, &key.local, &key.remote, BPF_NOEXIST);

    // 调用 BPF 辅助函数去更新套接字 map map_redir
    /* update map_redir */
    bpf_sock_hash_update(skops, &map_redir, &key, BPF_ANY);
}

// 是 BPF 的一个回调函数，用于处理被动建立连接的套接字操作。
static inline void bpf_sock_ops_passive_establish_cb(struct bpf_sock_ops *skops) {
    struct socket_4_tuple key = {};
    struct socket_4_tuple proxy_key = {};
    struct socket_4_tuple proxy_val = {};
    struct addr_2_tuple *original_dst;

    // 从 bpf_sock_ops socket 套接字中获取元数据
    sk_ops_extract4_key(skops, &key);
    // 如果本机地址是 Envoy 的自身的地址，则更新 map_redir 并且跳过
    if (key.remote.ip4 == INBOUND_ENVOY_IP) {
        char inbound_key_local_fmt[] = "bpf_sock_ops_passive_establish_cb data local ip4 and port [%x]->[%x]\n";
        bpf_trace_printk(inbound_key_local_fmt, sizeof(inbound_key_local_fmt), key.local.ip4, key.local.port);

        char inbound_key_remote_fmt[] = "bpf_sock_ops_passive_establish_cb data remote ip4 and port [%x]->[%x]\n";
        bpf_trace_printk(inbound_key_remote_fmt, sizeof(inbound_key_remote_fmt), key.remote.ip4, key.remote.port);

        // 调用 BPF 辅助函数去更新套接字 map map_redir
        bpf_sock_hash_update(skops, &map_redir, &key, BPF_ANY);
    }
    // 调用 BPF 辅助函数从 bpf_map_lookup_elem 去获取原始地址
    original_dst = bpf_map_lookup_elem(&map_active_estab, &key.remote);
    if (original_dst == NULL) {
        char fmt[] = "original_dst data remote ip4 and port [%x]->[%x]\n";
        bpf_trace_printk(fmt, sizeof(fmt), key.remote.ip4, key.remote.port);
        return;
    }
    /* update map_proxy */
    proxy_key.local = key.remote;
    proxy_key.remote = *original_dst;
    proxy_val.local = key.local;
    proxy_val.remote = key.remote;
    // 调用 BPF 辅助函数 key
    bpf_map_update_elem(&map_proxy, &proxy_key, &proxy_val, BPF_ANY);
    // 调用 BPF 辅助函数 key
    bpf_map_update_elem(&map_proxy, &proxy_val, &proxy_key, BPF_ANY);

    /* update map_redir */
    // 调用 BPF 辅助函数去更新套接字 map map_redir
    bpf_sock_hash_update(skops, &map_redir, &key, BPF_ANY);

    /* delete element in map_active_estab*/
    // 调用 BPF 辅助函数去更新套接字 map map_active_estab
    bpf_map_delete_elem(&map_active_estab, &key.remote);
}

static inline void bpf_sock_ops_state_cb(struct bpf_sock_ops *skops) {
    struct socket_4_tuple key = {};
    sk_ops_extract4_key(skops, &key);
    char inbound_key_local_fmt[] = "bpf_sock_ops_state_cb data local ip4 and port [%x]->[%x]\n";
    bpf_trace_printk(inbound_key_local_fmt, sizeof(inbound_key_local_fmt), key.local.ip4, key.local.port);

    char inbound_key_remote_fmt[] = "bpf_sock_ops_state_cb data remote ip4 and port [%x]->[%x]\n";
    bpf_trace_printk(inbound_key_remote_fmt, sizeof(inbound_key_remote_fmt), key.remote.ip4, key.remote.port);

    /* delete elem in map_proxy */
    bpf_map_delete_elem(&map_proxy, &key);
    /* delete elem in map_active_estab */
    bpf_map_delete_elem(&map_active_estab, &key.local);
}

// 将函数或者变量放在指定段中，可在指定的地方取函数执行
SEC("sockops")
int bpf_sockmap(struct bpf_sock_ops *skops)
{
    // 判断 skops 对应的套接字操作是否为 IPv4 地址
    if (!(skops->family == AF_INET || skops->remote_ip4)) {
        /* support dual-stack socket */
        return 0;
    }
    // 通过调用 bpf_sock_ops_cb_flags_set 函数，并传递 skops 指针和 BPF_SOCK_OPS_STATE_CB_FLAG 标志位，
    // 可以将该标志位设置到 skops 的套接字操作回调标志中，表示需要对套接字状态进行回调处理。
    // BPF_SOCK_OPS_STATE_CB_FLAG 是一个位掩码（bitmask），用于表示套接字操作回调的不同状态
    bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG);
    switch (skops->op) {
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        // 处理主动连接
        bpf_sock_ops_active_establish_cb(skops);
        break;
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        // 处理被动连接
        bpf_sock_ops_passive_establish_cb(skops);
        break;
        // BPF_SOCK_OPS_STATE_CB 是一个标志位，用于表示在套接字操作回调中需要处理套接字状态的回调函数。
    case BPF_SOCK_OPS_STATE_CB:
        if (skops->args[1] == BPF_TCP_CLOSE) {
            bpf_sock_ops_state_cb(skops);
        }
        break;
    default:
        break;
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
