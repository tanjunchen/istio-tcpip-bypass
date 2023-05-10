#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bpf_sockops.h"

// 加载目标文件ELF中的`sk_msg`section，`sendmsg`系统调用时触发执行
SEC("sk_msg")
int bpf_redir_proxy(struct sk_msg_md *msg)
{
    uint32_t rc;
    uint32_t* debug_val_ptr;
    uint32_t debug_val;
    uint32_t debug_on_index = 0;
    uint32_t debug_pckts_index = 1;
    struct socket_4_tuple proxy_key = {};
    /* 处理 envoy inbound 流量 */
    struct socket_4_tuple key = {};
    /* 处理 envoy outbound 与同节点(envoy-envoy) 流量 */
    struct socket_4_tuple *key_redir = NULL;
    // 从 struct sk_msg_md *msg（socket metadata）中提取 key，并且更新 proxy_key 与 key
    sk_msg_extract4_keys(msg, &proxy_key, &key);
    if (key.local.ip4 == INBOUND_ENVOY_IP || key.remote.ip4 == INBOUND_ENVOY_IP) {
        // 处理 Inbound 流量
        rc = bpf_msg_redirect_hash(msg, &map_redir, &key, BPF_F_INGRESS);
    } else {
        // 处理 envoy outbound 与同节点(envoy-envoy) 流量
        // 在 map_proxy 中查找 proxy_key 相应的值
        key_redir = bpf_map_lookup_elem(&map_proxy, &proxy_key);
        if (key_redir == NULL) {
            // 如果没有找到对应值，则跳过，这种模式也可以支持非 sidecar
            return SK_PASS;
        }
        // bpf_msg_redirect_hash 用于在 eBPF 程序中重定向套接字消息。
        rc = bpf_msg_redirect_hash(msg, &map_redir, key_redir, BPF_F_INGRESS);
    }
    if (rc == SK_PASS) {
        // 通过调用 bpf_map_lookup_elem 函数并提供映射的文件描述符和要查找的键，可以检索映射中与该键关联的值。
        debug_val_ptr = bpf_map_lookup_elem(&debug_map, &debug_on_index);
        if (debug_val_ptr && *debug_val_ptr == 1) {
            char info_fmt[] = "data redirection succeed: [%x]->[%x]\n";
            // 使用 bpf_trace_printk 函数，可以将格式化的日志消息输出到内核的 trace_pipe
            // 从而允许开发人员在不修改代码的情况下观察和分析 BPF 程序的执行过程。
            bpf_trace_printk(info_fmt, sizeof(info_fmt), proxy_key.local.ip4, proxy_key.remote.ip4);

            debug_val_ptr = bpf_map_lookup_elem(&debug_map, &debug_pckts_index);
            if (debug_val_ptr == NULL) {
                debug_val = 0;
                debug_val_ptr = &debug_val;
            }
            // 函数的主要功能是以原子方式执行加法操作。
            __sync_fetch_and_add(debug_val_ptr, 1);
            bpf_map_update_elem(&debug_map, &debug_pckts_index, debug_val_ptr, BPF_ANY);
        }
        char debug_info[] = "tanjunchen data redirection succeed: [%x]->[%x]\n";
        bpf_trace_printk(debug_info, sizeof(debug_info), proxy_key.local.ip4, proxy_key.remote.ip4);
    }
    return SK_PASS;
}

char _license[] SEC("license") = "GPL";
