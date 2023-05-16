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
        // 这种写法会报错 bpf/bpf_redir.c:25:9: error: too many args to 0x21a3090: i64 = Constant<6>
        // char inbound_info_fmt[] = "INBOUND_ENVOY_IP exec bpf_msg_redirect_hash :[%x]=[%x]->[%x], [%x]->[%x]\n";
        // bpf_trace_printk(inbound_info_fmt, sizeof(inbound_info_fmt), key, key.local.ip4, key.local.port, key.remote.ip4, key.remote.port);

        // bpf_trace_printk 在使用时有一些输出参数的限制。比如：参数类型限制、参数个数限制(4-8)、参数大小限制等。
        // char inbound_key_local_fmt[] = "bpf_msg_redirect_hash data local ip4 and port [%x]->[%x]\n";
        // bpf_trace_printk(inbound_key_local_fmt, sizeof(inbound_key_local_fmt), key.local.ip4, key.local.port);

        // char inbound_key_remote_fmt[] = "bpf_msg_redirect_hash data remote ip4 and port [%x]->[%x]\n";
        // bpf_trace_printk(inbound_key_remote_fmt, sizeof(inbound_key_remote_fmt), key.remote.ip4, key.remote.port);
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

            char sk_msg_info_local[] = "<<< sk_msg_info_local >>> local_ip=%d, local_port=%d \n";
            bpf_trace_printk(sk_msg_info_local, sizeof(sk_msg_info_local), msg->local_ip4, bpf_ntohl(msg->local_port));

            char sk_msg_info_remote[] = "<<< sk_msg_info_remote >>> remote_ip=%d, remote_port=%d \n";
            bpf_trace_printk(sk_msg_info_remote, sizeof(sk_msg_info_remote), msg->remote_ip4, bpf_ntohl(msg->remote_port));

            debug_val_ptr = bpf_map_lookup_elem(&debug_map, &debug_pckts_index);
            if (debug_val_ptr == NULL) {
                debug_val = 0;
                debug_val_ptr = &debug_val;
            }
            // 函数的主要功能是以原子方式执行加法操作。
            __sync_fetch_and_add(debug_val_ptr, 1);
            bpf_map_update_elem(&debug_map, &debug_pckts_index, debug_val_ptr, BPF_ANY);
        }
    }
    return SK_PASS;
}

char _license[] SEC("license") = "GPL";
