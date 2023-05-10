# sock_ebpf 代码分析

## sockops

SOCK_OPS 类型的 BPF 程序都是从 tcp_call_bpf() 调用过来的，这个文件中多个地方都会调用到该函数。
参考 http://arthurchiao.art/blog/bpf-advanced-notes-1-zh/

加载方式：attach 到某个 cgroup（可使用 bpftool 等工具）
指定以 BPF_CGROUP_SOCK_OPS 类型，将 BPF 程序 attach 到某个 cgroup 文件描述符。

依赖 cgroupv2。

内核已经有了 BPF_PROG_TYPE_CGROUP_SOCK 类型的 BPF 程序，这里为什么又要引入一个 BPF_PROG_TYPE_SOCK_OPS 类型的程序呢？

BPF_PROG_TYPE_CGROUP_SOCK 类型的 BPF 程序：在一个连接（connection）的生命周期中只执行一次，
BPF_PROG_TYPE_SOCK_OPS 类型的 BPF 程序：在一个连接的生命周期中，在不同地方被多次调用。

## 主动连接 BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB

socket.c connect
net/af_inet.c  __inet_stream_connect
net/tcp_ipv4.c  tcp_v4_pre_connect
net/tcp_ipv4.c  tcp_v4_connect
net/tcp_output.c tcp_connect
net/tcp_output.c tcp_connect_init
net/tcp_input.c tcp_finish_connect
net/tcp_input.c  tcp_init_transfer
net/tcp_input.c bpf_skops_established
include/linux/bpf-cgroup.h BPF_CGROUP_RUN_PROG_SOCK_OPS

## 主动连接 BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB

socket.c connect
net/af_inet.c  inet_recvmsg
net/tcp.c  tcp_recvmsg
net/tcp_ipv4.c  tcp_v4_rcv
net/tcp_ipv4.c  tcp_v4_do_rcv
net/tcp_input.c  tcp_rcv_state_process
net/tcp_input.c  tcp_init_transfer
net/tcp_input.c bpf_skops_established
include/linux/bpf-cgroup.h BPF_CGROUP_RUN_PROG_SOCK_OPS

recv过程参考https://zhuanlan.zhihu.com/p/405794790

## BPF_CGROUP_RUN_PROG_INET4_CONNECT
