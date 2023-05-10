// 如果宏没有定义，则返回真
#ifndef __VMLINUX_H__
/*
 * 使用 #define 预处理器定义常量 
 * 定义宏
*/
#define __VMLINUX_H__

/*
 * run the following command in btf supported OS such as ubuntu 21.04 and deleted unused lines
 * 在支持 BTF（BPF Type Format）的操作系统中（例如 Ubuntu 21.04），运行以下命令并删除未使用的行。
 * BTF 是 Linux 内核中用于表示 C 语言结构体和函数的类型信息的一种格式。
 * 在 BPF 程序中，使用 BTF 可以更加方便地访问内核中的数据结构，提高 BPF 程序的可读性和可维护性。
 * bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
*/

/*
* typedef 为类型定义新名称
*/
typedef unsigned char __u8;
typedef short int __s16;
typedef short unsigned int __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long int __s64;
typedef long long unsigned int __u64;

typedef __u8 u8;
typedef __s16 s16;
typedef __u16 u16;
typedef __s32 s32;
typedef __u32 u32;
typedef __s64 s64;
typedef __u64 u64;

typedef __u16 __le16;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;

typedef s32 int32_t;
typedef u32 uint32_t;
typedef __u32 __wsum;

/*
 *  使用 enum 定义 bpf_map_type 枚举常量
*/
enum bpf_map_type {
        // BPF_MAP_TYPE_UNSPEC 是一种特殊的 BPF Map 类型，它代表了未指定 Map 类型的情况。
        BPF_MAP_TYPE_UNSPEC = 0,
        // 哈希表类型的 BPF Map。支持键值对读写操作，键和值的大小是可配置的。
        BPF_MAP_TYPE_HASH = 1,
        // 数组类型的 BPF Map。支持下标访问操作，值的大小是可配置的。
        BPF_MAP_TYPE_ARRAY = 2,
        // 存储 BPF 程序的数组类型的 BPF Map。支持下标访问操作，值是 BPF 程序句柄。
        BPF_MAP_TYPE_PROG_ARRAY = 3,
        // 存储 perf_event 文件描述符的数组类型的 BPF Map。支持下标访问操作，值是 perf_event 文件描述符。
        BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
        // 针对多核心场景，哈希表类型的 BPF Map。支持键值对读写操作，键和值的大小是可配置的，每个 CPU 核心都有一份独立的哈希表。
        BPF_MAP_TYPE_PERCPU_HASH = 5,
        // 针对多核心场景，数组类型的 BPF Map。支持下标访问操作，值的大小是可配置的，每个 CPU 核心都有一份独立的数组。
        BPF_MAP_TYPE_PERCPU_ARRAY = 6,
        // 用于跟踪内核函数调用栈的 BPF Map。每个键值对表示一个函数调用栈，键是调用栈 ID，值是调用栈的信息。
        BPF_MAP_TYPE_STACK_TRACE = 7,
        // 存储 cgroup 文件描述符的数组类型的 BPF Map。支持下标访问操作，值是 cgroup 文件描述符。
        BPF_MAP_TYPE_CGROUP_ARRAY = 8,
        // 带有 LRU（Least Recently Used）淘汰机制的哈希表类型的 BPF Map。
        // 支持键值对读写操作，键和值的大小是可配置的，会自动淘汰最近最少使用的键值对。
        BPF_MAP_TYPE_LRU_HASH = 9,
        // 针对多核心场景，带有 LRU 淘汰机制的哈希表类型的 BPF Map。支持键值对读写操作，键和值的大小是可配置的。
        // 每个 CPU 核心都有一份独立的哈希表，会自动淘汰最近最少使用的键值对。
        BPF_MAP_TYPE_LRU_PERCPU_HASH = 10,
        // 前缀树类型的 BPF Map。支持前缀匹配操作，键是 IP 地址前缀，值是用户定义的数据。
        BPF_MAP_TYPE_LPM_TRIE = 11,
        // 数组类型的 BPF Map，每个元素都是一个子 BPF Map 的句柄。支持下标访问操作，可以用于构建更复杂的数据结构。
        BPF_MAP_TYPE_ARRAY_OF_MAPS = 12,
        // 类似 BPF_MAP_TYPE_HASH，但是 value 是另一个 Map。
        BPF_MAP_TYPE_HASH_OF_MAPS = 13,
        // 用于管理和查找内核中设备和设备驱动程序之间的关系的 Map。
        BPF_MAP_TYPE_DEVMAP = 14,
        // 用于跟踪和操作套接字的 Map。
        BPF_MAP_TYPE_SOCKMAP = 15,
        // 用于跟踪和操作 CPU 和处理器的 Map。
        BPF_MAP_TYPE_CPUMAP = 16,
        // 用于 XDP 程序中的共享内存区域，支持从用户空间和内核空间同时访问。
        BPF_MAP_TYPE_XSKMAP = 17,
        // 类似 BPF_MAP_TYPE_SOCKMAP，但是使用哈希表而不是数组来存储套接字。
        BPF_MAP_TYPE_SOCKHASH = 18,
        // 用于在 cgroup v1 中存储关联的数据。
        BPF_MAP_TYPE_CGROUP_STORAGE = 19,
        // 用于存储共享套接字列表，用于 SO_REUSEPORT 选项。
        BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20,
        // 类似 BPF_MAP_TYPE_CGROUP_STORAGE，但是使用 per-cpu 数组来存储数据。
        BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21,
        // 用于实现队列，支持多个生产者和多个消费者。
        BPF_MAP_TYPE_QUEUE = 22,
        // 用于实现栈。
        BPF_MAP_TYPE_STACK = 23,
        // 用于在 BPF 程序和用户空间之间共享套接字数据。
        BPF_MAP_TYPE_SK_STORAGE = 24,
        // 类似 BPF_MAP_TYPE_DEVMAP，但是使用哈希表而不是数组来存储设备和设备驱动程序之间的关系。
        BPF_MAP_TYPE_DEVMAP_HASH = 25,
        // 用于在 BPF 程序和用户空间之间共享结构体定义。
        BPF_MAP_TYPE_STRUCT_OPS = 26,
        // 用于实现环形缓冲区。
	    BPF_MAP_TYPE_RINGBUF = 27,
	    // 用于在 cgroup v2 中存储关联的数据。
        BPF_MAP_TYPE_INODE_STORAGE = 28,
        // 用于在 BPF 程序和用户空间之间共享与任务相关的数据。
        BPF_MAP_TYPE_TASK_STORAGE = 29,
};

/*
 *  使用 enum 定义 sk_action 枚举常量
*/
enum sk_action {
        // 丢弃
        SK_DROP = 0,
        // 通过
        SK_PASS = 1,
};

/*
 *  使用 enum 定义枚举常量
*/
enum {
        // 如果 key 不存在，则创建一个新元素，否则更新现有元素的值。
        BPF_ANY = 0,
        // 如果 key 不存在，则创建一个新元素，否则操作失败。
        BPF_NOEXIST = 1,
        // 如果 key 存在，则更新现有元素的值，否则操作失败。
        BPF_EXIST = 2,
        // 在更新元素之前获取元素锁。
        BPF_F_LOCK = 4,
};

/*
 *  使用 enum 定义枚举常量
*/
enum {
        // BPF_F_INGRESS 是在 eBPF 程序中使用的一个标志，
        // 用于指示程序应该在数据包到达 Linux 内核网络协议栈时处理它们（也就是入站方向）
        // 在 eBPF 程序中，可以通过将 BPF_F_INGRESS 标志传递给 bpf_prog_load() 或 bpf_prog_attach() 函数
        // 来指示该程序要作为网络协议栈的一个钩子来运行。
        BPF_F_INGRESS = 1,
};

/*
 *  使用 enum 定义枚举常量
*/
enum {
        // BPF套接字操作回调函数的标志位
        // 启用超时时间回调函数。
        BPF_SOCK_OPS_RTO_CB_FLAG = 1,
        // 启用重传计数器回调函数。
        BPF_SOCK_OPS_RETRANS_CB_FLAG = 2,
        // 启用套接字状态回调函数。
        BPF_SOCK_OPS_STATE_CB_FLAG = 4,
        // 启用往返时间回调函数。
        BPF_SOCK_OPS_RTT_CB_FLAG = 8,
        // 启用所有报头选项的回调函数。
        BPF_SOCK_OPS_PARSE_ALL_HDR_OPT_CB_FLAG = 16,
        // 启用未知报头选项的回调函数。
        BPF_SOCK_OPS_PARSE_UNKNOWN_HDR_OPT_CB_FLAG = 32,
        // 启用写入报头选项的回调函数。
        BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG = 64,
        // 表示所有回调函数均已启用。
        BPF_SOCK_OPS_ALL_CB_FLAGS = 127,
};

/*
 *  使用 enum 定义枚举常量
*/
enum {
        // 保留字段，没有实际含义。
        BPF_SOCK_OPS_VOID = 0,
        // 初始化套接字的超时时间。
        BPF_SOCK_OPS_TIMEOUT_INIT = 1,
        // 初始化套接字的接收窗口大小。
        BPF_SOCK_OPS_RWND_INIT = 2,
        // TCP连接建立时回调函数。
        BPF_SOCK_OPS_TCP_CONNECT_CB = 3,
        // 主动发起的TCP连接建立成功时回调函数。
        BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB = 4,
        // 被动接收的TCP连接建立成功时回调函数。
        BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB = 5,
        // 在套接字上启用显式拥塞通知（ECN）。
        BPF_SOCK_OPS_NEEDS_ECN = 6,
        // 获取基准往返时间（RTT）。
        BPF_SOCK_OPS_BASE_RTT = 7,
        // 重新计算超时时间（RTO）时回调函数。
        BPF_SOCK_OPS_RTO_CB = 8,
        // 重传时回调函数。
        BPF_SOCK_OPS_RETRANS_CB = 9,
        // 套接字状态发生变化时回调函数。
        BPF_SOCK_OPS_STATE_CB = 10,
        // TCP监听套接字接受连接时回调函数。
        BPF_SOCK_OPS_TCP_LISTEN_CB = 11,
        // 计算RTT时回调函数。
        BPF_SOCK_OPS_RTT_CB = 12,
        // 解析TCP头部选项时回调函数。
        BPF_SOCK_OPS_PARSE_HDR_OPT_CB = 13,
        // TCP头部选项长度变化时回调函数。
        BPF_SOCK_OPS_HDR_OPT_LEN_CB = 14,
        // 写入TCP头部选项时回调函数。
        BPF_SOCK_OPS_WRITE_HDR_OPT_CB = 15,
};

/*
 *  使用 enum 定义枚举常量
*/
enum {
        // BPF（Berkeley Packet Filter）中用于表示 TCP 状态的常量
        // 已建立连接
        BPF_TCP_ESTABLISHED = 1,
        // SYN 包已发送，等待对端回应
        BPF_TCP_SYN_SENT = 2,
        // 已接收到对端的 SYN 包，正在等待发送 ACK 包
        BPF_TCP_SYN_RECV = 3,
        // 已发送 FIN 包，等待对端的 ACK 包
        BPF_TCP_FIN_WAIT1 = 4,
        // 已接收到对端的 ACK 包，等待对端发送 FIN 包
        BPF_TCP_FIN_WAIT2 = 5,
        // 等待 2MSL 时间，等待任何未到达的报文段，并且确保它们已被丢弃，以避免连接复用时发生冲突
        BPF_TCP_TIME_WAIT = 6,
        // 连接已关闭，但是在此状态下仍可以接收数据
        BPF_TCP_CLOSE = 7,
        // 已经发送了 FIN 包，正在等待对端关闭连接
        BPF_TCP_CLOSE_WAIT = 8,
        // 已经接收到对端的 FIN 包，正在等待发送 ACK 包
        BPF_TCP_LAST_ACK = 9,
        // 正在监听传入的连接请求
        BPF_TCP_LISTEN = 10,
        // 等待对端的 ACK 包，以使连接状态过渡到 TIME_WAIT
        BPF_TCP_CLOSING = 11,
        // 等待在新套接字上接收到的 SYN 包
        BPF_TCP_NEW_SYN_RECV = 12,
        // 用于检查 TCP 状态是否有效的边界值
        BPF_TCP_MAX_STATES = 13,
};

struct bpf_sock_ops {
        // Socket操作类型
        __u32 op;
        union {
                // Socket操作的参数，使用数组形式存储，最多包含4个参数
                __u32 args[4];
                // 操作的返回值
                __u32 reply;
                // 操作的返回值，使用数组形式存储，最多包含4个返回值
                __u32 replylong[4];
        };
        // Socket的地址族（如AF_INET）
        __u32 family;
        // 远程 IP 地址 (IPv4)
        __u32 remote_ip4;
        // 本地 IP 地址（IPv4）
        __u32 local_ip4;
        // 远程IP地址（IPv6）
        __u32 remote_ip6[4];
        // 本地IP地址（IPv6）
        __u32 local_ip6[4];
        // 远程端口号
        __u32 remote_port;
        // 本地端口号
        __u32 local_port;
        // Socket是否为完整Socket，即是否含有完整的5元组信息
        __u32 is_fullsock;
        // 发送方拥塞窗口大小
        __u32 snd_cwnd;
        // 平滑的往返时间（RTT）
        __u32 srtt_us;
        // 回调函数的标志位，由枚举类型bpf_sock_ops_cb_flags定义
        __u32 bpf_sock_ops_cb_flags;
        // Socket的状态，由枚举类型bpf_tcp_state定义
        __u32 state;
        // 最小往返时间
        __u32 rtt_min;
        // 慢启动门限
        __u32 snd_ssthresh;
        // 接收到的数据包的下一个序列号
        __u32 rcv_nxt;
        // 下一个要发送的数据包的序列号
        __u32 snd_nxt;
        // 已经发送的最后一个未确认的数据包的序列号
        __u32 snd_una;
        // MSS（Maximum Segment Size）缓存
        __u32 mss_cache;
        // ECN（Explicit Congestion Notification）标志位
        __u32 ecn_flags;
        // 发送的数据包的速率
        __u32 rate_delivered;
        // 速率统计的时间间隔
        __u32 rate_interval_us;
        // 已经发送的数据包数
        __u32 packets_out;
        // 已经重传的数据包数
        __u32 retrans_out;
        // 总共重传的数据包数
        __u32 total_retrans;
        // 已经接收的数据包数
        __u32 segs_in;
        // 已经接收到的数据包中的数据段数
        __u32 data_segs_in;
        // 已经发送的数据包数
        __u32 segs_out;
        // 已经发送的数据包中的数据段数
        __u32 data_segs_out;
        // 已经发送的数据包中丢失的数据包数
        __u32 lost_out;
        // 已经发送的数据包中使用SACK选项确认的数据包数
        __u32 sacked_out;
        // Socket的散列值
        __u32 sk_txhash;
        // 接收到的字节数
        __u64 bytes_received;
        // 已经确认的字节数
        __u64 bytes_acked;
        union {
                // 对应的Socket结构体
                struct bpf_sock *sk;
        };
        union {
                // 指向数据包中数据部分的指针
                void *skb_data;
        };
        union {
                // 指向数据包数据部分末尾的指针
                void *skb_data_end;
        };
        // 数据包长度
        __u32 skb_len;
        // TCP标志位
        __u32 skb_tcp_flags;
};

struct sk_msg_md {
        union {
                // 指向消息数据的指针。
                void *data;
        };
        union {
                // 指向消息数据结束位置的指针。
                void *data_end;
        };
        // 协议族（AF_INET 或 AF_INET6）
        __u32 family;
        // 远程 IPv4 地址。
        __u32 remote_ip4;
        // 本地 IPv4 地址。
        __u32 local_ip4;
        // 远程 IPv6 地址。
        __u32 remote_ip6[4];
        // 本地 IPv6 地址。
        __u32 local_ip6[4];
        // 远程端口号。
        __u32 remote_port;
        // 本地端口号。
        __u32 local_port;
        // 消息数据大小。
        __u32 size;
        union {
                // 指向套接字对象的指针。
                struct bpf_sock *sk;
        };
};

// 结束一个 #if……#else 条件编译块
#endif
