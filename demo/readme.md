# vmlinux

同目录下的 vmlinux.h 文件是通过执行以下命名生成的。

```
run the following command in btf supported OS such as ubuntu 21.04 and deleted unused lines
在支持 BTF（BPF Type Format）的操作系统中（例如 Ubuntu 21.04），运行以下命令并删除未使用的行。
BTF 是 Linux 内核中用于表示 C 语言结构体和函数的类型信息的一种格式。
在 BPF 程序中，使用 BTF 可以更加方便地访问内核中的数据结构，提高 BPF 程序的可读性和可维护性。
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```
