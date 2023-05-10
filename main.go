package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf -cflags "-D__TARGET_ARCH_x86" bpf_redir   bpf/bpf_redir.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf -cflags "-D__TARGET_ARCH_x86" bpf_sockops bpf/bpf_sockops.c

// go generate 在代码生成阶段自动化地运行命令，上述命名生成 bpf 程序

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/containers/common/pkg/cgroupv2"
	"golang.org/x/sys/unix"
)

const (
	// FilesystemTypeBPFFS 在 Linux 系统中，BPF_FS_MAGIC 常量用于表示 BPF 文件系统的魔数（magic number），
	// 它是一个 16 进制数值，通常为 0xcafe4a11。在 ARM 架构上，可以通过查询操作系统的头文件来确定该常量的定义。
	FilesystemTypeBPFFS = unix.BPF_FS_MAGIC
	// MapsRoot bpf 根目录
	MapsRoot = "/sys/fs/bpf"
	// MapsPinpath tcpip-bypass 目录
	MapsPinpath = "/sys/fs/bpf/tcpip-bypass"
)

type BypassProgram struct {
	// 定义在 BPF 程序开发中常用的头文件 bpf_sockops.h 中，用于简化在 BPF 程序中访问 Socket 操作函数的操作。
	sockops_Obj bpf_sockopsObjects
	// 定义在 BPF 程序开发中常用的头文件 bpf_helpers.h 中，用于简化在 BPF 程序中访问 Socket 重定向功能的操作。
	redir_Obj     bpf_redirObjects
	SockopsCgroup link.Link
}

// 设置 bpf 程序内存 limit 限制
func setLimit() error {
	var err error = nil

	err = unix.Setrlimit(unix.RLIMIT_MEMLOCK,
		&unix.Rlimit{
			Cur: unix.RLIM_INFINITY,
			Max: unix.RLIM_INFINITY,
		})
	if err != nil {
		fmt.Printf("failed to set rlimit: %v", err)
	}

	return err
}

func getCgroupPath() (string, error) {
	var err error = nil
	cgroupPath := "/sys/fs/cgroup"

	enabled, err := cgroupv2.Enabled()
	// 如果没有开启 cgroupv2 则使用 /sys/fs/cgroup/unified
	if !enabled {
		cgroupPath = filepath.Join(cgroupPath, "unified")
	}
	return cgroupPath, err
}

func loadProgram(prog BypassProgram) (BypassProgram, error) {
	var err error
	var options ebpf.CollectionOptions

	err = os.Mkdir(MapsPinpath, os.ModePerm)
	if err != nil {
		fmt.Println(err)
	}

	options.Maps.PinPath = MapsPinpath

	// 在用户空间中将这些函数指针和相应的内核空间中的函数进行绑定
	// 并将绑定后的 bpf_redirObjects 结构体传递给 BPF 程序使用。
	if err = loadBpf_redirObjects(&prog.redir_Obj, &options); err != nil {
		fmt.Println("Error load objects:", err)
	}

	// 实现 BPF_PROG_ATTACH
	if err = link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  prog.redir_Obj.bpf_redirMaps.MapRedir.FD(),
		Program: prog.redir_Obj.bpf_redirPrograms.BpfRedirProxy,
		Attach:  ebpf.AttachSkMsgVerdict,
	}); err != nil {
		fmt.Printf("Error attaching to sockmap: %s\n", err)
	}

	// 将 BPF 程序中常用的函数指针与相应的内核空间函数进行绑定，
	// 并将绑定后的结果填充到 bpf_sockopsObjects 结构体中相应字段的函数。
	if err = loadBpf_sockopsObjects(&prog.sockops_Obj, &options); err != nil {
		fmt.Println("Error load objects:", err)
	}

	if cgroupPath, cgroupPathErr := getCgroupPath(); cgroupPathErr == nil {
		// AttachCgroup 函数将一个 BPF 程序与一个 cgroup 进行关联，从而使该程序能够访问与该 cgroup 相关的信息
		prog.SockopsCgroup, cgroupPathErr = link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupPath,
			Attach:  ebpf.AttachCGroupSockOps,
			Program: prog.sockops_Obj.bpf_sockopsPrograms.BpfSockmap,
		})
		if cgroupPathErr != nil {
			fmt.Printf("Error attaching sockops to cgroup: %s", cgroupPathErr)
		}
	}

	return prog, err
}

func closeProgram(prog BypassProgram) {
	var err error

	if prog.SockopsCgroup != nil {
		fmt.Printf("Closing sockops cgroup...\n")
		// 即使进程退出，链接也可能会继续存在超出进程生命周期的时间，
		// 因此在程序运行结束时应该调用 Close 方法来关闭链接，以免出现资源泄露等问题。
		prog.SockopsCgroup.Close()
	}

	// detach BPF_PROG_DETACH
	if prog.redir_Obj.bpf_redirPrograms.BpfRedirProxy != nil {
		err = link.RawDetachProgram(link.RawDetachProgramOptions{
			// 该 Map 中存储了一组键值对，其中键为 bpf_redir_key 结构体类型，代表了一个重定向规则的键；
			// 值为 bpf_redir_value 结构体类型，代表了一个重定向规则的值。
			Target:  prog.redir_Obj.bpf_redirMaps.MapRedir.FD(),
			Program: prog.redir_Obj.bpf_redirPrograms.BpfRedirProxy,
			Attach:  ebpf.AttachSkMsgVerdict,
		})
		if err != nil {
			fmt.Printf("Error detaching '%v'\n", err)
		}
		fmt.Printf("Closing redirect prog...\n")
	}

	// 存储已经建立连接的 socket 文件描述符和其对应的 bpf_sock_ops 结构体的 Map。
	if prog.sockops_Obj.bpf_sockopsMaps.MapActiveEstab != nil {
		// 将 bpf_sockopsMaps.MapActiveEstab 对象在内核中的引用计数减一，从而允许该对象在内核中被删除或卸载。
		prog.sockops_Obj.bpf_sockopsMaps.MapActiveEstab.Unpin()
		// 关闭 bpf_sockopsMaps.MapActiveEstab 对象，防止资源泄露
		prog.sockops_Obj.bpf_sockopsMaps.MapActiveEstab.Close()
	}

	// 同理，处理 MapProxy
	if prog.sockops_Obj.bpf_sockopsMaps.MapProxy != nil {
		prog.sockops_Obj.bpf_sockopsMaps.MapProxy.Unpin()
		prog.sockops_Obj.bpf_sockopsMaps.MapProxy.Close()
	}

	// 同理，处理 MapRedir
	if prog.sockops_Obj.bpf_sockopsMaps.MapRedir != nil {
		prog.sockops_Obj.bpf_sockopsMaps.MapRedir.Unpin()
		prog.sockops_Obj.bpf_sockopsMaps.MapRedir.Close()
	}

	// 同理，处理 DebugMap
	if prog.sockops_Obj.bpf_sockopsMaps.DebugMap != nil {
		prog.sockops_Obj.bpf_sockopsMaps.DebugMap.Unpin()
		prog.sockops_Obj.bpf_sockopsMaps.DebugMap.Close()
	}
}

// checkOrMountBPFFSDefault 挂载 /sys/fs/bpf 目录
func checkOrMountBPFFSDefault() error {
	var err error
	_, err = os.Stat(MapsRoot)
	if err != nil {
		if os.IsNotExist(err) {
			if mkErr := os.MkdirAll(MapsRoot, 0755); mkErr != nil {
				return fmt.Errorf("unable to create bpf mount directory: %v", mkErr)
			}
		}
	}
	fst := unix.Statfs_t{}
	err = unix.Statfs(MapsRoot, &fst)
	if err != nil {
		return &os.PathError{Op: "statfs", Path: MapsRoot, Err: err}
	} else if fst.Type == FilesystemTypeBPFFS {
		return nil
	}

	err = unix.Mount(MapsRoot, MapsRoot, "bpf", 0, "")
	if err != nil {
		return fmt.Errorf("failed to mount %s: %v", MapsRoot, err)
	}
	return nil
}

func main() {
	var prog BypassProgram

	err := checkOrMountBPFFSDefault()
	if err != nil {
		fmt.Printf("BPF filesystem mounting on /sys/fs/bpf failed: %v\n", err)
		return
	}

	if err = setLimit(); err != nil {
		fmt.Println("Setting limit failed:", err)
		return
	}

	prog, err = loadProgram(prog)
	if err != nil {
		fmt.Println("Loading program failed:", err)
		return
	}
	defer closeProgram(prog)

	fmt.Println("Start tcpip-bypass...")
	defer fmt.Println("Exiting...")

	c := make(chan os.Signal, 1)
	signal.Notify(c)
	<-c
}
