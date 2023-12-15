package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"github.com/cilium/ebpf/link"
	"log"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
)

//go:embed bin/varmor.o
var _bytecode []byte

// bpfNetworkRule rules
type bpfNetworkRule struct {
	Flags   uint32
	Address [16]byte
	Mask    [16]byte
	Port    uint32
}

func readMntID() (int, error) {
	// 读取文件内容
	content, err := os.Readlink("/proc/1/ns/mnt")
	if err != nil {
		fmt.Println("无法读取文件:", err)
		return -1, fmt.Errorf("无法读取文件: %w", err)
	}

	// 使用正则表达式提取数值
	re := regexp.MustCompile(`\[(\d+)\]`)
	match := re.FindStringSubmatch(string(content))
	if len(match) < 2 {
		return -1, fmt.Errorf("未找到匹配的数值")
	}

	// 提取到的数值
	mntValueStr := match[1]
	mntValue, err := strconv.Atoi(mntValueStr)
	if err != nil {
		return -1, fmt.Errorf("转换数值失败: %w", err)
	}
	return mntValue, nil
}

func main() {
	nsID, err := readMntID()
	if err != nil {
		log.Fatalf("failed to read mnt id: %v", err)
	}

	fmt.Println(fmt.Sprintf("nsID: %d", nsID))

	// 加载eBPF程序集合
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(_bytecode))
	if err != nil {
		log.Fatalf("failed to load collection spec: %v", err)
	}

	// 配置网络
	netInnerMap := ebpf.MapSpec{
		Name:       "v_net_inner_",
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  4*2 + 16*2,
		MaxEntries: 1024,
	}
	spec.Maps["v_net_outer"].InnerMap = &netInnerMap

	// 加载 bprm 规则
	bprmInnerMap := ebpf.MapSpec{
		Name:       "v_bprm_inner_",
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  4*2 + 64*2,
		MaxEntries: 50,
	}
	spec.Maps["v_bprm_outer"].InnerMap = &bprmInnerMap

	// 加载文件规则
	fileInnerMap := ebpf.MapSpec{
		Name:       "v_file_inner_",
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  4*2 + 64*2,
		MaxEntries: 50,
	}
	spec.Maps["v_file_outer"].InnerMap = &fileInnerMap

	mountInnerMap := ebpf.MapSpec{
		Name:       "v_mount_inner_",
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  4*3 + 16 + 64*2,
		MaxEntries: 50,
	}
	spec.Maps["v_mount_outer"].InnerMap = &mountInnerMap

	// 加载程序
	// 加载eBPF程序集合
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("failed to load collection: %v", err)
	}
	defer coll.Close()

	// 从集合中加载`varmor_socket_connect`
	prog := coll.Programs["varmor_socket_connect"]
	if prog == nil {
		log.Fatalf("program not found in collection")
	}
	_, err = link.AttachLSM(link.LSMOptions{
		Program: prog,
	})
	if err != nil {
		log.Fatalf("failed to attach varmor_socket_connect program: %v", err)
	}
	fmt.Println("successfully attached varmor_socket_connect program")

	fmt.Println("successfully started, head over to /sys/kernel/debug/tracing/trace_pipe")

	// 配置网络规则
	outerMap, ok := coll.Maps["v_net_outer"]
	if !ok {
		log.Fatalf("map not found in collection")
	}
	mapName := fmt.Sprintf("v_net_inner_%d", nsID)
	innerMapSpec := ebpf.MapSpec{
		Name:       mapName,
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  4*2 + 16*2,
		MaxEntries: uint32(50),
	}

	innerMap, err := ebpf.NewMap(&innerMapSpec)
	if err != nil {
		log.Fatalf("failed to create inner map: %v", err)
		return
	}
	defer innerMap.Close()

	var rule bpfNetworkRule
	rule.Port = 443
	rule.Flags |= 0x00000001
	ip := net.ParseIP("1.1.1.1")
	if ip.To4() != nil {
		copy(rule.Address[:], ip.To4())
	} else {
		copy(rule.Address[:], ip.To16())
	}
	var index uint32 = uint32(0)
	err = innerMap.Put(&index, &rule)
	if err != nil {
		log.Fatalf("failed to put rule: %v", err)
	}
	outerMap.Put(uint32(nsID), innerMap)

	// Wait for an interrupt or a timeout
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-sig:
		// Interrupt signal received, close the collection
		coll.Close()
	case <-time.After(10 * time.Minute):
		// Timeout after 10 minutes, close the collection
		coll.Close()
	}
}
