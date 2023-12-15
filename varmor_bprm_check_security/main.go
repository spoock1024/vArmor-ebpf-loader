package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"log"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"syscall"
	"time"
)

//go:embed bin/varmor.o
var _bytecode []byte

type pathPattern struct {
	Flags  uint32
	Prefix [64]byte
	Suffix [64]byte
}

type bpfPathRule struct {
	Permissions uint32
	Pattern     pathPattern
}

const (
	PreciseMatch  = 0x00000001
	GreedyMatch   = 0x00000002
	PrefixMatch   = 0x00000004
	SuffixMatch   = 0x00000008
	CidrMatch     = 0x00000020
	Ipv4Match     = 0x00000040
	Ipv6Match     = 0x00000080
	PortMatch     = 0x00000100
	AaMayExec     = 0x00000001
	AaMayWrite    = 0x00000002
	AaMayRead     = 0x00000004
	AaMayAppend   = 0x00000008
	AaPtraceTrace = 0x00000002
	AaPtraceRead  = 0x00000004
	AaMayBeTraced = 0x00000008
	AaMayBeRead   = 0x00000010
	AaMayUmount   = 0x00000200
)

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
	prog := coll.Programs["varmor_bprm_check_security"]
	if prog == nil {
		log.Fatalf("program not found in collection")
	}
	_, err = link.AttachLSM(link.LSMOptions{
		Program: prog,
	})
	if err != nil {
		log.Fatalf("failed to attach varmor_file_open program: %v", err)
	}
	fmt.Println("successfully attached varmor_bprm_check_security program")
	fmt.Println("successfully started, head over to /sys/kernel/debug/tracing/trace_pipe")

	outerBPRMBprmMap, ok := coll.Maps["v_bprm_outer"]
	if !ok {
		log.Fatalf("outerBPRMBprmMap not found in collection")
	}
	bprmMapName := fmt.Sprintf("v_bprm_inner_%d", nsID)
	innerbprmMapSpec := ebpf.MapSpec{
		Name:       bprmMapName,
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  4*2 + 64*2,
		MaxEntries: uint32(50),
	}

	innerbprmMap, err := ebpf.NewMap(&innerbprmMapSpec)
	if err != nil {
		log.Fatalf("failed to create inner map: %v", err)
		return
	}
	defer innerbprmMap.Close()

	var ExecpathRule bpfPathRule
	var execPrefix, execSuffix [64]byte
	copy(execPrefix[:], "/usr/bin/curl")
	copy(execSuffix[:], "")

	// permissions: 4 for AaMayRead
	ExecpathRule.Permissions = AaMayExec
	ExecpathRule.Pattern.Flags = PreciseMatch | PrefixMatch
	ExecpathRule.Pattern.Prefix = execPrefix
	ExecpathRule.Pattern.Suffix = execSuffix

	var bprmIndex = uint32(0)
	err = innerbprmMap.Put(&bprmIndex, &ExecpathRule)
	if err != nil {
		log.Fatalf("failed to put rule: %v", err)
	}
	outerBPRMBprmMap.Put(uint32(nsID), innerbprmMap)

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
