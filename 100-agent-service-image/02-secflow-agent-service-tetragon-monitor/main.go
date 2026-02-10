package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esutil"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
	"gopkg.in/ini.v1"
)

// 配置结构
type Config struct {
	ESEndpoint    string
	ESUsername    string
	ESPassword    string
	IndexPrefix   string
	TetragonSock  string
	SelfPID       int
	HostIP        string
	Hostname      string
	UUID          string
}

// 事件类型枚举
type EventType string

const (
	EventProcessExec      EventType = "process_exec"
	EventFileOp           EventType = "file_op"
	EventNetwork          EventType = "network"
	EventSyscall          EventType = "syscall"
	EventCapability       EventType = "capability"
	EventNamespace        EventType = "namespace"
	EventSignal           EventType = "signal"
	EventProcessExit      EventType = "process_exit"
	EventKernelModule     EventType = "kernel_module"
	EventPrivilegeEsc     EventType = "privilege_escalation"
	EventFilesystemMount  EventType = "filesystem_mount"
	EventMemory           EventType = "memory"
)

// 事件去重键
type DedupKey struct {
	PID         int
	EventType   EventType
	Key         string
	Timestamp   time.Time
}

// 去重管理器
type DedupManager struct {
	mu            sync.RWMutex
	dedupCache    map[string]time.Time
	config        *DedupConfig
	enabledEvents map[EventType]bool
}

// 去重配置
type DedupConfig struct {
	Enabled      bool
	Window       time.Duration
	EventConfigs map[EventType]DedupRule
}

// 去重规则
type DedupRule struct {
	Enabled bool
	KeyFunc func(interface{}) string
}

// 全局变量
var (
	config       Config
	dedupManager *DedupManager
	esClient     *elasticsearch.Client
	stats        = &StatsCollector{}
	selfPIDs     = make(map[int]bool)
)

// 统计收集器
type StatsCollector struct {
	mu              sync.RWMutex
	eventCounts     map[EventType]int64
	dedupedCounts   map[EventType]int64
	processedCounts map[EventType]int64
}

func NewStatsCollector() *StatsCollector {
	return &StatsCollector{
		eventCounts:     make(map[EventType]int64),
		dedupedCounts:   make(map[EventType]int64),
		processedCounts: make(map[EventType]int64),
	}
}

func (s *StatsCollector) Increment(eventType EventType, deduped bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.eventCounts[eventType]++
	if deduped {
		s.dedupedCounts[eventType]++
	} else {
		s.processedCounts[eventType]++
	}
}

func (s *StatsCollector) GetStats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[string]interface{})
	for eventType, count := range s.eventCounts {
		result[string(eventType)] = map[string]interface{}{
			"total":     count,
			"deduped":   s.dedupedCounts[eventType],
			"processed": s.processedCounts[eventType],
		}
	}
	return result
}

// 在main函数中添加重试逻辑
func connectToTetragon() {
	maxRetries := 10
	retryDelay := 5 * time.Second

	for i := 0; i < maxRetries; i++ {
		fmt.Printf("尝试连接Tetragon (尝试 %d/%d)...\n", i+1, maxRetries)

		// 检查socket文件是否存在
		if _, err := os.Stat(config.TetragonSock); os.IsNotExist(err) {
			fmt.Printf("Tetragon socket不存在，等待...\n")
			time.Sleep(retryDelay)
			continue
		}

		conn, err := grpc.Dial(
			"unix://"+config.TetragonSock,
			grpc.WithInsecure(),
			grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(50*1024*1024)), // 50MB
		)

		if err != nil {
			fmt.Printf("连接Tetragon失败: %v\n", err)
			time.Sleep(retryDelay)
			continue
		}

		defer conn.Close()
		fmt.Println("成功连接到Tetragon")

		client := tetragon.NewFineGuidanceSensorsClient(conn)
		ctx := context.Background()

		// 获取Tetragon版本信息
		versionResp, err := client.GetVersion(ctx, &tetragon.GetVersionRequest{})
		if err != nil {
			fmt.Printf("获取Tetragon版本失败: %v\n", err)
		} else {
			fmt.Printf("Tetragon版本: %s\n", versionResp.Version)
		}

		// 开始监听事件
		stream, err := client.GetEvents(ctx, &tetragon.GetEventsRequest{})
		if err != nil {
			fmt.Printf("获取事件流失败: %v\n", err)
			time.Sleep(retryDelay)
			continue
		}

		fmt.Println("开始监听事件...")
		eventCounter := 0

		for {
			res, err := stream.Recv()
			if err == io.EOF {
				fmt.Println("Tetragon连接关闭")
				break
			}
			if err != nil {
				fmt.Printf("接收事件失败: %v\n", err)
				break
			}

			eventCounter++
			if eventCounter%1000 == 0 {
				fmt.Printf("已处理 %d 个事件\n", eventCounter)
			}

			go processEvent(res)
		}

		// 如果连接断开，重试
		fmt.Println("连接断开，尝试重新连接...")
		time.Sleep(retryDelay)
	}

	fmt.Println("达到最大重试次数，退出")
	os.Exit(1)
}

func main() {
	// 初始化配置
	if err := initConfig(); err != nil {
		fmt.Printf("初始化配置失败: %v\n", err)
		os.Exit(1)
	}

	// 初始化自身PID
	config.SelfPID = os.Getpid()
	selfPIDs[config.SelfPID] = true

	// 获取Tetragon进程PID（用于过滤）
	getTetragonPIDs()

	// 初始化去重管理器
	initDedupManager()

	// 初始化ES客户端
	if err := initESClient(); err != nil {
		fmt.Printf("初始化ES客户端失败: %v\n", err)
		os.Exit(1)
	}

	// 启动API服务器
	go startAPIServer()

	// 连接Tetragon并处理事件
	connectToTetragon()
}

func initConfig() error {
	// 从环境变量读取ES配置
	config.ESEndpoint = os.Getenv("ES_ENDPOINT")
	if config.ESEndpoint == "" {
		return fmt.Errorf("ES_ENDPOINT环境变量未设置")
	}
	config.ESUsername = os.Getenv("ES_USERNAME")
	config.ESPassword = os.Getenv("ES_PASSWORD")
	config.IndexPrefix = os.Getenv("ES_INDEX_PREFIX")
	if config.IndexPrefix == "" {
		config.IndexPrefix = "tetragon-events"
	}

	config.TetragonSock = os.Getenv("TETRAGON_SOCK")
	if config.TetragonSock == "" {
		config.TetragonSock = "/var/run/tetragon/tetragon.sock"
	}

	// 获取主机信息
	config.Hostname, _ = os.Hostname()
	config.HostIP = getBridgeIP("br-sothoth")

	// 解析配置文件获取UUID
	if err := parseConfigFile("/sothothv2/config/sothothv2_agent.ini"); err != nil {
		return fmt.Errorf("解析配置文件失败: %v", err)
	}

	// 检查必要的环境变量
	if config.ESEndpoint == "" {
		return fmt.Errorf("ES_ENDPOINT环境变量必须设置")
	}

	// 检查socket文件
	if _, err := os.Stat(config.TetragonSock); err != nil {
		fmt.Printf("警告: Tetragon socket文件不存在: %s\n", config.TetragonSock)
	}

	return nil
}

func getBridgeIP(bridgeName string) string {
	cmd := exec.Command("ip", "-4", "addr", "show", bridgeName)
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}

	re := regexp.MustCompile(`inet (\d+\.\d+\.\d+\.\d+)`)
	matches := re.FindStringSubmatch(string(output))
	if len(matches) > 1 {
		return matches[1]
	}
	return "unknown"
}

func parseConfigFile(path string) error {
	cfg, err := ini.Load(path)
	if err != nil {
		return err
	}
	config.UUID = cfg.Section("").Key("uuid").String()
	return nil
}

func getTetragonPIDs() {
	// 查找Tetragon相关进程
	cmd := exec.Command("pgrep", "-f", "tetragon")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(strings.TrimSpace(string(output)), "\n")
		for _, line := range lines {
			if pid := strings.TrimSpace(line); pid != "" {
				var p int
				fmt.Sscanf(pid, "%d", &p)
				selfPIDs[p] = true
			}
		}
	}
}

func initDedupManager() {
	dedupManager = &DedupManager{
		dedupCache: make(map[string]time.Time),
		enabledEvents: map[EventType]bool{
			EventProcessExec:      true,
			EventFileOp:           true,
			EventNetwork:          true,
			EventSyscall:          true,
			EventCapability:       true,
			EventNamespace:        true,
			EventSignal:           true,
			EventProcessExit:      true,
			EventKernelModule:     true,
			EventPrivilegeEsc:     true,
			EventFilesystemMount:  true,
			EventMemory:           true,
		},
		config: &DedupConfig{
			Enabled: true,
			Window:  5 * time.Minute,
			EventConfigs: map[EventType]DedupRule{
				EventProcessExec: {
					Enabled: true,
					KeyFunc: func(data interface{}) string {
						event := data.(*tetragon.ProcessExec)
						// ProcessExec 的 Arguments 是单个字符串
						return fmt.Sprintf("exec:%d:%s:%s",
							event.Process.Pid.Value,
							event.Process.Binary,
							event.Process.Arguments)
					},
				},
				EventFileOp: {
					Enabled: true,
					KeyFunc: func(data interface{}) string {
						event := data.(*tetragon.ProcessKprobe)
						// 提取文件名和操作
						args := event.GetArgs()
						for _, arg := range args {
							if arg.GetFileArg() != nil {
								return fmt.Sprintf("file:%d:%s:%s",
									event.Process.Pid.Value,
									arg.GetFileArg().Path,
									event.FunctionName)
							}
						}
						return ""
					},
				},
				EventNetwork: {
					Enabled: true,
					KeyFunc: func(data interface{}) string {
						event := data.(*tetragon.ProcessKprobe)
						// 网络连接信息
						return fmt.Sprintf("net:%d:%s",
							event.Process.Pid.Value,
							event.FunctionName)
					},
				},
				// 其他事件类型的去重规则...
			},
		},
	}
}

func initESClient() error {
	cfg := elasticsearch.Config{
		Addresses: []string{config.ESEndpoint},
		Username:  config.ESUsername,
		Password:  config.ESPassword,
	}

	client, err := elasticsearch.NewClient(cfg)
	if err != nil {
		return err
	}

	esClient = client

	// 测试连接
	_, err = esClient.Info()
	return err
}

func processEvent(event *tetragon.GetEventsResponse) {
	// 过滤自身进程事件
	if isSelfProcess(event) {
		return
	}

	var eventType EventType
	var eventData interface{}

	switch event.Event.(type) {
	case *tetragon.GetEventsResponse_ProcessExec:
		eventType = EventProcessExec
		eventData = event.GetProcessExec()
	case *tetragon.GetEventsResponse_ProcessExit:
		eventType = EventProcessExit
		eventData = event.GetProcessExit()
	case *tetragon.GetEventsResponse_ProcessKprobe:
		kprobe := event.GetProcessKprobe()
		eventType = classifyKprobeEvent(kprobe)
		eventData = kprobe
	case *tetragon.GetEventsResponse_ProcessTracepoint:
		// 处理tracepoint事件
		eventType = EventSyscall
		eventData = event.GetProcessTracepoint()
	default:
		return
	}

	// 检查事件类型是否启用
	if !dedupManager.IsEventEnabled(eventType) {
		return
	}

	// 去重检查
	deduped := false
	if dedupManager.config.Enabled {
		deduped = dedupManager.CheckAndUpdate(eventType, eventData)
	}

	// 更新统计
	stats.Increment(eventType, deduped)

	// 如果未去重，则上报到ES
	if !deduped {
		go sendToES(eventType, eventData)
	}
}

func classifyKprobeEvent(kprobe *tetragon.ProcessKprobe) EventType {
	functionName := kprobe.FunctionName

	// 根据函数名分类事件类型
	switch {
	case strings.Contains(functionName, "open") ||
		strings.Contains(functionName, "read") ||
		strings.Contains(functionName, "write") ||
		strings.Contains(functionName, "close"):
		return EventFileOp
	case strings.Contains(functionName, "connect") ||
		strings.Contains(functionName, "accept") ||
		strings.Contains(functionName, "bind") ||
		strings.Contains(functionName, "listen"):
		return EventNetwork
	case strings.Contains(functionName, "cap_") ||
		strings.Contains(functionName, "setuid") ||
		strings.Contains(functionName, "setgid"):
		return EventCapability
	case strings.Contains(functionName, "clone") ||
		strings.Contains(functionName, "unshare"):
		return EventNamespace
	case strings.Contains(functionName, "kill") ||
		strings.Contains(functionName, "tkill"):
		return EventSignal
	case strings.Contains(functionName, "init_module") ||
		strings.Contains(functionName, "finit_module"):
		return EventKernelModule
	case strings.Contains(functionName, "execve"):
		return EventPrivilegeEsc
	case strings.Contains(functionName, "mount") ||
		strings.Contains(functionName, "umount"):
		return EventFilesystemMount
	case strings.Contains(functionName, "mmap") ||
		strings.Contains(functionName, "brk") ||
		strings.Contains(functionName, "mprotect"):
		return EventMemory
	default:
		return EventSyscall
	}
}

func isSelfProcess(event *tetragon.GetEventsResponse) bool {
	var pid int

	switch e := event.Event.(type) {
	case *tetragon.GetEventsResponse_ProcessExec:
		pid = int(e.ProcessExec.Process.Pid.Value)
	case *tetragon.GetEventsResponse_ProcessExit:
		pid = int(e.ProcessExit.Process.Pid.Value)
	case *tetragon.GetEventsResponse_ProcessKprobe:
		pid = int(e.ProcessKprobe.Process.Pid.Value)
	case *tetragon.GetEventsResponse_ProcessTracepoint:
		pid = int(e.ProcessTracepoint.Process.Pid.Value)
	default:
		return false
	}

	return selfPIDs[pid]
}

func (dm *DedupManager) IsEventEnabled(eventType EventType) bool {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	return dm.enabledEvents[eventType]
}

func (dm *DedupManager) CheckAndUpdate(eventType EventType, data interface{}) bool {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	// 获取去重规则
	rule, exists := dm.config.EventConfigs[eventType]
	if !exists || !rule.Enabled {
		return false
	}

	// 获取PID
	var pid int
	switch d := data.(type) {
	case *tetragon.ProcessExec:
		pid = int(d.Process.Pid.Value)
	case *tetragon.ProcessKprobe:
		pid = int(d.Process.Pid.Value)
	default:
		return false
	}

	// 生成去重键
	key := rule.KeyFunc(data)
	if key == "" {
		return false
	}

	cacheKey := fmt.Sprintf("%d:%s:%s", pid, eventType, key)

	// 检查是否在去重窗口内
	now := time.Now()
	if lastTime, exists := dm.dedupCache[cacheKey]; exists {
		if now.Sub(lastTime) <= dm.config.Window {
			return true // 需要去重
		}
	}

	// 更新缓存
	dm.dedupCache[cacheKey] = now

	// 清理过期的缓存项
	dm.cleanupCache()

	return false
}

func (dm *DedupManager) cleanupCache() {
	now := time.Now()
	for key, timestamp := range dm.dedupCache {
		if now.Sub(timestamp) > dm.config.Window {
			delete(dm.dedupCache, key)
		}
	}
}

func (dm *DedupManager) EnableDedup(enabled bool) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	dm.config.Enabled = enabled
}

func (dm *DedupManager) EnableEvent(eventType EventType, enabled bool) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	dm.enabledEvents[eventType] = enabled
}

func sendToES(eventType EventType, data interface{}) {
	// 构建事件文档
	doc := buildESDocument(eventType, data)

	indexName := fmt.Sprintf("%s-%s-%s", config.IndexPrefix, string(eventType), time.Now().Format("2006.01.02"))

	// 发送到ES
	_, err := esClient.Index(
		indexName,
		esutil.NewJSONReader(doc),
		esClient.Index.WithRefresh("true"),
	)

	if err != nil {
		fmt.Printf("发送事件到ES失败: %v\n", err)
	}
}

func buildESDocument(eventType EventType, data interface{}) map[string]interface{} {
	doc := make(map[string]interface{})
	doc["@timestamp"] = time.Now().Format(time.RFC3339)
	doc["event_type"] = string(eventType)
	doc["host"] = map[string]interface{}{
		"ip":       config.HostIP,
		"hostname": config.Hostname,
		"uuid":     config.UUID,
	}

	// 根据事件类型添加具体数据
	switch d := data.(type) {
	case *tetragon.ProcessExec:
		doc["process"] = map[string]interface{}{
			"pid":        d.Process.Pid.Value,
			"binary":     d.Process.Binary,
			"arguments":  d.Process.Arguments,
			"cwd":        d.Process.Cwd,
			"uid":        d.Process.Uid.Value,
			"parent_pid": d.Parent.Pid.Value,
		}
	case *tetragon.ProcessKprobe:
		doc["process"] = map[string]interface{}{
			"pid":    d.Process.Pid.Value,
			"binary": d.Process.Binary,
		}
		doc["function"] = d.FunctionName
		// 添加参数信息
		args := make([]interface{}, 0)
		for _, arg := range d.Args {
			args = append(args, arg.String())
		}
		doc["args"] = args
	}

	return doc
}

func startAPIServer() {
	router := gin.Default()

	// 配置API
	router.POST("/config/dedup", func(c *gin.Context) {
		var req struct {
			Enabled bool `json:"enabled"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}

		dedupManager.EnableDedup(req.Enabled)
		c.JSON(200, gin.H{"status": "success"})
	})

	router.POST("/config/event", func(c *gin.Context) {
		var req struct {
			EventType EventType `json:"event_type"`
			Enabled   bool      `json:"enabled"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}

		dedupManager.EnableEvent(req.EventType, req.Enabled)
		c.JSON(200, gin.H{"status": "success"})
	})

	router.GET("/stats", func(c *gin.Context) {
		c.JSON(200, stats.GetStats())
	})

	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "healthy"})
	})

	fmt.Println("API服务器启动在:20002")
	router.Run(":20002")
}