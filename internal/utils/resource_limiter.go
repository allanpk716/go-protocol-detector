package utils

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ResourceLimiter 资源限制器
type ResourceLimiter struct {
	maxConnections    int           // 最大并发连接数
	maxMemoryMB       int           // 最大内存使用(MB)
	currentConnections int           // 当前连接数
	connectionCounter  int64         // 连接计数器（总连接数）
	mu                sync.RWMutex // 互斥锁
	connLimiter       chan struct{} // 连接限制通道
	startTime         time.Time     // 启动时间
}

// NewResourceLimiter 创建新的资源限制器
func NewResourceLimiter(maxConnections, maxMemoryMB int) *ResourceLimiter {
	if maxConnections <= 0 {
		maxConnections = 100 // 默认最大100个并发连接
	}
	if maxMemoryMB <= 0 {
		maxMemoryMB = 512 // 默认最大512MB内存
	}

	rl := &ResourceLimiter{
		maxConnections: maxConnections,
		maxMemoryMB:    maxMemoryMB,
		connLimiter:    make(chan struct{}, maxConnections),
		startTime:      time.Now(),
	}

	return rl
}

// AcquireConnection 获取连接许可
func (rl *ResourceLimiter) AcquireConnection(ctx context.Context) error {
	rl.mu.Lock()
	rl.connectionCounter++
	rl.mu.Unlock()

	// 检查是否超过最大连接数
	select {
	case rl.connLimiter <- struct{}{}:
		rl.mu.Lock()
		rl.currentConnections++
		rl.mu.Unlock()
		return nil
	case <-ctx.Done():
		return fmt.Errorf("connection acquisition timeout: %w", ctx.Err())
	}
}

// ReleaseConnection 释放连接许可
func (rl *ResourceLimiter) ReleaseConnection() {
	rl.mu.Lock()
	if rl.currentConnections > 0 {
		rl.currentConnections--
	}
	rl.mu.Unlock()

	// 从限制通道中移除
	select {
	case <-rl.connLimiter:
	default:
		// 通道已空，无需操作
	}
}

// CheckMemoryUsage 检查内存使用情况（简化版）
func (rl *ResourceLimiter) CheckMemoryUsage() error {
	// 注意：这是一个简化的内存检查实现
	// 在实际应用中，你可能需要使用 runtime.MemStats 来获取更准确的内存使用情况
	rl.mu.RLock()
	currentConn := rl.currentConnections
	rl.mu.RUnlock()

	// 简单估算：每个连接大约使用1MB内存
	estimatedMemoryMB := currentConn
	if estimatedMemoryMB > rl.maxMemoryMB {
		return fmt.Errorf("estimated memory usage %dMB exceeds limit %dMB", estimatedMemoryMB, rl.maxMemoryMB)
	}

	return nil
}

// GetStats 获取资源使用统计
func (rl *ResourceLimiter) GetStats() ResourceStats {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	uptime := time.Since(rl.startTime)

	return ResourceStats{
		MaxConnections:     rl.maxConnections,
		CurrentConnections: rl.currentConnections,
		TotalConnections:   rl.connectionCounter,
		MaxMemoryMB:        rl.maxMemoryMB,
		Uptime:             uptime,
	}
}

// ResourceStats 资源使用统计
type ResourceStats struct {
	MaxConnections     int           `json:"max_connections"`
	CurrentConnections int           `json:"current_connections"`
	TotalConnections   int64         `json:"total_connections"`
	MaxMemoryMB        int           `json:"max_memory_mb"`
	Uptime             time.Duration `json:"uptime"`
}

// String 返回统计信息的字符串表示
func (rs ResourceStats) String() string {
	return fmt.Sprintf("Connections: %d/%d (total: %d), Memory Limit: %dMB, Uptime: %v",
		rs.CurrentConnections, rs.MaxConnections, rs.TotalConnections, rs.MaxMemoryMB, rs.Uptime.Round(time.Second))
}

// ConnectionGuard 连接守卫，用于自动管理连接生命周期
type ConnectionGuard struct {
	limiter *ResourceLimiter
}

// NewConnectionGuard 创建连接守卫
func NewConnectionGuard(limiter *ResourceLimiter) *ConnectionGuard {
	return &ConnectionGuard{limiter: limiter}
}

// Acquire 获取连接许可，返回一个释放函数
func (cg *ConnectionGuard) Acquire(ctx context.Context) (func(), error) {
	if err := cg.limiter.AcquireConnection(ctx); err != nil {
		return nil, err
	}

	// 检查内存使用
	if err := cg.limiter.CheckMemoryUsage(); err != nil {
		cg.limiter.ReleaseConnection()
		return nil, err
	}

	return func() {
		cg.limiter.ReleaseConnection()
	}, nil
}

// RateLimiter 简单的速率限制器
type RateLimiter struct {
	ticker   *time.Ticker
	tokens   chan struct{}
	maxTokens int
}

// NewRateLimiter 创建速率限制器
func NewRateLimiter(requestsPerSecond int) *RateLimiter {
	if requestsPerSecond <= 0 {
		requestsPerSecond = 10 // 默认每秒10个请求
	}

	rl := &RateLimiter{
		ticker:    time.NewTicker(time.Second / time.Duration(requestsPerSecond)),
		tokens:    make(chan struct{}, requestsPerSecond),
		maxTokens: requestsPerSecond,
	}

	// 初始填充tokens
	for i := 0; i < requestsPerSecond; i++ {
		rl.tokens <- struct{}{}
	}

	// 启动定期补充tokens的goroutine
	go func() {
		for range rl.ticker.C {
			select {
			case rl.tokens <- struct{}{}:
			default:
				// tokens已满，无需添加
			}
		}
	}()

	return rl
}

// Wait 等待获取一个token
func (rl *RateLimiter) Wait(ctx context.Context) error {
	select {
	case <-rl.tokens:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("rate limit wait timeout: %w", ctx.Err())
	}
}

// Stop 停止速率限制器
func (rl *RateLimiter) Stop() {
	rl.ticker.Stop()
	close(rl.tokens)
}