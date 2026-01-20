package utils

import (
	"context"
	"testing"
	"time"
)

func TestResourceLimiter_AcquireTimeout(t *testing.T) {
	limiter := NewResourceLimiter(1, 100)

	ctx1 := context.Background()
	err := limiter.AcquireConnection(ctx1)
	if err != nil {
		t.Fatalf("第一次获取不应该失败: %v", err)
	}
	defer limiter.ReleaseConnection()

	ctx2, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	startCount := limiter.GetStats().TotalConnections
	err = limiter.AcquireConnection(ctx2)

	if err == nil {
		t.Error("预期超时错误但获取成功")
	}

	endCount := limiter.GetStats().TotalConnections
	if endCount != startCount {
		t.Errorf("超时时不应递增计数器: 开始=%d, 结束=%d", startCount, endCount)
	}
}

func TestResourceLimiter_AcquireSuccess(t *testing.T) {
	limiter := NewResourceLimiter(10, 100)

	ctx := context.Background()
	startCount := limiter.GetStats().TotalConnections

	err := limiter.AcquireConnection(ctx)
	if err != nil {
		t.Fatalf("获取连接不应该失败: %v", err)
	}

	endCount := limiter.GetStats().TotalConnections
	if endCount != startCount+1 {
		t.Errorf("成功获取后计数器应递增1: 开始=%d, 结束=%d", startCount, endCount)
	}

	limiter.ReleaseConnection()
}
