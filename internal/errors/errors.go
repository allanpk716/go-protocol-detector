package errors

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// ErrorType 错误类型
type ErrorType int

const (
	ErrorTypeNetwork ErrorType = iota
	ErrorTypeValidation
	ErrorTypeTimeout
	ErrorTypeAuthentication
	ErrorTypeResourceLimit
	ErrorTypeFileSystem
	ErrorTypeProtocol
	ErrorTypeUnknown
)

// ScannerError 扫描器自定义错误类型
type ScannerError struct {
	Type    ErrorType
	Message string
	Host    string
	Port    string
	Cause   error
}

// Error 实现error接口
func (e *ScannerError) Error() string {
	if e.Host != "" && e.Port != "" {
		return fmt.Sprintf("[%s] %s (host: %s, port: %s): %v", e.typeString(), e.Message, e.Host, e.Port, e.Cause)
	} else if e.Host != "" {
		return fmt.Sprintf("[%s] %s (host: %s): %v", e.typeString(), e.Message, e.Host, e.Cause)
	}
	return fmt.Sprintf("[%s] %s: %v", e.typeString(), e.Message, e.Cause)
}

// Unwrap 支持errors.Unwrap
func (e *ScannerError) Unwrap() error {
	return e.Cause
}

// typeString 返回错误类型的字符串表示
func (e *ScannerError) typeString() string {
	switch e.Type {
	case ErrorTypeNetwork:
		return "NETWORK"
	case ErrorTypeValidation:
		return "VALIDATION"
	case ErrorTypeTimeout:
		return "TIMEOUT"
	case ErrorTypeAuthentication:
		return "AUTH"
	case ErrorTypeResourceLimit:
		return "RESOURCE"
	case ErrorTypeFileSystem:
		return "FILESYSTEM"
	case ErrorTypeProtocol:
		return "PROTOCOL"
	default:
		return "UNKNOWN"
	}
}

// IsTimeout 检查是否为超时错误
func (e *ScannerError) IsTimeout() bool {
	return e.Type == ErrorTypeTimeout || isNetTimeoutError(e.Cause)
}

// IsNetwork 检查是否为网络错误
func (e *ScannerError) IsNetwork() bool {
	return e.Type == ErrorTypeNetwork || isNetError(e.Cause)
}

// NewScannerError 创建新的扫描器错误
func NewScannerError(errorType ErrorType, message string, cause error) *ScannerError {
	return &ScannerError{
		Type:    errorType,
		Message: message,
		Cause:   cause,
	}
}

// NewNetworkError 创建网络错误
func NewNetworkError(host, port string, message string, cause error) *ScannerError {
	return &ScannerError{
		Type:    ErrorTypeNetwork,
		Message: message,
		Host:    host,
		Port:    port,
		Cause:   cause,
	}
}

// NewValidationError 创建验证错误
func NewValidationError(message string, cause error) *ScannerError {
	return &ScannerError{
		Type:    ErrorTypeValidation,
		Message: message,
		Cause:   cause,
	}
}

// NewTimeoutError 创建超时错误
func NewTimeoutError(host, port string, cause error) *ScannerError {
	return &ScannerError{
		Type:    ErrorTypeTimeout,
		Message: "operation timeout",
		Host:    host,
		Port:    port,
		Cause:   cause,
	}
}

// NewResourceLimitError 创建资源限制错误
func NewResourceLimitError(message string, cause error) *ScannerError {
	return &ScannerError{
		Type:    ErrorTypeResourceLimit,
		Message: message,
		Cause:   cause,
	}
}

// NewProtocolError 创建协议错误
func NewProtocolError(protocol, host, port string, message string, cause error) *ScannerError {
	return &ScannerError{
		Type:    ErrorTypeProtocol,
		Message: fmt.Sprintf("%s: %s", protocol, message),
		Host:    host,
		Port:    port,
		Cause:   cause,
	}
}

// isNetTimeoutError 检查是否为网络超时错误
func isNetTimeoutError(err error) bool {
	if err == nil {
		return false
	}

	// 优先使用类型断言
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}

	// 检查包装的错误
	if unwrapped := errors.Unwrap(err); unwrapped != nil {
		if netErr, ok := unwrapped.(net.Error); ok && netErr.Timeout() {
			return true
		}
	}

	// 字符串匹配仅作为最后的后备手段
	errMsg := err.Error()
	return strings.Contains(errMsg, "timeout") ||
		strings.Contains(errMsg, "deadline") ||
		strings.Contains(errMsg, "timed out")
}

// isNetError 检查是否为网络错误
func isNetError(err error) bool {
	if err == nil {
		return false
	}

	// 优先使用类型断言
	if _, ok := err.(net.Error); ok {
		return true
	}

	// 检查包装的错误
	if unwrapped := errors.Unwrap(err); unwrapped != nil {
		if _, ok := unwrapped.(net.Error); ok {
			return true
		}
	}

	// 字符串匹配仅作为后备
	errMsg := err.Error()
	return strings.Contains(errMsg, "connection") ||
		strings.Contains(errMsg, "network") ||
		strings.Contains(errMsg, "dial") ||
		strings.Contains(errMsg, "refused") ||
		strings.Contains(errMsg, "unreachable")
}

// 移除手动的 contains 函数，使用 strings.Contains 替代
// 此函数已不再需要，因为改用了标准库的 strings.Contains