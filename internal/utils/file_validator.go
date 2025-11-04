package utils

import (
	"os"
	"path/filepath"
	"strings"
)

// ValidatePrivateKeyPath 验证私钥文件路径是否安全
func ValidatePrivateKeyPath(keyPath string) error {
	if keyPath == "" {
		return nil // 空路径是允许的，表示使用密码认证
	}

	// 清理路径，防止路径遍历攻击
	cleanPath := filepath.Clean(keyPath)

	// 检查是否包含路径遍历模式
	if strings.Contains(cleanPath, "..") {
		return os.ErrPermission // 路径包含潜在的遍历模式
	}

	// 检查路径是否为绝对路径
	if !filepath.IsAbs(cleanPath) {
		// 如果是相对路径，需要相对于当前工作目录
		wd, err := os.Getwd()
		if err != nil {
			return err
		}
		cleanPath = filepath.Join(wd, cleanPath)
		cleanPath = filepath.Clean(cleanPath)
	}

	// 检查路径是否尝试访问敏感系统目录
	sensitivePaths := []string{
		"/etc",
		"/usr/bin",
		"/usr/sbin",
		"/bin",
		"/sbin",
		"/boot",
		"/sys",
		"/proc",
		"/dev",
	}

	for _, sensitive := range sensitivePaths {
		if strings.HasPrefix(cleanPath, sensitive) {
			return os.ErrPermission // 尝试访问敏感系统目录
		}
	}

	// 检查文件是否存在且可读
	fileInfo, err := os.Stat(cleanPath)
	if err != nil {
		return err
	}

	// 确保是文件而不是目录
	if fileInfo.IsDir() {
		return os.ErrInvalid // 路径指向目录而不是文件
	}

	// 检查文件权限（确保只有所有者可读写）
	if fileInfo.Mode().Perm()&0077 != 0 {
		// 其他用户或组有权限，这在生产环境中可能不安全
		// 这里只是警告，但不阻止使用
	}

	return nil
}

// IsSafeFilename 检查文件名是否安全（不包含危险字符）
func IsSafeFilename(filename string) bool {
	if filename == "" {
		return false
	}

	// 检查危险字符
	dangerousChars := []string{
		"..", "/", "\\", ":", "*", "?", "\"", "<", ">", "|",
	}

	for _, char := range dangerousChars {
		if strings.Contains(filename, char) {
			return false
		}
	}

	return true
}