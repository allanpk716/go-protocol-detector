package pkg

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CSVResult represents a single scan result for CSV output
type CSVResult struct {
	Timestamp    time.Time `json:"timestamp"`
	ScanID       string    `json:"scan_id"`
	Protocol     string    `json:"protocol"`
	Host         string    `json:"host"`
	Port         int       `json:"port"`
	Status       string    `json:"status"`
	ResponseTime string    `json:"response_time"`
	ErrorMessage string    `json:"error_message"`
}

// CSVWriter handles thread-safe CSV file writing with buffering
type CSVWriter struct {
	file    *os.File
	writer  *csv.Writer
	mutex   sync.Mutex
	path    string
	headers []string
	closed  bool
}

// NewCSVWriter creates a new CSV writer for the specified file path
func NewCSVWriter(filePath string) (*CSVWriter, error) {
	// Ensure directory exists
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Open file for writing (append if exists, create if not)
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open CSV file %s: %w", filePath, err)
	}

	// Check if file is empty to determine if we need to write headers
	fileInfo, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to stat CSV file %s: %w", filePath, err)
	}

	writeHeaders := fileInfo.Size() == 0

	writer := &CSVWriter{
		file:    file,
		writer:  csv.NewWriter(file),
		path:    filePath,
		headers: []string{"timestamp", "scan_id", "protocol", "host", "port", "status", "response_time", "error_message"},
		closed:  false,
	}

	// Write headers if file is new
	if writeHeaders {
		if err := writer.writeHeaders(); err != nil {
			file.Close()
			return nil, fmt.Errorf("failed to write CSV headers: %w", err)
		}
	}

	return writer, nil
}

// writeHeaders writes the CSV header row
func (w *CSVWriter) writeHeaders() error {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	if err := w.writer.Write(w.headers); err != nil {
		return fmt.Errorf("failed to write CSV headers: %w", err)
	}

	w.writer.Flush()
	if err := w.writer.Error(); err != nil {
		return fmt.Errorf("CSV flush error after headers: %w", err)
	}

	return nil
}

// WriteResult writes a single scan result to the CSV file
func (w *CSVWriter) WriteResult(result CSVResult) error {
	if w.closed {
		return fmt.Errorf("CSV writer is closed")
	}

	w.mutex.Lock()
	defer w.mutex.Unlock()

	record := []string{
		result.Timestamp.Format("2006-01-02 15:04:05"),
		result.ScanID,
		result.Protocol,
		result.Host,
		fmt.Sprintf("%d", result.Port),
		result.Status,
		result.ResponseTime,
		result.ErrorMessage,
	}

	if err := w.writer.Write(record); err != nil {
		return fmt.Errorf("failed to write CSV record: %w", err)
	}

	return nil
}

// Flush flushes any buffered data to disk
func (w *CSVWriter) Flush() error {
	if w.closed {
		return fmt.Errorf("CSV writer is closed")
	}

	w.mutex.Lock()
	defer w.mutex.Unlock()

	w.writer.Flush()
	return w.writer.Error()
}

// Close closes the CSV writer and flushes remaining data
func (w *CSVWriter) Close() error {
	if w.closed {
		return nil
	}

	w.mutex.Lock()
	defer w.mutex.Unlock()

	w.writer.Flush()
	if err := w.writer.Error(); err != nil {
		w.file.Close()
		return fmt.Errorf("CSV flush error during close: %w", err)
	}

	if err := w.file.Close(); err != nil {
		return fmt.Errorf("failed to close CSV file: %w", err)
	}

	w.closed = true
	return nil
}

// GetPath returns the file path of the CSV writer
func (w *CSVWriter) GetPath() string {
	return w.path
}

// IsClosed returns whether the writer is closed
func (w *CSVWriter) IsClosed() bool {
	return w.closed
}