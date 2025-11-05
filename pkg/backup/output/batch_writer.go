package output

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/allanpk716/go-protocol-detector/pkg"
)

// BatchWriter handles time-based batch writing of scan results to CSV
type BatchWriter struct {
	csvWriter     *CSVWriter
	scanContext   *pkg.ScanContext
	flushInterval time.Duration
	buffer        []CSVResult
	bufferSize    int
	maxBufferSize int

	// Concurrency control
	mutex   sync.RWMutex
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	started bool
	stopped bool

	// Statistics
	totalWritten   int
	batchesWritten int
	lastFlushTime  time.Time
}

// BatchWriterConfig contains configuration for the batch writer
type BatchWriterConfig struct {
	FlushInterval time.Duration // How often to flush buffered results
	MaxBufferSize int           // Maximum number of results to buffer before forced flush
}

// DefaultBatchWriterConfig returns a default configuration
func DefaultBatchWriterConfig() BatchWriterConfig {
	return BatchWriterConfig{
		FlushInterval: 5 * time.Second,
		MaxBufferSize: 1000,
	}
}

// NewBatchWriter creates a new batch writer with the specified CSV writer and configuration
func NewBatchWriter(csvWriter *CSVWriter, scanContext *pkg.ScanContext, config BatchWriterConfig) *BatchWriter {
	ctx, cancel := context.WithCancel(context.Background())

	return &BatchWriter{
		csvWriter:     csvWriter,
		scanContext:   scanContext,
		flushInterval: config.FlushInterval,
		buffer:        make([]CSVResult, 0, config.MaxBufferSize),
		maxBufferSize: config.MaxBufferSize,
		ctx:           ctx,
		cancel:        cancel,
		lastFlushTime: time.Now(),
	}
}

// Start begins the batch writing process
func (bw *BatchWriter) Start() error {
	bw.mutex.Lock()
	defer bw.mutex.Unlock()

	if bw.started {
		return nil
	}

	bw.started = true
	bw.stopped = false

	bw.wg.Add(1)
	go bw.flushLoop()

	log.Printf("Batch writer started with flush interval: %v, max buffer size: %d",
		bw.flushInterval, bw.maxBufferSize)

	return nil
}

// WriteResult adds a result to the buffer for batch writing
func (bw *BatchWriter) WriteResult(result CSVResult) error {
	if bw.stopped {
		return ErrBatchWriterStopped
	}

	bw.mutex.Lock()
	defer bw.mutex.Unlock()

	bw.buffer = append(bw.buffer, result)
	bw.bufferSize = len(bw.buffer)

	// Force flush if buffer is full
	if bw.bufferSize >= bw.maxBufferSize {
		return bw.flushBuffer()
	}

	return nil
}

// flushLoop runs in a goroutine and flushes the buffer at regular intervals
func (bw *BatchWriter) flushLoop() {
	defer bw.wg.Done()

	ticker := time.NewTicker(bw.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-bw.ctx.Done():
			// Context cancelled, flush remaining data and exit
			bw.flushBuffer()
			return
		case <-ticker.C:
			bw.mutex.Lock()
			if bw.bufferSize > 0 {
				if err := bw.flushBuffer(); err != nil {
					log.Printf("Failed to flush batch: %v", err)
				}
			}
			bw.mutex.Unlock()
		}
	}
}

// flushBuffer writes all buffered results to the CSV file
func (bw *BatchWriter) flushBuffer() error {
	if bw.bufferSize == 0 {
		return nil
	}

	startTime := time.Now()
	errors := make([]error, 0, bw.bufferSize)

	// Write each result to CSV
	for _, result := range bw.buffer {
		if err := bw.csvWriter.WriteResult(result); err != nil {
			errors = append(errors, err)
			log.Printf("Failed to write result %s:%d to CSV: %v",
				result.Host, result.Port, err)
		}
	}

	// Flush the CSV writer to ensure data is written to disk
	if err := bw.csvWriter.Flush(); err != nil {
		errors = append(errors, err)
		log.Printf("Failed to flush CSV writer: %v", err)
	}

	// Update statistics
	bw.totalWritten += bw.bufferSize
	bw.batchesWritten++
	bw.lastFlushTime = time.Now()

	// Clear the buffer
	bw.buffer = bw.buffer[:0]
	bw.bufferSize = 0

	duration := bw.lastFlushTime.Sub(startTime)

	// Log batch statistics
	if len(errors) > 0 {
		log.Printf("Batch flush completed in %v with %d errors (wrote %d results)",
			duration, len(errors), bw.bufferSize)
	} else {
		log.Printf("Batch flush completed in %v (wrote %d results)",
			duration, bw.bufferSize)
	}

	if len(errors) > 0 {
		return ErrBatchWriteFailed
	}

	return nil
}

// Flush forces an immediate flush of all buffered results
func (bw *BatchWriter) Flush() error {
	bw.mutex.Lock()
	defer bw.mutex.Unlock()

	return bw.flushBuffer()
}

// Stop stops the batch writer and flushes any remaining data
func (bw *BatchWriter) Stop() error {
	bw.mutex.Lock()
	defer bw.mutex.Unlock()

	if bw.stopped {
		return nil
	}

	// Cancel the context to stop the flush loop
	bw.cancel()
	bw.stopped = true

	// Wait for the flush loop to finish
	bw.wg.Wait()

	// Flush any remaining data
	if bw.bufferSize > 0 {
		if err := bw.flushBuffer(); err != nil {
			log.Printf("Error during final flush: %v", err)
			return err
		}
	}

	log.Printf("Batch writer stopped. Total written: %d results in %d batches",
		bw.totalWritten, bw.batchesWritten)

	return nil
}

// GetStats returns current statistics about the batch writer
func (bw *BatchWriter) GetStats() BatchWriterStats {
	bw.mutex.RLock()
	defer bw.mutex.RUnlock()

	return BatchWriterStats{
		BufferSize:     bw.bufferSize,
		MaxBufferSize:  bw.maxBufferSize,
		TotalWritten:   bw.totalWritten,
		BatchesWritten: bw.batchesWritten,
		LastFlushTime:  bw.lastFlushTime,
		FlushInterval:  bw.flushInterval,
		IsStarted:      bw.started,
		IsStopped:      bw.stopped,
		TimeSinceFlush: time.Since(bw.lastFlushTime),
	}
}

// BatchWriterStats provides statistics about the batch writer
type BatchWriterStats struct {
	BufferSize     int
	MaxBufferSize  int
	TotalWritten   int
	BatchesWritten int
	LastFlushTime  time.Time
	FlushInterval  time.Duration
	IsStarted      bool
	IsStopped      bool
	TimeSinceFlush time.Duration
}

// Error definitions
var (
	ErrBatchWriterStopped = NewBatchWriterError("batch writer is stopped")
	ErrBatchWriteFailed   = NewBatchWriterError("batch write operation failed")
)

// BatchWriterError represents an error from the batch writer
type BatchWriterError struct {
	message string
}

func NewBatchWriterError(message string) *BatchWriterError {
	return &BatchWriterError{message: message}
}

func (e *BatchWriterError) Error() string {
	return e.message
}
