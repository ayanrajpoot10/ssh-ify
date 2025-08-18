package tunnel

import (
	"io"
	"sync"
)

const (
	// BufferPoolSize is the size of each buffer in the pool (32KB)
	BufferPoolSize = 32 * 1024
)

// bufferPool is a pool of reusable byte slices for I/O operations
var bufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, BufferPoolSize)
		return &buf
	},
}

// getBuffer retrieves a buffer from the pool
func getBuffer() *[]byte {
	return bufferPool.Get().(*[]byte)
}

// putBuffer returns a buffer to the pool for reuse
func putBuffer(buf *[]byte) {
	bufferPool.Put(buf)
}

// CopyWithBuffer performs buffered copying between src and dst using a pooled buffer.
// It's more efficient than io.Copy for high-frequency operations as it reuses buffers
// and reduces garbage collection pressure.
//
// Parameters:
//   - dst: The destination writer
//   - src: The source reader
//
// Returns:
//   - int64: The number of bytes copied
//   - error: Any error that occurred during copying
func CopyWithBuffer(dst io.Writer, src io.Reader) (int64, error) {
	buf := getBuffer()
	defer putBuffer(buf)
	return io.CopyBuffer(dst, src, *buf)
}
