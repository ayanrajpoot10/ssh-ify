package ssh

import (
	"io"
	"sync"
)

const (
	// SSHBufferPoolSize is the size of each buffer in the SSH pool (32KB)
	// Optimized for SSH channel data transfer
	SSHBufferPoolSize = 32 * 1024
)

// sshBufferPool is a pool of reusable byte slices for SSH I/O operations
var sshBufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, SSHBufferPoolSize)
		return &buf
	},
}

// getSSHBuffer retrieves a buffer from the SSH pool
func getSSHBuffer() *[]byte {
	return sshBufferPool.Get().(*[]byte)
}

// putSSHBuffer returns a buffer to the SSH pool for reuse
func putSSHBuffer(buf *[]byte) {
	sshBufferPool.Put(buf)
}

// CopyWithSSHBuffer performs buffered copying between src and dst using a pooled buffer
// optimized for SSH channel operations. This reduces memory allocations and GC pressure
// during high-frequency port forwarding operations.
//
// Parameters:
//   - dst: The destination writer
//   - src: The source reader
//
// Returns:
//   - int64: The number of bytes copied
//   - error: Any error that occurred during copying
func CopyWithSSHBuffer(dst io.Writer, src io.Reader) (int64, error) {
	buf := getSSHBuffer()
	defer putSSHBuffer(buf)
	return io.CopyBuffer(dst, src, *buf)
}
