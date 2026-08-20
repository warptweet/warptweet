package provisioner

import (
	"bytes"
	"errors"
)

var errProvisionerOutputTruncated = errors.New("provisioner child output exceeded limit")

type limitedBuffer struct {
	buffer *bytes.Buffer
	limit  int
}

func (writer *limitedBuffer) Write(data []byte) (int, error) {
	remaining := writer.limit - writer.buffer.Len()
	if remaining <= 0 {
		return 0, errProvisionerOutputTruncated
	}
	if len(data) > remaining {
		written, _ := writer.buffer.Write(data[:remaining])
		return written, errProvisionerOutputTruncated
	}
	return writer.buffer.Write(data)
}
