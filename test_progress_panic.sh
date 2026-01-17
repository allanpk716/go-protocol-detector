#!/bin/bash
# Test progress bar with connection failures
go run cmd/go-protocol-detector/main.go \
  --protocol=ssh \
  --host=192.168.255.1-10 \
  --port=9999 \
  --thread=10
