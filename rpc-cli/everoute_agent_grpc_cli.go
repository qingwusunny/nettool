package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"google.golang.org/grpc"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Usage: %s <flowID>", os.Args[0])
	}

	flowID, err := strconv.ParseUint(os.Args[1], 10, 64)
	if err != nil {
		log.Fatalf("Invalid flowID: %v", err)
	}

	// 连接 Unix Socket
	conn, err := grpc.Dial(
		"unix:///var/lib/everoute/rpc.sock",
		grpc.WithInsecure(),
		grpc.WithTimeout(5*time.Second),
	)
	if err != nil {
		log.Fatalf("Connection failed: %v", err)
	}
	defer conn.Close()

	// 创建请求
	req := &BridgeIndexRequest{
		FlowID: flowID,
	}

	// 直接使用 grpc 调用
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var resp BridgeIndexResponse
	err = conn.Invoke(ctx, "/everoute_io.pkg.apis.rpc.v1alpha1.Collector/GetBridgeIndexWithFlowID", req, &resp)
	if err != nil {
		log.Fatalf("RPC call failed: %v", err)
	}

	fmt.Printf("Index: %d\n", resp.Index)
}