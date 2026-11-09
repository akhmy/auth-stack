package grpc

import (
	"context"

	"google.golang.org/grpc"
)

func GracefulStop(ctx context.Context, srv *grpc.Server) bool {
	stopped := make(chan struct{})

	go func() {
		srv.GracefulStop()
		close(stopped)
	}()

	select {
	case <-stopped:
		return true
	case <-ctx.Done():
		srv.Stop()
		<-stopped

		return false
	}
}
