package application

import (
	"context"
	"time"
)

type PendingQueue interface {
	PendingOwners(context.Context, int64) ([]string, error)
}

type pagedPendingQueue interface{PendingOwnersAfter(context.Context,string,int64)([]string,error)}

func (m *Manager) RunWorker(ctx context.Context, queue PendingQueue) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	after:=""
	for {
		var owners []string;var err error
		if paged,ok:=queue.(pagedPendingQueue);ok{owners,err=paged.PendingOwnersAfter(ctx,after,100)}else{owners,err=queue.PendingOwners(ctx,100)}
		if len(owners)==100{after=owners[len(owners)-1]}else{after=""}
		if err == nil {
			for _, owner := range owners {
				for step := 0; step < 100; step++ {
					if ctx.Err() != nil {
						return
					}
					worked, _ := m.ProcessNext(ctx, owner)
					if !worked {
						break
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
