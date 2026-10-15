package mongodb

import (
	"context"
	"errors"
	"fmt"
	"go.mongodb.org/mongo-driver/v2/bson"
	"leprechaun/users/internal/application"
	"leprechaun/users/internal/domain"
	"os"
	"sync"
	"testing"
	"time"
)

func TestRepositoryIntegration(t *testing.T) {
	uri := os.Getenv("MONGO_TEST_URI")
	if uri == "" {
		t.Skip("set MONGO_TEST_URI to a disposable MongoDB with database creation permissions")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	database := fmt.Sprintf("leprechaun_test_users_%d", time.Now().UnixNano())
	client, repository, err := Open(ctx, uri, database)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		if err := client.Database(database).Drop(cleanup); err != nil {
			t.Error(err)
		}
		if err := client.Disconnect(cleanup); err != nil {
			t.Error(err)
		}
	}()
	var wg sync.WaitGroup
	results := make(chan domain.User, 8)
	failures := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			user, err := repository.FindOrCreate(ctx, domain.User{ID: fmt.Sprint(i), YandexID: "same-identity", Role: domain.RoleUser, CreatedAt: time.Now().UTC()})
			if err != nil {
				failures <- err
				return
			}
			results <- user
		}(i)
	}
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	if t.Failed() {
		return
	}
	id := ""
	for user := range results {
		if id == "" {
			id = user.ID
		}
		if user.ID != id {
			t.Fatal("concurrent sign-ins returned different users")
		}
	}
	count, err := repository.collection.CountDocuments(ctx, bson.D{})
	if err != nil || count != 1 {
		t.Fatalf("count=%d err=%v", count, err)
	}
	_, err = repository.collection.UpdateOne(ctx, bson.D{{Key: "_id", Value: id}}, bson.D{{Key: "$set", Value: bson.D{{Key: "role", Value: domain.RoleAdmin}}}})
	if err != nil {
		t.Fatal(err)
	}
	user, err := repository.FindOrCreate(ctx, domain.User{ID: "new-id", YandexID: "same-identity", Role: domain.RoleUser})
	if err != nil || user.ID != id || user.Role != domain.RoleAdmin {
		t.Fatalf("existing user changed: %+v err=%v", user, err)
	}
	sessions, err := OpenSessions(ctx, client.Database(database))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err = sessions.SaveState(ctx, "state-hash", "verifier", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if verifier, err := sessions.ConsumeState(ctx, "state-hash", now); err != nil || verifier != "verifier" {
		t.Fatal("state consumption failed", err)
	}
	if _, err = sessions.ConsumeState(ctx, "state-hash", now); !errors.Is(err, application.ErrUnauthenticated) {
		t.Fatal("state replay accepted", err)
	}
	if err = sessions.SaveSession(ctx, "session-hash", id, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if actual, err := sessions.SessionUser(ctx, "session-hash", now); err != nil || actual != id {
		t.Fatal("session missing", err)
	}
	if _, err = sessions.SessionUser(ctx, "session-hash", now.Add(2*time.Minute)); !errors.Is(err, application.ErrUnauthenticated) {
		t.Fatal("expired session accepted before TTL cleanup", err)
	}
	if err = sessions.DeleteSession(ctx, "session-hash"); err != nil {
		t.Fatal(err)
	}
	if _, err = sessions.SessionUser(ctx, "session-hash", now); !errors.Is(err, application.ErrUnauthenticated) {
		t.Fatal("deleted session accepted", err)
	}
}
