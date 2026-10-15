package mongodb

import (
	"context"
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
)

func Open(ctx context.Context, uri, database string) (*mongo.Client, *ManagedRepository, error) {
	client, err := mongo.Connect(options.Client().ApplyURI(uri).SetServerSelectionTimeout(5 * time.Second).SetConnectTimeout(5 * time.Second))
	if err != nil {
		return nil, nil, errors.New("invalid MongoDB connection configuration")
	}
	fail := func() (*mongo.Client, *ManagedRepository, error) {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = client.Disconnect(cleanup)
		return nil, nil, errors.New("MongoDB initialization failed; check connection, credentials and indexes")
	}
	if err = client.Ping(ctx, readpref.Primary()); err != nil {
		return fail()
	}
	repository := NewManagedRepository(client.Database(database))
	_, err = repository.collection.Indexes().CreateOne(ctx, mongo.IndexModel{Keys: bson.D{{Key: "state.operations.completedat", Value: 1}}})
	if err != nil {
		return fail()
	}
	return client, repository, nil
}
