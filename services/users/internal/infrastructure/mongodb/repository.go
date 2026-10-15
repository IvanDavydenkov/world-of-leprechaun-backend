package mongodb

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
	"leprechaun/users/internal/application"
	"leprechaun/users/internal/domain"
)

type Repository struct{ collection *mongo.Collection }

var _ application.Repository = (*Repository)(nil)
var _ application.DirectoryRepository = (*Repository)(nil)

func (r *Repository) FindByID(ctx context.Context, id string) (domain.User, error) {
	var stored document
	err := r.collection.FindOne(ctx, bson.D{{Key: "_id", Value: id}}).Decode(&stored)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return domain.User{}, application.ErrNotFound
	}
	if err != nil {
		return domain.User{}, fmt.Errorf("find user: %w", err)
	}
	return stored.entity(), nil
}

func (d document) entity() domain.User {
	// Role is deliberately omitted: application derives it from current configuration.
	return domain.User{ID: d.ID, YandexID: d.YandexID, DisplayName: d.DisplayName, CreatedAt: d.CreatedAt}
}

func (r *Repository) List(ctx context.Context, after string, limit int) ([]domain.User, error) {
	if limit < 1 || limit > 100 {
		return nil, errors.New("invalid user page size")
	}
	filter := bson.D{}
	if after != "" {
		filter = bson.D{{Key: "_id", Value: bson.D{{Key: "$gt", Value: after}}}}
	}
	cursor, err := r.collection.Find(ctx, filter, options.Find().SetSort(bson.D{{Key: "_id", Value: 1}}).SetLimit(int64(limit)))
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer cursor.Close(ctx)
	users := make([]domain.User, 0)
	for cursor.Next(ctx) {
		var stored document
		if err := cursor.Decode(&stored); err != nil {
			return nil, err
		}
		users = append(users, stored.entity())
	}
	return users, cursor.Err()
}

func Open(ctx context.Context, uri, database string) (*mongo.Client, *Repository, error) {
	client, err := mongo.Connect(options.Client().ApplyURI(uri).SetServerSelectionTimeout(5 * time.Second).SetConnectTimeout(5 * time.Second))
	if err != nil {
		return nil, nil, errors.New("invalid MongoDB connection configuration")
	}
	fail := func() (*mongo.Client, *Repository, error) {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = client.Disconnect(cleanup)
		return nil, nil, errors.New("MongoDB initialization failed; check connection, credentials and indexes")
	}
	if err := client.Ping(ctx, readpref.Primary()); err != nil {
		return fail()
	}
	repository := &Repository{collection: client.Database(database).Collection("users")}
	_, err = repository.collection.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "yandex_id", Value: 1}}, Options: options.Index().SetUnique(true),
	})
	if err != nil {
		return fail()
	}
	return client, repository, nil
}

type document struct {
	ID          string      `bson:"_id"`
	YandexID    string      `bson:"yandex_id"`
	DisplayName string      `bson:"display_name"`
	Role        domain.Role `bson:"role"`
	CreatedAt   time.Time   `bson:"created_at"`
}

func (r *Repository) FindOrCreate(ctx context.Context, user domain.User) (domain.User, error) {
	filter := bson.D{{Key: "yandex_id", Value: user.YandexID}}
	insert := document{user.ID, user.YandexID, user.DisplayName, user.Role, user.CreatedAt}
	var stored document
	err := r.collection.FindOneAndUpdate(ctx, filter,
		bson.D{{Key: "$setOnInsert", Value: insert}},
		options.FindOneAndUpdate().SetUpsert(true).SetReturnDocument(options.After)).Decode(&stored)
	// Concurrent initial sign-ins can race on the unique index; read the winner.
	if mongo.IsDuplicateKeyError(err) {
		err = r.collection.FindOne(ctx, filter).Decode(&stored)
	}
	if err != nil {
		return domain.User{}, fmt.Errorf("persist user: %w", err)
	}
	return domain.User{ID: stored.ID, YandexID: stored.YandexID, DisplayName: stored.DisplayName, Role: stored.Role, CreatedAt: stored.CreatedAt}, nil
}
