package mongodb

import (
	"context"
	"errors"
	"leprechaun/vpn-configs/internal/application"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"leprechaun/vpn-configs/internal/infrastructure/vault"
)

type FileStore struct{ collection *mongo.Collection }

var _ vault.Store = (*FileStore)(nil)

func NewFileStore(database *mongo.Database) *FileStore {
	return &FileStore{collection: database.Collection("config_files")}
}

func (s *FileStore) Insert(ctx context.Context, id string, blob vault.Blob) (bool, error) {
	_, err := s.collection.InsertOne(ctx, struct {
		ID   string     `bson:"_id"`
		Blob vault.Blob `bson:"blob"`
	}{ID: id, Blob: blob})
	if mongo.IsDuplicateKeyError(err) {
		return false, nil
	}
	return err == nil, err
}

func (s *FileStore) Load(ctx context.Context, id string) (vault.Blob, error) {
	var stored struct {
		Blob vault.Blob `bson:"blob"`
	}
	err := s.collection.FindOne(ctx, bson.D{{Key: "_id", Value: id}}).Decode(&stored)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return vault.Blob{}, application.ErrNotFound
	}
	return stored.Blob, err
}
