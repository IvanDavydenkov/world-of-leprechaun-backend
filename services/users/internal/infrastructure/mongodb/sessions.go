package mongodb

import (
	"context"
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"leprechaun/users/internal/application"
)

type Sessions struct{ collection *mongo.Collection }

var _ application.SessionStore = (*Sessions)(nil)

func OpenSessions(ctx context.Context, database *mongo.Database) (*Sessions, error) {
	sessions := &Sessions{collection: database.Collection("auth_sessions")}
	_, err := sessions.collection.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "expires_at", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0),
	})
	return sessions, err
}

type sessionDocument struct {
	ID        string    `bson:"_id"`
	Kind      string    `bson:"kind"`
	UserID    string    `bson:"user_id,omitempty"`
	Verifier  string    `bson:"verifier,omitempty"`
	ExpiresAt time.Time `bson:"expires_at"`
}

func (s *Sessions) SaveState(ctx context.Context, hash, verifier string, expiry time.Time) error {
	_, err := s.collection.InsertOne(ctx, sessionDocument{ID: "state:" + hash, Kind: "state", Verifier: verifier, ExpiresAt: expiry})
	return err
}
func (s *Sessions) ConsumeState(ctx context.Context, hash string, now time.Time) (string, error) {
	var stored sessionDocument
	err := s.collection.FindOneAndDelete(ctx, bson.D{{Key: "_id", Value: "state:" + hash}, {Key: "kind", Value: "state"}, {Key: "expires_at", Value: bson.D{{Key: "$gt", Value: now}}}}).Decode(&stored)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return "", application.ErrUnauthenticated
	}
	return stored.Verifier, err
}
func (s *Sessions) SaveSession(ctx context.Context, hash, userID string, expiry time.Time) error {
	_, err := s.collection.InsertOne(ctx, sessionDocument{ID: "session:" + hash, Kind: "session", UserID: userID, ExpiresAt: expiry})
	return err
}
func (s *Sessions) SessionUser(ctx context.Context, hash string, now time.Time) (string, error) {
	var stored sessionDocument
	err := s.collection.FindOne(ctx, bson.D{{Key: "_id", Value: "session:" + hash}, {Key: "kind", Value: "session"}, {Key: "expires_at", Value: bson.D{{Key: "$gt", Value: now}}}}).Decode(&stored)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return "", application.ErrUnauthenticated
	}
	return stored.UserID, err
}
func (s *Sessions) DeleteSession(ctx context.Context, hash string) error {
	_, err := s.collection.DeleteOne(ctx, bson.D{{Key: "_id", Value: "session:" + hash}, {Key: "kind", Value: "session"}})
	return err
}
