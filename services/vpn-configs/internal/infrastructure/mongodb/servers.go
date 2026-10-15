package mongodb

import (
	"context"
	"errors"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"leprechaun/vpn-configs/internal/application"
	"leprechaun/vpn-configs/internal/domain"
)

type ServerRepository struct{ collection *mongo.Collection }

func NewServerRepository(db *mongo.Database) *ServerRepository {
	return &ServerRepository{db.Collection("vpn_servers")}
}
func (r *ServerRepository) Create(ctx context.Context, s domain.VPNServer) error {
	_, err := r.collection.InsertOne(ctx, s)
	if mongo.IsDuplicateKeyError(err) {
		return application.ErrConflict
	}
	return err
}
func (r *ServerRepository) Get(ctx context.Context, id string) (domain.VPNServer, error) {
	var s domain.VPNServer
	err := r.collection.FindOne(ctx, bson.M{"_id": id}).Decode(&s)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return s, application.ErrNotFound
	}
	return s, err
}
func (r *ServerRepository) List(ctx context.Context) ([]domain.VPNServer, error) {
	cursor, err := r.collection.Find(ctx, bson.M{}, options.Find().SetSort(bson.M{"_id": 1}))
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	result := make([]domain.VPNServer, 0)
	if err = cursor.All(ctx, &result); err != nil {
		return nil, err
	}
	return result, nil
}
func (r *ServerRepository) Update(ctx context.Context, s domain.VPNServer, revision int64) (bool, error) {
	result, err := r.collection.ReplaceOne(ctx, bson.M{"_id": s.ID, "revision": revision}, s)
	if err != nil {
		return false, err
	}
	return result.MatchedCount == 1, nil
}
