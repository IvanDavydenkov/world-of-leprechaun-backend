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

// ManagedRepository stores lifecycle state and metadata atomically per owner.
// Owner _id provides indexed isolation; encrypted files are in config_files.
type ManagedRepository struct{ collection *mongo.Collection }

var _ application.StateStore = (*ManagedRepository)(nil)
var _ application.Repository = (*ManagedRepository)(nil)

func NewManagedRepository(database *mongo.Database) *ManagedRepository {
	return &ManagedRepository{collection: database.Collection("config_accounts")}
}

type accountDocument struct {
	ID       string         `bson:"_id"`
	Revision int64          `bson:"revision"`
	State    domain.Account `bson:"state"`
}

func (r *ManagedRepository) Load(ctx context.Context, ownerID string) (domain.Account, error) {
	if ownerID == "" {
		return domain.Account{}, application.ErrInvalid
	}
	var stored accountDocument
	err := r.collection.FindOne(ctx, bson.D{{Key: "_id", Value: ownerID}}).Decode(&stored)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return domain.Account{OwnerID: ownerID}, nil
	}
	if err != nil {
		return domain.Account{}, err
	}
	stored.State.OwnerID, stored.State.Revision = stored.ID, stored.Revision
	return stored.State, nil
}

func (r *ManagedRepository) Save(ctx context.Context, state domain.Account, revision int64) (bool, error) {
	if state.OwnerID == "" || revision < 0 {
		return false, application.ErrInvalid
	}
	state.Revision = revision + 1
	stored := accountDocument{ID: state.OwnerID, Revision: revision + 1, State: state}
	if revision == 0 {
		_, err := r.collection.InsertOne(ctx, stored)
		if mongo.IsDuplicateKeyError(err) {
			return false, nil
		}
		return err == nil, err
	}
	result, err := r.collection.ReplaceOne(ctx, bson.D{{Key: "_id", Value: state.OwnerID}, {Key: "revision", Value: revision}}, stored)
	if err != nil {
		return false, err
	}
	return result.MatchedCount == 1, nil
}

func (r *ManagedRepository) ListByOwner(ctx context.Context, ownerID string) ([]domain.Config, error) {
	if ownerID == "" {
		return nil, application.ErrForbidden
	}
	state, err := r.Load(ctx, ownerID)
	if err != nil {
		return nil, err
	}
	return state.Active(), nil
}

func (r *ManagedRepository) FindByOwner(ctx context.Context, ownerID, configID string) (domain.Config, error) {
	configs, err := r.ListByOwner(ctx, ownerID)
	if err != nil {
		return domain.Config{}, err
	}
	for _, config := range configs {
		if config.ID == configID {
			return config, nil
		}
	}
	return domain.Config{}, application.ErrNotFound
}

// PendingOwners supports recovery after restarts; workers must not expose this API publicly.
func (r *ManagedRepository) PendingOwners(ctx context.Context, limit int64) ([]string, error) {
	if limit < 1 || limit > 100 {
		return nil, application.ErrInvalid
	}
	cursor, err := r.collection.Find(ctx, bson.D{{Key: "state.operations", Value: bson.D{{Key: "$elemMatch", Value: bson.D{{Key: "completedat", Value: nil}}}}}},
		options.Find().SetLimit(limit).SetProjection(bson.D{{Key: "_id", Value: 1}}))
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	owners := make([]string, 0)
	for cursor.Next(ctx) {
		var stored struct {
			ID string `bson:"_id"`
		}
		if err := cursor.Decode(&stored); err != nil {
			return nil, err
		}
		owners = append(owners, stored.ID)
	}
	return owners, cursor.Err()
}
