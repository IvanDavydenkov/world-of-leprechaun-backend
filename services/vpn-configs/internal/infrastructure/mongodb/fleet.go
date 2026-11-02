package mongodb

import (
	"context"
	"crypto/rand"
	"errors"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"leprechaun/vpn-configs/internal/application"
	"leprechaun/vpn-configs/internal/domain"
	"time"
)

type FleetStore struct{ collection *mongo.Collection }

func NewFleetStore(db *mongo.Database) *FleetStore { return &FleetStore{db.Collection("vpn_fleet")} }
func (r *FleetStore) LoadFleet(ctx context.Context) (domain.FleetControl, error) {
	var doc struct{ State domain.FleetControl }
	err := r.collection.FindOne(ctx, bson.M{"_id": "control"}).Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return domain.FleetControl{}, nil
	}
	return doc.State, err
}
func (r *FleetStore) SaveFleet(ctx context.Context, s domain.FleetControl, revision int64) (bool, error) {
	if err := assertLease(ctx); err != nil {
		return false, err
	}
	s.Revision = revision + 1
	doc := struct {
		ID       string `bson:"_id"`
		Revision int64
		State    domain.FleetControl
	}{"control", s.Revision, s}
	encoded, err := bson.Marshal(doc)
	if err != nil {
		return false, err
	}
	if len(encoded) > 14*1024*1024 {
		return false, application.Fault("storage_capacity", application.ErrUnavailable)
	}
	if revision == 0 {
		_, err = r.collection.InsertOne(ctx, doc)
		if mongo.IsDuplicateKeyError(err) {
			return false, nil
		}
		return err == nil, err
	}
	result, err := r.collection.ReplaceOne(ctx, bson.M{"_id": "control", "revision": revision}, doc)
	if err != nil {
		return false, err
	}
	return result.MatchedCount == 1, nil
}
func (r *ManagedRepository) OwnersAfter(ctx context.Context, after string, limit int64) ([]string, error) {
	filter := bson.M{}
	if after != "" {
		filter["_id"] = bson.M{"$gt": after}
	}
	cur, err := r.collection.Find(ctx, filter, options.Find().SetLimit(limit).SetSort(bson.M{"_id": 1}).SetProjection(bson.M{"_id": 1}))
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)
	ids := []string{}
	for cur.Next(ctx) {
		var d struct {
			ID string `bson:"_id"`
		}
		if err = cur.Decode(&d); err != nil {
			return nil, err
		}
		ids = append(ids, d.ID)
	}
	return ids, cur.Err()
}

type leaseContextKey struct{}
type leaseClaim struct {
	guard *Coordinator
	token string
}

func assertLease(ctx context.Context) error {
	claim, _ := ctx.Value(leaseContextKey{}).(*leaseClaim)
	if claim == nil {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	err := claim.guard.collection.FindOne(ctx, bson.M{"_id": "mutations", "token": claim.token, "until": bson.M{"$gt": time.Now().UTC()}}).Err()
	if err != nil {
		return application.Fault("server_busy", application.ErrConflict)
	}
	return nil
}

type Coordinator struct{ collection *mongo.Collection }

func NewCoordinator(db *mongo.Database) *Coordinator { return &Coordinator{db.Collection("vpn_locks")} }
func (g *Coordinator) With(ctx context.Context, fn func(context.Context) error) error {
	if claim, ok := ctx.Value(leaseContextKey{}).(*leaseClaim); ok && claim.guard == g {
		return fn(ctx)
	}
	token := rand.Text()
	now := time.Now().UTC()
	until := now.Add(2 * time.Minute)
	_, err := g.collection.UpdateOne(ctx, bson.M{"_id": "mutations", "$or": bson.A{bson.M{"until": bson.M{"$lte": now}}, bson.M{"until": bson.M{"$exists": false}}}}, bson.M{"$set": bson.M{"token": token, "until": until}}, options.UpdateOne().SetUpsert(true))
	if mongo.IsDuplicateKeyError(err) {
		return application.Fault("server_busy", application.ErrConflict)
	}
	if err != nil {
		return err
	}
	locked, cancel := context.WithCancel(context.WithValue(ctx, leaseContextKey{}, &leaseClaim{g, token}))
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-locked.Done():
				return
			case <-ticker.C:
				now := time.Now().UTC()
				result, e := g.collection.UpdateOne(locked, bson.M{"_id": "mutations", "token": token, "until": bson.M{"$gt": now}}, bson.M{"$set": bson.M{"until": now.Add(2 * time.Minute)}})
				if e != nil || result.MatchedCount != 1 {
					cancel()
					return
				}
			}
		}
	}()
	result := fn(locked)
	leaseErr := locked.Err()
	cancel()
	<-done
	cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	_, _ = g.collection.UpdateOne(cleanup, bson.M{"_id": "mutations", "token": token}, bson.M{"$set": bson.M{"until": time.Now().UTC()}})
	if result == nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if result == nil && leaseErr != nil {
		return leaseErr
	}
	return result
}
