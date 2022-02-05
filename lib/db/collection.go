package db

import (
	"context"
	"time"

	"github.com/pkg/errors"
	"github.com/stewelarend/logger"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

var log = logger.New().WithLevel(logger.LevelDebug)

type Collection interface {
	Name() string
	Add(item interface{}) (id string, err error)
	Find(filter map[string]interface{}, sort []string, limit int) ([]interface{}, error)
	Get(id string) interface{}
}

type collection struct {
	name            string
	mongoCollection *mongo.Collection
}

func (c collection) Name() string { return c.name }

func (c collection) Add(item interface{}) (id string, err error) {
	//The Collection instance can then be used to insert documents:
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := c.mongoCollection.InsertOne(ctx, item)
	if err != nil {
		return "", errors.Wrapf(err, "failed to insert %s into database", c.name)
	}
	id = res.InsertedID.(string)
	return id, nil
}

func (c collection) Find(filter map[string]interface{}, sort []string, limit int) ([]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := c.mongoCollection.Find(ctx, filter) //, opts)
	if err != nil {
		return nil, errors.Wrapf(err, "find error")
	}

	log.Debugf("LIST: %+v", res)
	return nil, nil
}

func (c collection) Get(id string) interface{} {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	filter := bson.D{{
		"$and",
		bson.A{
			bson.D{{"id", bson.D{{"$eq", id}}}},
		},
	}}
	res := c.mongoCollection.FindOne(ctx, filter)
	var w interface{}
	if err := res.Decode(&w); err != nil {
		log.Errorf("cannot decode WASP: %+v", err)
		return nil
	}
	return w
}
