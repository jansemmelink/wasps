package db

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

type Database interface {
	Name() string
	Collection(name string) Collection
}

func New(name string) (Database, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		return nil, err
	}

	//Make sure to defer a call to Disconnect after instantiating your client:
	// defer func() {
	// 	if err = client.Disconnect(ctx); err != nil {
	// 		panic(err)
	// 	}
	// }()

	//Calling Connect does not block for server discovery. If you wish to know if a MongoDB server has been found and connected to, use the Ping method:
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err = client.Ping(ctx, readpref.Primary()); err != nil {
		return nil, err
	}

	return database{
		name:          name,
		mongoDatabase: client.Database(name),
	}, nil
}

type database struct {
	name          string
	mongoDatabase *mongo.Database
}

func (db database) Name() string {
	return db.name
}

func (db database) Collection(name string) Collection {
	return collection{
		mongoCollection: db.mongoDatabase.Collection(name),
	}
}
