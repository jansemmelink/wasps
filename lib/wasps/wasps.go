package wasps

import (
	"github.com/go-msvc/errors"
	"github.com/jansemmelink/wasps/lib/db"
	"github.com/stewelarend/logger"
)

var log = logger.New().WithLevel(logger.LevelDebug)

type Wasps interface {
	Add(w Wasp) (Wasp, error)
	Find(filter map[string]interface{}) []Wasp
	Get(id string) *Wasp
}

func New(database db.Database) (Wasps, error) {
	c := database.Collection("wasps")
	if c == nil {
		return nil, errors.Errorf("failed to create database wasps collection")
	}
	w := wasps{
		dbCollection: c,
	}
	return w, nil
}

type wasps struct {
	dbCollection db.Collection
}

func (wasps wasps) Add(newWasp Wasp) (addedWasp Wasp, err error) {
	if newWasp.Validate(); err != nil {
		return Wasp{}, errors.Wrapf(err, "cannot add invalid wasp")
	}

	//todo: check duplicate name

	//insert user into database
	id, err := wasps.dbCollection.Add(newWasp)
	if err != nil {
		return Wasp{}, errors.Wrapf(err, "failed to add wasp")
	}
	newWasp.ID = id
	return newWasp, nil
}

func (wasps wasps) Find(filter map[string]interface{}) []Wasp {
	list, err := wasps.dbCollection.Find(filter, []string{"name"}, 10)
	if err != nil {
		log.Errorf("Failed: %+v", err)
		return nil
	}
	log.Errorf("LIST: %+v", list)
	return nil
}

func (wasps wasps) Get(id string) *Wasp {
	return wasps.dbCollection.Get(id).(*Wasp)
}
