package etcd

import (
	"context"
	"testing"
	"time"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/models"
	. "github.com/smartystreets/goconvey/convey"
	"go.etcd.io/etcd/clientv3"
)

var (
	endpoints = []string{"http://127.0.0.1:2379"}
)

func newEtcdStore(namespace ...string) (oauth2.TokenStore, error) {
	cnf := clientv3.Config{
		Endpoints: endpoints,
	}
	return NewEtcdStore(cnf, namespace...)
}

func TestTokenStore(t *testing.T) {
	Convey("Test etcd token store", t, func() {
		store, err := newEtcdStore()
		So(err, ShouldBeNil)
		ctx := context.Background()

		Convey("Test authorization code store", func() {
			info := &models.Token{
				ClientID:      "1",
				UserID:        "1_1",
				RedirectURI:   "http://localhost/",
				Scope:         "all",
				Code:          "11_11_11",
				CodeCreateAt:  time.Now(),
				CodeExpiresIn: time.Second * 5,
			}
			err := store.Create(ctx, info)
			So(err, ShouldBeNil)

			cinfo, err := store.GetByCode(ctx, info.Code)
			So(err, ShouldBeNil)
			So(cinfo.GetUserID(), ShouldEqual, info.UserID)

			err = store.RemoveByCode(ctx, info.Code)
			So(err, ShouldBeNil)

			cinfo, err = store.GetByCode(ctx, info.Code)
			So(err, ShouldBeNil)
			So(cinfo, ShouldBeNil)
		})

		Convey("Test access token store", func() {
			info := &models.Token{
				ClientID:        "1",
				UserID:          "1_1",
				RedirectURI:     "http://localhost/",
				Scope:           "all",
				Access:          "1_1_1",
				AccessCreateAt:  time.Now(),
				AccessExpiresIn: time.Second * 5,
			}
			err := store.Create(ctx, info)
			So(err, ShouldBeNil)

			ainfo, err := store.GetByAccess(ctx, info.GetAccess())
			So(err, ShouldBeNil)
			So(ainfo.GetUserID(), ShouldEqual, info.GetUserID())

			err = store.RemoveByAccess(ctx, info.GetAccess())
			So(err, ShouldBeNil)

			ainfo, err = store.GetByAccess(ctx, info.GetAccess())
			So(err, ShouldBeNil)
			So(ainfo, ShouldBeNil)
		})

		Convey("Test refresh token store", func() {
			info := &models.Token{
				ClientID:         "1",
				UserID:           "1_2",
				RedirectURI:      "http://localhost/",
				Scope:            "all",
				Access:           "1_2_1",
				AccessCreateAt:   time.Now(),
				AccessExpiresIn:  time.Second * 5,
				Refresh:          "1_2_2",
				RefreshCreateAt:  time.Now(),
				RefreshExpiresIn: time.Second * 15,
			}
			err := store.Create(ctx, info)
			So(err, ShouldBeNil)

			rinfo, err := store.GetByRefresh(ctx, info.GetRefresh())
			So(err, ShouldBeNil)
			So(rinfo.GetUserID(), ShouldEqual, info.GetUserID())

			err = store.RemoveByRefresh(ctx, info.GetRefresh())
			So(err, ShouldBeNil)

			rinfo, err = store.GetByRefresh(ctx, info.GetRefresh())
			So(err, ShouldBeNil)
			So(rinfo, ShouldBeNil)
		})
	})
}

func TestTokenStoreWithKeyNamespace(t *testing.T) {
	Convey("Test etcd token store", t, func() {
		cnf := clientv3.Config{
			Endpoints: endpoints,
		}
		store, err := NewEtcdStore(cnf, "test:")
		So(err, ShouldBeNil)
		ctx := context.Background()

		Convey("Test authorization code store", func() {
			info := &models.Token{
				ClientID:      "1",
				UserID:        "1_1",
				RedirectURI:   "http://localhost/",
				Scope:         "all",
				Code:          "11_11_11",
				CodeCreateAt:  time.Now(),
				CodeExpiresIn: time.Second * 5,
			}
			err := store.Create(ctx, info)
			So(err, ShouldBeNil)

			cinfo, err := store.GetByCode(ctx, info.Code)
			So(err, ShouldBeNil)
			So(cinfo.GetUserID(), ShouldEqual, info.UserID)

			err = store.RemoveByCode(ctx, info.Code)
			So(err, ShouldBeNil)

			cinfo, err = store.GetByCode(ctx, info.Code)
			So(err, ShouldBeNil)
			So(cinfo, ShouldBeNil)
		})

		Convey("Test access token store", func() {
			info := &models.Token{
				ClientID:        "1",
				UserID:          "1_1",
				RedirectURI:     "http://localhost/",
				Scope:           "all",
				Access:          "1_1_1",
				AccessCreateAt:  time.Now(),
				AccessExpiresIn: time.Second * 5,
			}
			err := store.Create(ctx, info)
			So(err, ShouldBeNil)

			ainfo, err := store.GetByAccess(ctx, info.GetAccess())
			So(err, ShouldBeNil)
			So(ainfo.GetUserID(), ShouldEqual, info.GetUserID())

			err = store.RemoveByAccess(ctx, info.GetAccess())
			So(err, ShouldBeNil)

			ainfo, err = store.GetByAccess(ctx, info.GetAccess())
			So(err, ShouldBeNil)
			So(ainfo, ShouldBeNil)
		})

		Convey("Test refresh token store", func() {
			info := &models.Token{
				ClientID:         "1",
				UserID:           "1_2",
				RedirectURI:      "http://localhost/",
				Scope:            "all",
				Access:           "1_2_1",
				AccessCreateAt:   time.Now(),
				AccessExpiresIn:  time.Second * 5,
				Refresh:          "1_2_2",
				RefreshCreateAt:  time.Now(),
				RefreshExpiresIn: time.Second * 15,
			}
			err := store.Create(ctx, info)
			So(err, ShouldBeNil)

			rinfo, err := store.GetByRefresh(ctx, info.GetRefresh())
			So(err, ShouldBeNil)
			So(rinfo.GetUserID(), ShouldEqual, info.GetUserID())

			err = store.RemoveByRefresh(ctx, info.GetRefresh())
			So(err, ShouldBeNil)

			rinfo, err = store.GetByRefresh(ctx, info.GetRefresh())
			So(err, ShouldBeNil)
			So(rinfo, ShouldBeNil)
		})
	})
}
