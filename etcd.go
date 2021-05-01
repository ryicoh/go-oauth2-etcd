package etcd

import (
	"context"
	"fmt"
	"time"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/google/uuid"
	jsoniter "github.com/json-iterator/go"
	"go.etcd.io/etcd/clientv3"
)

var (
	jsonMarshal   = jsoniter.Marshal
	jsonUnmarshal = jsoniter.Unmarshal
)

// NewEtcdStore create an instance of a etcd store
func NewEtcdStore(opts clientv3.Config, keyNamespace ...string) (*TokenStore, error) {
	cli, err := clientv3.New(opts)
	if err != nil {
		return nil, err
	}

	return NewEtcdStoreWithCli(cli, keyNamespace...), nil
}

// NewEtcdStoreWithCli create an instance of a etcd store
func NewEtcdStoreWithCli(cli *clientv3.Client, keyNamespace ...string) *TokenStore {
	store := &TokenStore{cli: cli}

	if len(keyNamespace) > 0 {
		store.ns = keyNamespace[0]
	}
	return store
}

// TokenStore etcd token store
type TokenStore struct {
	cli *clientv3.Client
	ns  string
}

// Close close the store
func (s *TokenStore) Close() error {
	return s.cli.Close()
}

func (s *TokenStore) wrapperKey(key string) string {
	return fmt.Sprintf("%s%s", s.ns, key)
}

// remove
func (s *TokenStore) remove(ctx context.Context, key string) error {
	_, err := s.cli.Delete(ctx, s.wrapperKey(key))
	if err != nil {
		return err
	}
	return nil
}

func (s *TokenStore) removeToken(ctx context.Context, tokenString string, isRefresh bool) error {
	basicID, err := s.getBasicID(ctx, tokenString)
	if err != nil {
		return err
	} else if basicID == "" {
		return nil
	}

	if err := s.remove(ctx, tokenString); err != nil {
		return err
	}

	token, err := s.getToken(ctx, basicID)
	if err != nil {
		return err
	} else if token == nil {
		return nil
	}

	checkToken := token.GetRefresh()
	if isRefresh {
		checkToken = token.GetAccess()
	}
	if checkToken == "" {
		return nil
	}

	res, err := s.cli.Get(ctx, s.wrapperKey(checkToken))
	if err != nil {
		return err
	} else if res.Count == 0 {
		if err := s.remove(ctx, basicID); err != nil {
			return err
		}
	}

	return nil
}

func (s *TokenStore) parseToken(res *clientv3.GetResponse) (oauth2.TokenInfo, error) {
	if res.Count == 0 {
		return nil, nil
	}

	var token models.Token
	if err := jsonUnmarshal(res.Kvs[0].Value, &token); err != nil {
		return nil, err
	}
	return &token, nil
}

func (s *TokenStore) getToken(ctx context.Context, key string) (oauth2.TokenInfo, error) {
	result, err := s.cli.Get(ctx, s.wrapperKey(key))
	if err != nil {
		return nil, err
	}
	return s.parseToken(result)
}

func (s *TokenStore) parseBasicID(res *clientv3.GetResponse) (string, error) {
	if res.Count == 0 {
		return "", nil
	}

	return string(res.Kvs[0].Value), nil
}

func (s *TokenStore) getBasicID(ctx context.Context, token string) (string, error) {
	result, err := s.cli.Get(ctx, s.wrapperKey(token))
	if err != nil {
		return "", err
	}
	return s.parseBasicID(result)
}

// Create Create and store the new token information
func (s *TokenStore) Create(ctx context.Context, info oauth2.TokenInfo) error {
	ct := time.Now()
	jv, err := jsonMarshal(info)
	if err != nil {
		return err
	}

	if code := info.GetCode(); code != "" {
		lease, err := s.cli.Grant(ctx, int64(info.GetCodeExpiresIn()))
		if err != nil {
			return err
		}
		s.cli.Put(ctx, s.wrapperKey(code), string(jv), clientv3.WithLease(lease.ID))
	} else {
		basicID := uuid.Must(uuid.NewRandom()).String()
		aexp := info.GetAccessExpiresIn()
		rexp := aexp

		ops := make([]clientv3.Op, 0, 3)
		txn := s.cli.Txn(ctx)
		aexpLease, err := s.cli.Grant(ctx, int64(aexp))
		if err != nil {
			return err
		}
		rexpLease, err := s.cli.Grant(ctx, int64(rexp))
		if err != nil {
			return err
		}

		if refresh := info.GetRefresh(); refresh != "" {
			rexp = info.GetRefreshCreateAt().Add(info.GetRefreshExpiresIn()).Sub(ct)
			if aexp.Seconds() > rexp.Seconds() {
				aexp = rexp
			}
			ops = append(
				ops,
				clientv3.OpPut(s.wrapperKey(refresh), basicID, clientv3.WithLease(rexpLease.ID)),
			)
		}
		ops = append(ops,
			clientv3.OpPut(s.wrapperKey(info.GetAccess()), basicID, clientv3.WithLease(aexpLease.ID)),
			clientv3.OpPut(s.wrapperKey(basicID), string(jv)),
		)
		if _, err = txn.Then(ops...).Commit(); err != nil {
			return err
		}
	}

	return nil
}

// RemoveByCode Use the authorization code to delete the token information
func (s *TokenStore) RemoveByCode(ctx context.Context, code string) error {
	return s.remove(ctx, code)
}

// RemoveByAccess Use the access token to delete the token information
func (s *TokenStore) RemoveByAccess(ctx context.Context, access string) error {
	return s.removeToken(ctx, access, false)
}

// RemoveByRefresh Use the refresh token to delete the token information
func (s *TokenStore) RemoveByRefresh(ctx context.Context, refresh string) error {
	return s.removeToken(ctx, refresh, true)
}

// GetByCode Use the authorization code for token information data
func (s *TokenStore) GetByCode(ctx context.Context, code string) (oauth2.TokenInfo, error) {
	return s.getToken(ctx, code)
}

// GetByAccess Use the access token for token information data
func (s *TokenStore) GetByAccess(ctx context.Context, access string) (oauth2.TokenInfo, error) {
	basicID, err := s.getBasicID(ctx, access)
	if err != nil || basicID == "" {
		return nil, err
	}
	return s.getToken(ctx, basicID)
}

// GetByRefresh Use the refresh token for token information data
func (s *TokenStore) GetByRefresh(ctx context.Context, refresh string) (oauth2.TokenInfo, error) {
	basicID, err := s.getBasicID(ctx, refresh)
	if err != nil || basicID == "" {
		return nil, err
	}
	return s.getToken(ctx, basicID)
}
