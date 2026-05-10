package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	up "github.com/upper/db/v4"
	postgresql "github.com/upper/db/v4/adapter/postgresql"
)

// Create a oauth token that is always the same length each time one is generated.
func (o *Service) GenerateOauthToken() (*OauthToken, error) {
	token := &OauthToken{
		Expires: time.Now().UTC().Add(o.Config.OauthTokenTTL),
	}

	randomBytes := make([]byte, 16)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return nil, err
	}

	token.PlainText = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(randomBytes)
	hash := sha256.Sum256([]byte(token.PlainText))
	token.Hash = hash[:]

	return token, nil
}

// Add a token to the db and return the token id in the response
func (o *Service) InsertOauthToken(token *OauthToken) (*OauthToken, error) {

	collection := DB.Collection("tokens")

	token.CreatedAt = time.Now()
	token.UpdatedAt = time.Now()

	// Do not persist plaintext to DB; keep it in-memory for the HTTP response.
	plain := token.PlainText
	token.PlainText = ""
	res, err := collection.Insert(token)
	token.PlainText = plain
	if err != nil {
		return nil, err
	}

	id, err := strconv.Atoi(fmt.Sprintf("%d", res.ID()))
	if err != nil {
		return nil, err
	}

	token.ID = id

	return token, nil
}

func (o *Service) GetOauthToken(id int) (*OauthToken, error) {

	collection := DB.Collection("tokens")

	var token OauthToken
	res := collection.Find(up.Cond{"id": id})
	err := res.One(&token)
	if err != nil {
		return nil, err
	}
	return &token, nil
}

func (o *Service) DeleteOauthToken(id int) error {

	collection := DB.Collection("tokens")
	res := collection.Find(up.Cond{"id": id})
	err := res.Delete()
	if err != nil {
		return err
	}
	return nil
}

// token authentication attached to a http request in the form of bearer token.
func (o *Service) AuthenticateToken(r *http.Request) (bool, *OauthToken, error) {
	token, err := o.GetAuthTokenFromHeader(r)
	if err != nil {
		return false, nil, err
	}

	ok := o.TokenIsExpired(token)
	if !ok {
		return false, nil, errors.New("expired token")
	}

	return true, token, nil
}

// get the token from the db by hashing the plain text value and querying token_hash
func (o *Service) GetByToken(plainText string) (*OauthToken, error) {

	collection := DB.Collection("tokens")

	var token OauthToken

	hash := sha256.Sum256([]byte(plainText))
	// Wrap with postgresql.Bytea so upper/db's toInterfaceArguments takes the
	// driver.Valuer fast path instead of converting []byte -> string (which makes
	// pgx send the bytes as text and Postgres reject them with SQLSTATE 22021).
	res := collection.Find(up.Cond{"token_hash": postgresql.Bytea(hash[:])})
	err := res.One(&token)
	if err != nil {
		return nil, err
	}
	return &token, nil
}

// extract a token from the http request header
func (o *Service) GetAuthTokenFromHeader(r *http.Request) (*OauthToken, error) {
	authorizationHeader := r.Header.Get("Authorization")
	if authorizationHeader == "" {
		return nil, errors.New("no authorization header received")
	}

	headerParts := strings.Split(authorizationHeader, " ")
	if len(headerParts) != 2 || !strings.EqualFold(headerParts[0], "Bearer") {
		return nil, errors.New("invalid authorization header received")
	}

	token := headerParts[1]

	if len(token) != 26 {
		return nil, errors.New("token is wrong size")
	}

	tkn, err := o.GetByToken(token)
	if err != nil {
		return nil, errors.New("no matching token found")
	}

	// Restore plaintext from the inbound bearer header. The DB no longer
	// stores plaintext (only token_hash bytea), so DB lookups return a
	// struct with PlainText == "". Callers that propagate the token to
	// downstream context keys (BearerTokenHandler stamps both typed
	// ContextKeyAccessToken and the legacy "accessToken" string key with
	// token.PlainText) need the plaintext value populated.
	tkn.PlainText = token

	return tkn, nil
}
