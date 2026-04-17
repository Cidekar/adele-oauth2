package api

import (
	"bytes"
	"encoding/base64"
	"strconv"
	"time"

	"github.com/google/uuid"
	up "github.com/upper/db/v4"
)

// hashFromRefreshPlainText recovers the token_hash bytes from the plaintext.
// PlainText is base64.URLEncoding of the hash bytes, so decoding reverses it.
func hashFromRefreshPlainText(plainText string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(plainText)
}

// Generate a string representing the authorization granted to the client by the resource owner.  The string is usually opaque to the client. The token denotes an identifier used to retrieve the authorization information. https://datatracker.ietf.org/doc/html/rfc6749#section-1.5
func (o *Service) GenerateRefreshToken(userID int, AccessTokenID int, clientID int) (*RefreshToken, error) {
	token := &RefreshToken{
		AccessTokenID: AccessTokenID,
		Expires:       time.Now().UTC().Add(o.Config.RefreshTokenTokenTTL),
	}

	buf := bytes.NewBufferString(strconv.Itoa(clientID))
	buf.WriteString(strconv.Itoa(userID))
	buf.WriteString(strconv.FormatInt((time.Now()).UnixNano(), 10))

	uid := uuid.Must(uuid.NewRandom())
	sha := uuid.NewSHA1(uid, buf.Bytes()).String()

	token.Hash = []byte(sha)
	token.PlainText = base64.URLEncoding.EncodeToString([]byte(sha))

	return token, nil
}

// Add a authorization token to the db and return the token id in the response
func (o *Service) InsertRefreshToken(token *RefreshToken) error {

	collection := DB.Collection("refresh_tokens")

	token.CreatedAt = time.Now()
	token.UpdatedAt = time.Now()

	// Do not persist plaintext to DB; keep it in-memory for the HTTP response.
	plain := token.PlainText
	token.PlainText = ""
	_, err := collection.Insert(token)
	token.PlainText = plain
	if err != nil {
		return err
	}

	return nil
}

// Find a refresh token in the db by hashing the plain text value and querying token_hash.
func (o *Service) GetRefreshByToken(plainText string) (*RefreshToken, error) {
	var token RefreshToken

	hash, err := hashFromRefreshPlainText(plainText)
	if err != nil {
		return nil, err
	}

	collection := DB.Collection("refresh_tokens")
	res := collection.Find(up.Cond{"token_hash": hash})
	err = res.One(&token)
	if err != nil {
		if err == up.ErrNoMoreRows {
			return nil, nil
		}
		return nil, err
	}
	return &token, nil
}

// Delete a refresh token from db by deriving its hash from the plain text token.
func (o *Service) DeleteRefreshTokenByToken(plainText string) error {

	hash, err := hashFromRefreshPlainText(plainText)
	if err != nil {
		return err
	}

	collection := DB.Collection("refresh_tokens")
	res := collection.Find(up.Cond{"token_hash": hash})
	err = res.Delete()
	if err != nil {
		return err
	}
	return nil
}
