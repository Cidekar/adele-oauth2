package api

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	up "github.com/upper/db/v4"
)

// Create a new authorization token
func (o *Service) GenerateAuthorizationToken() (*AuthorizationToken, error) {
	token := &AuthorizationToken{
		Expires: time.Now().UTC().Add(o.Config.AuthorizationTokenTTL),
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

// Get a authorization token by hashing the plain text value and querying token_hash.
func (o *Service) GetAuthorizationTokenByToken(plainText string) (*AuthorizationToken, error) {

	collection := DB.Collection("authorization_tokens")

	var token AuthorizationToken
	hash := sha256.Sum256([]byte(plainText))
	res := collection.Find(up.Cond{"token_hash": hash[:]})
	err := res.One(&token)
	if err != nil {
		return nil, err
	}
	return &token, nil
}

// Add a authorization token to the database and return the token id in the response
func (o *Service) InsertAuthorizationToken(token *AuthorizationToken) (*AuthorizationToken, error) {

	collection := DB.Collection("authorization_tokens")

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

// Verify by calculating the code challenge from the received "code_verifier" and comparing it with the previously associated "code_challenge" after first transforming it according to the "code_challenge_method" method specified by the client. The formula for this is BASE64URL-ENCODE(SHA256(ASCII(code_verifier))) == code_challenge, but we will need to replace the "=" for padding as it would be parsed by the URL in the browser and converted to a URL safe encoded character.
func (o *Service) VerifyAuthorizationCode(token AuthorizationToken, codeVerifier string) bool {
	sha := sha256.New()
	sha.Write([]byte(codeVerifier))
	bs := sha.Sum(nil)
	challengeCodeHash := strings.Replace(base64.URLEncoding.EncodeToString([]byte(bs)), "=", "", -1)

	return subtle.ConstantTimeCompare([]byte(token.ChallengeCode), []byte(challengeCodeHash)) == 1
}

// ConsumeAuthorizationToken atomically retrieves and deletes an authorization token.
// Returns the token if found and deleted, nil if already consumed or not found.
func (o *Service) ConsumeAuthorizationToken(plainText string) (*AuthorizationToken, error) {
	hash := sha256.Sum256([]byte(plainText))

	var token AuthorizationToken

	err := DB.Tx(func(sess up.Session) error {
		col := sess.Collection("authorization_tokens")
		res := col.Find(up.Cond{"token_hash": hash[:]})

		if err := res.One(&token); err != nil {
			return err
		}
		return res.Delete()
	})

	if err != nil {
		return nil, err
	}

	return &token, nil
}

// delete a authorization token by id from the database and return an error if necessary
func (o *Service) DeleteAuthorizationToken(id int) error {

	collection := DB.Collection("authorization_tokens")

	res := collection.Find(up.Cond{"id": id})
	err := res.Delete()
	if err != nil {
		return err
	}
	return nil
}
