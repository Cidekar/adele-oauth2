package oauth

import (
	"github.com/cidekar/adele-framework"
	"github.com/cidekar/adele-oauth2/api"
)

type (
	Service       = api.Service
	Configuration = api.Configuration
	Scopes        = api.Scopes
	OauthResponse = api.OauthResponse
	ErrorResponse = api.ErrorResponse
	Client        = api.Client
)

func New(a *adele.Adele) (Service, error) {
	return api.New(a)
}

func NewWithConfig(a *adele.Adele, config Configuration) (Service, error) {
	return api.NewWithConfig(a, config)
}
