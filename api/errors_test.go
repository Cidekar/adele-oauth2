package api

import (
	"encoding/json"
	"testing"
)

func TestOauth_Errors(t *testing.T) {

	e := NewErrorResponse(ErrInvalidRequest)

	if e.Description != Descriptions[ErrInvalidRequest] {
		t.Error("error description from new error response returned an unexpected value")
	}

	if e.ErrorCode != StatusCodes[ErrInvalidRequest] {
		t.Error("status code from new error response returned an unexpected value")
	}

	if e.Error == Descriptions[ErrInvalidRequest] {
		t.Error("new error response returned an unexpected value")
	}
}

func TestOauth_ErrorResponse_JSONFormat(t *testing.T) {
	err := NewErrorResponse(ErrInvalidClient)
	data, _ := json.Marshal(err)
	var m map[string]interface{}
	json.Unmarshal(data, &m)

	if _, ok := m["error"]; !ok {
		t.Error("missing 'error' key in JSON")
	}
	if _, ok := m["error_description"]; !ok {
		t.Error("missing 'error_description' key in JSON")
	}
	if _, ok := m["error_code"]; ok {
		t.Error("'error_code' should not appear in JSON (tagged json:\"-\")")
	}
	if _, ok := m["description"]; ok {
		t.Error("'description' should not appear in JSON (renamed to error_description)")
	}
}
