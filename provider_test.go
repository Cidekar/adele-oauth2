package oauth

import (
	"os"
	"testing"

	adele "github.com/cidekar/adele-framework"
	"github.com/cidekar/adele-framework/database"
	"github.com/cidekar/adele-framework/mux"
	"github.com/cidekar/adele-framework/render"
	"github.com/cidekar/adele-framework/session"
	"github.com/joho/godotenv"
)

// TestServiceProvider_ServiceReturnsNilBeforeRegister verifies that a freshly
// constructed ServiceProvider has no underlying *api.Service yet.
func TestServiceProvider_ServiceReturnsNilBeforeRegister(t *testing.T) {
	var p ServiceProvider
	if got := p.Service(); got != nil {
		t.Fatalf("expected Service() to return nil before Register, got %v", got)
	}
}

// TestServiceProvider_ServiceReturnsNonNilAfterRegister builds a minimal
// *adele.Adele inline (mirroring api/setup_test.go) and asserts that
// Service() returns a non-nil pointer once Register has succeeded. The test
// skips cleanly when no Postgres is reachable so it is safe to run in CI
// environments without a database.
func TestServiceProvider_ServiceReturnsNonNilAfterRegister(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Skipf("integration test requires working directory: %v", err)
	}

	// Best-effort load of the api package's test env so DATABASE_TYPE etc. are
	// populated when running locally. Missing file is not fatal.
	_ = godotenv.Load(cwd + "/api/testdata/.test.env")

	if os.Getenv("DATABASE_TYPE") == "" {
		t.Skip("integration test requires DATABASE_TYPE env var")
	}

	dsn := &database.DataSourceName{
		Host:         "localhost",
		Port:         "5432",
		User:         "postgres",
		Password:     "password",
		DatabaseName: "test",
		SslMode:      "disable",
	}
	db, err := database.OpenDB(os.Getenv("DATABASE_TYPE"), dsn)
	if err != nil {
		t.Skipf("integration test requires Postgres: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Skipf("integration test requires Postgres: %v", err)
	}

	var ade adele.Adele
	ade.DB = &database.Database{
		DataType: os.Getenv("DATABASE_TYPE"),
		Pool:     db,
	}
	ade.Routes = mux.NewRouter()
	sess := session.Session{}
	ade.Session = sess.InitSession()
	ade.Render = &render.Render{}

	var p ServiceProvider
	if err := p.Register(&ade); err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if p.Service() == nil {
		t.Fatalf("expected Service() to return non-nil after Register")
	}
}
