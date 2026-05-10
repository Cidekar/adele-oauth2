package oauth

import (
	"os"
	"path/filepath"
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
	_ = godotenv.Load(cwd + "/test.env")

	if os.Getenv("DATABASE_TYPE") == "" {
		t.Skip("integration test requires DATABASE_TYPE env var")
	}

	dsn := &database.DataSourceName{
		Host:         os.Getenv("DATABASE_HOST"),
		Port:         os.Getenv("DATABASE_PORT"),
		User:         os.Getenv("DATABASE_USER"),
		Password:     os.Getenv("DATABASE_PASSWORD"),
		DatabaseName: os.Getenv("DATABASE_NAME"),
		SslMode:      os.Getenv("DATABASE_SSL_MODE"),
	}
	db, err := database.OpenDB(os.Getenv("DATABASE_TYPE"), dsn)
	if err != nil {
		t.Skipf("integration test requires Postgres: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Skipf("integration test requires Postgres: %v", err)
	}

	var ade adele.Adele
	// Provide a writable RootPath with a pre-created config/ subdir so that
	// api.loadConfig can seed config/oauth.yml from the embedded template
	// without trying to write to the filesystem root (/config/oauth.yml).
	rootPath := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rootPath, "config"), 0o755); err != nil {
		t.Fatalf("setup tempdir config: %v", err)
	}
	ade.RootPath = rootPath
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
