package shield360

import (
	"context"
	"testing"

	"github.com/ThinkfleetAI/shield360-go/rasp"
)

// SHIELD: Config.Rasp turns runtime protection on through Init.
func TestInitTurnsOnRasp(t *testing.T) {
	t.Setenv("SHIELD360_RASP", "")
	t.Setenv("SHIELD360_URL", "")
	t.Setenv("SHIELD360_API_KEY", "")
	err := Init(Config{
		ApplicationName: "orders-api",
		DisableTracing:  true,
		DisableMetrics:  true,
		Rasp:            &rasp.Options{Mode: rasp.ModeBlock},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = Shutdown(context.Background())
		rasp.Init(nil, rasp.InitContext{})
	}()
	if !rasp.Active() || rasp.ModeFor(rasp.SQLInjection) != rasp.ModeBlock || rasp.ApplicationName() != "orders-api" {
		t.Errorf("active=%v mode=%s app=%s", rasp.Active(), rasp.ModeFor(rasp.SQLInjection), rasp.ApplicationName())
	}
}
