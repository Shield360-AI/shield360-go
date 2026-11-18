package rasp

import (
	"context"
	"database/sql"
	"sync"
	"testing"
)

// Enterprise databases through database/sql: stub drivers registered under
// the names the real SQL Server, Oracle and Db2 drivers use, so the dialect
// and the event sink come from the driver name as they would in an app.

var (
	registerEnterprise sync.Once
	enterpriseFakes    = map[string]*fakeDB{}
)

var enterpriseDrivers = []struct {
	name    string // the name the real driver registers
	dialect SQLDialect
}{
	{"sqlserver", DialectMSSQL}, // github.com/microsoft/go-mssqldb
	{"mssql", DialectMSSQL},     // go-mssqldb's legacy name
	{"godror", "oracle"},        // github.com/godror/godror
	{"oracle", "oracle"},        // github.com/sijms/go-ora
	{"go_ibm_db", "db2"},        // github.com/ibmdb/go_ibm_db
}

func enterpriseOpen(t *testing.T, name string) (*sql.DB, *fakeDB) {
	t.Helper()
	registerEnterprise.Do(func() {
		for _, d := range enterpriseDrivers {
			f := &fakeDB{}
			enterpriseFakes[d.name] = f
			sql.Register(d.name, f)
		}
	})
	db, err := OpenSQL(name, "dsn")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, enterpriseFakes[name]
}

func TestSQLEnterpriseDriversContract(t *testing.T) {
	for _, d := range enterpriseDrivers {
		name := d.name
		runSinkContract(t, sinkCase{
			name:   "database/sql " + name,
			attack: SQLInjection,
			inputs: sqliInputs(),
			call: func(t *testing.T, ctx context.Context) (bool, error) {
				db, f := enterpriseOpen(t, name)
				return queryRan(db, f, ctx)
			},
		})
	}
}

func TestSQLEnterpriseDialectAndSink(t *testing.T) {
	for _, d := range enterpriseDrivers {
		if spec := newSQLSpec(d.name); spec.dialect != d.dialect || spec.sink != "db."+d.name {
			t.Errorf("%s: spec %+v, want dialect %s", d.name, spec, d.dialect)
		}
		log := setupEngine(t, engineSettings{mode: ModeMonitor})
		db, f := enterpriseOpen(t, d.name)
		ctx := requestCtx(sqliInputs(), nil)
		if ran, err := queryRan(db, f, ctx); err != nil || !ran {
			t.Fatalf("%s: ran=%v err=%v", d.name, ran, err)
		}
		ev := eventsOf(log, SQLInjection)
		if len(ev) != 1 || ev[0].Attrs["shield360.rasp.sink"] != "db."+d.name+".query" {
			t.Fatalf("%s: events %v", d.name, ev)
		}
		// Parameterised statements in each driver's placeholder style pass.
		for _, q := range []string{"SELECT * FROM t WHERE id = @p1", "SELECT * FROM t WHERE id = :1", "SELECT * FROM t WHERE id = ?"} {
			if _, err := db.ExecContext(ctx, q, sqliInput); err != nil {
				t.Fatalf("%s %q: %v", d.name, q, err)
			}
		}
		if len(eventsOf(log, SQLInjection)) != 1 {
			t.Fatalf("%s: parameterised statements reported", d.name)
		}
	}
	// A dialect the lexer does not know yet still detects (lexed with the shared rules).
	for _, dialect := range []SQLDialect{"mssql", "oracle", "db2"} {
		if f := DetectSQL(sqliQuery, sqliInputs(), dialect); f == nil || f.Rule != "sqli.userinput" {
			t.Errorf("%s: %+v", dialect, f)
		}
	}
}
