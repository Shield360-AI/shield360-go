package rasp

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
)

// A fake database/sql driver that records the statement text it is sent.

type fakeDB struct {
	mu   sync.Mutex
	sent []string
	// legacy: the conn implements only driver.Conn (no Context interfaces).
	legacy bool
	// skip: QueryContext and ExecContext decline with driver.ErrSkip.
	skip bool
	// wrappedSkip: QueryContext fails with an error wrapping driver.ErrSkip
	// (database/sql does not retry it).
	wrappedSkip bool
	// session: the conn implements SessionResetter and Validator.
	session bool
}

func (f *fakeDB) record(q string) {
	f.mu.Lock()
	f.sent = append(f.sent, q)
	f.mu.Unlock()
}

func (f *fakeDB) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sent)
}

func (f *fakeDB) Open(string) (driver.Conn, error) {
	if f.legacy {
		return &fakeLegacyConn{db: f}, nil
	}
	if f.session {
		return &fakeSessionConn{fakeConn{fakeLegacyConn{db: f}}}, nil
	}
	return &fakeConn{fakeLegacyConn{db: f}}, nil
}

type fakeSessionConn struct{ fakeConn }

func (*fakeSessionConn) ResetSession(context.Context) error { return nil }
func (*fakeSessionConn) IsValid() bool                      { return true }

func (f *fakeDB) Connect(context.Context) (driver.Conn, error) { return f.Open("") }
func (f *fakeDB) Driver() driver.Driver                        { return f }

type fakeLegacyConn struct{ db *fakeDB }

func (c *fakeLegacyConn) Prepare(q string) (driver.Stmt, error) {
	return &fakeStmt{db: c.db, q: q}, nil
}
func (c *fakeLegacyConn) Close() error              { return nil }
func (c *fakeLegacyConn) Begin() (driver.Tx, error) { return fakeTx{}, nil }

type fakeConn struct{ fakeLegacyConn }

func (c *fakeConn) PrepareContext(_ context.Context, q string) (driver.Stmt, error) {
	return &fakeStmt{db: c.db, q: q}, nil
}
func (c *fakeConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return fakeTx{}, nil
}
func (c *fakeConn) ExecContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Result, error) {
	if c.db.skip {
		return nil, driver.ErrSkip
	}
	c.db.record(q)
	return driver.RowsAffected(1), nil
}
func (c *fakeConn) QueryContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Rows, error) {
	if c.db.wrappedSkip {
		return nil, fmt.Errorf("fake: %w", driver.ErrSkip)
	}
	if c.db.skip {
		return nil, driver.ErrSkip
	}
	c.db.record(q)
	return &fakeRows{}, nil
}

type fakeStmt struct {
	db *fakeDB
	q  string
}

func (s *fakeStmt) Close() error  { return nil }
func (s *fakeStmt) NumInput() int { return -1 }
func (s *fakeStmt) Exec([]driver.Value) (driver.Result, error) {
	s.db.record(s.q)
	return driver.RowsAffected(1), nil
}
func (s *fakeStmt) Query([]driver.Value) (driver.Rows, error) {
	s.db.record(s.q)
	return &fakeRows{}, nil
}

type fakeTx struct{}

func (fakeTx) Commit() error   { return nil }
func (fakeTx) Rollback() error { return nil }

type fakeRows struct{}

func (*fakeRows) Columns() []string         { return []string{"x"} }
func (*fakeRows) Close() error              { return nil }
func (*fakeRows) Next([]driver.Value) error { return io.EOF }

// passConnector is another wrapper of the same kind (tracing, pooling):
// it hands its connections on, behind a type of its own.
type passConnector struct{ inner driver.Connector }

func (p passConnector) Connect(ctx context.Context) (driver.Conn, error) {
	c, err := p.inner.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &passConn{c}, nil
}
func (p passConnector) Driver() driver.Driver { return p.inner.Driver() }

type passConn struct{ driver.Conn }

func (p *passConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	return p.Conn.(driver.QueryerContext).QueryContext(ctx, q, args)
}
func (p *passConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	return p.Conn.(driver.ExecerContext).ExecContext(ctx, q, args)
}
func (p *passConn) PrepareContext(ctx context.Context, q string) (driver.Stmt, error) {
	return p.Conn.(driver.ConnPrepareContext).PrepareContext(ctx, q)
}

var registerFake sync.Once

const fakeDriverName = "rasp-postgres-fake"

var sharedFake = &fakeDB{}

func fakeOpen(t *testing.T) (*sql.DB, *fakeDB) {
	t.Helper()
	registerFake.Do(func() { sql.Register(fakeDriverName, sharedFake) })
	sharedFake.mu.Lock()
	sharedFake.sent = nil
	sharedFake.mu.Unlock()
	db, err := OpenSQL(fakeDriverName, "dsn")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, sharedFake
}

const (
	sqliInput = "1 OR 1=1"
	sqliQuery = "SELECT * FROM t WHERE id = 1 OR 1=1"
)

func sqliInputs() []Input { return AddInput(nil, sqliInput, "query.id") }

func queryRan(db *sql.DB, f *fakeDB, ctx context.Context) (bool, error) {
	before := f.count()
	rows, err := db.QueryContext(ctx, sqliQuery)
	if err == nil {
		_ = rows.Close()
	}
	return f.count() > before, err
}

func TestSQLWrapperContract(t *testing.T) {
	runSinkContract(t, sinkCase{
		name:   "database/sql",
		attack: SQLInjection,
		inputs: sqliInputs(),
		call: func(t *testing.T, ctx context.Context) (bool, error) {
			db, f := fakeOpen(t)
			return queryRan(db, f, ctx)
		},
		composed: map[string]sinkCall{
			"another wrapper on top": func(t *testing.T, ctx context.Context) (bool, error) {
				f := &fakeDB{}
				db := sql.OpenDB(passConnector{WrapConnector("postgres", f)})
				defer db.Close()
				return queryRan(db, f, ctx)
			},
			"another wrapper underneath": func(t *testing.T, ctx context.Context) (bool, error) {
				f := &fakeDB{}
				db := OpenSQLDB("postgres", passConnector{f})
				defer db.Close()
				return queryRan(db, f, ctx)
			},
		},
	})
}

// Every way database/sql sends text: DB, Conn and Tx, Query, Exec and
// Prepare with their Context variants. Each is checked exactly once.
func TestSQLEveryPathCheckedOnce(t *testing.T) {
	type path struct {
		name string
		run  func(ctx context.Context, db *sql.DB) error
	}
	q := sqliQuery
	paths := []path{
		{"DB.QueryContext", func(ctx context.Context, db *sql.DB) error {
			r, err := db.QueryContext(ctx, q)
			if err == nil {
				r.Close()
			}
			return err
		}},
		{"DB.QueryRowContext", func(ctx context.Context, db *sql.DB) error {
			var x any
			err := db.QueryRowContext(ctx, q).Scan(&x)
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			return err
		}},
		{"DB.ExecContext", func(ctx context.Context, db *sql.DB) error { _, err := db.ExecContext(ctx, q); return err }},
		{"DB.PrepareContext", func(ctx context.Context, db *sql.DB) error {
			s, err := db.PrepareContext(ctx, q)
			if err != nil {
				return err
			}
			defer s.Close()
			_, err = s.ExecContext(ctx)
			return err
		}},
		{"Conn.QueryContext", func(ctx context.Context, db *sql.DB) error {
			c, err := db.Conn(ctx)
			if err != nil {
				return err
			}
			defer c.Close()
			r, err := c.QueryContext(ctx, q)
			if err == nil {
				r.Close()
			}
			return err
		}},
		{"Conn.ExecContext", func(ctx context.Context, db *sql.DB) error {
			c, err := db.Conn(ctx)
			if err != nil {
				return err
			}
			defer c.Close()
			_, err = c.ExecContext(ctx, q)
			return err
		}},
		{"Tx.QueryContext", func(ctx context.Context, db *sql.DB) error {
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				return err
			}
			defer tx.Rollback()
			r, err := tx.QueryContext(ctx, q)
			if err == nil {
				r.Close()
			}
			return err
		}},
		{"Tx.ExecContext", func(ctx context.Context, db *sql.DB) error {
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				return err
			}
			defer tx.Rollback()
			_, err = tx.ExecContext(ctx, q)
			return err
		}},
		{"Tx.PrepareContext", func(ctx context.Context, db *sql.DB) error {
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				return err
			}
			defer tx.Rollback()
			s, err := tx.PrepareContext(ctx, q)
			if err != nil {
				return err
			}
			defer s.Close()
			_, err = s.ExecContext(ctx)
			return err
		}},
	}
	drivers := map[string]func() *fakeDB{
		"context driver":             func() *fakeDB { return &fakeDB{} },
		"legacy driver (prepare)":    func() *fakeDB { return &fakeDB{legacy: true} },
		"driver declining (ErrSkip)": func() *fakeDB { return &fakeDB{skip: true} },
	}
	for dname, mk := range drivers {
		for _, p := range paths {
			t.Run(dname+"/"+p.name, func(t *testing.T) {
				log := setupEngine(t, engineSettings{mode: ModeMonitor})
				f := mk()
				db := OpenSQLDB("postgres", f)
				defer db.Close()
				if err := p.run(requestCtx(sqliInputs(), nil), db); err != nil {
					t.Fatal(err)
				}
				ev := eventsOf(log, SQLInjection)
				if len(ev) != 1 {
					t.Fatalf("want one event, got %d", len(ev))
				}
				if f.count() == 0 {
					t.Fatal("the statement never reached the driver")
				}
				if sink := ev[0].Attrs["shield360.rasp.sink"]; sink[:12] != "db.postgres." {
					t.Fatalf("sink %q", sink)
				}

				setupEngine(t, engineSettings{mode: ModeBlock})
				f2 := mk()
				db2 := OpenSQLDB("postgres", f2)
				defer db2.Close()
				if err := p.run(requestCtx(sqliInputs(), nil), db2); !errors.Is(err, ErrBlocked) {
					t.Fatalf("want the block error, got %v", err)
				}
				if f2.count() != 0 {
					t.Fatal("blocked text reached the driver")
				}
			})
		}
	}
}

func TestSQLNoRequestAndSafeQueries(t *testing.T) {
	log := setupEngine(t, engineSettings{mode: ModeBlock})
	f := &fakeDB{}
	db := OpenSQLDB("postgres", f)
	defer db.Close()
	// No context: nothing in scope, the statement goes through.
	if _, err := db.Exec(sqliQuery); err != nil {
		t.Fatal(err)
	}
	if r, err := db.Query(sqliQuery); err != nil {
		t.Fatal(err)
	} else {
		r.Close()
	}
	// A parameterised query never contains the input.
	if _, err := db.ExecContext(requestCtx(sqliInputs(), nil), "SELECT * FROM t WHERE id = $1", sqliInput); err != nil {
		t.Fatal(err)
	}
	if len(log.all()) != 0 || f.count() != 3 {
		t.Fatalf("events %v, sent %d", log.all(), f.count())
	}
}

func TestSQLDialectOfAndWrapIdempotent(t *testing.T) {
	cases := map[string]SQLDialect{
		"postgres": DialectPostgres, "pgx": DialectPostgres, "pgx/v5": DialectPostgres, "pq": DialectPostgres,
		"mysql": DialectMySQL, "sqlite3": DialectSQLite, "sqlite": DialectSQLite,
		"sqlserver": DialectMSSQL, "mssql": DialectMSSQL, "azuresql": DialectMSSQL,
		"oracle": "oracle", "godror": "oracle", "go-ora": "oracle", "oci8": "oracle",
		"go_ibm_db": "db2", "db2": "db2", "clickhouse": DialectGeneric,
	}
	for name, want := range cases {
		if got := SQLDialectOf(name); got != want {
			t.Errorf("%s: %s, want %s", name, got, want)
		}
	}
	f := &fakeDB{}
	w := WrapDriver("postgres", f)
	if WrapDriver("mysql", w) != w {
		t.Fatal("WrapDriver wrapped twice")
	}
	c := WrapConnector("postgres", f)
	if WrapConnector("postgres", c) != c {
		t.Fatal("WrapConnector wrapped twice")
	}
	// Dialect matters: backslash escapes only in mysql.
	if newSQLSpec("pgx").sink != "db.pgx" || newSQLSpec("").sink != "db.sql" {
		t.Fatal("sink names")
	}
}

type bsonE struct {
	Key   string
	Value any
}
type bsonD []bsonE

func TestCheckMongoContract(t *testing.T) {
	body := map[string]any{"user": map[string]any{"$ne": ""}}
	inputs := AddInput(nil, "x", "body.user.$ne")
	runSinkContract(t, sinkCase{
		name:   "CheckMongo",
		attack: NoSQLInjection,
		inputs: inputs,
		trees:  []any{body},
		call: func(t *testing.T, ctx context.Context) (bool, error) {
			// The app builds its filter from the parsed body (bson.D shape).
			filter := bsonD{{Key: "user", Value: body["user"]}}
			if err := CheckMongo(ctx, "find", filter); err != nil {
				return false, err
			}
			return true, nil
		},
	})
	t.Run("safe filter and $where", func(t *testing.T) {
		log := setupEngine(t, engineSettings{mode: ModeBlock})
		ctx := requestCtx(AddInput(nil, "this.a == 1 || true", "query.q"), []any{map[string]any{"name": "bob"}})
		if err := CheckMongo(ctx, "find", map[string]any{"name": "bob"}); err != nil {
			t.Fatal(err)
		}
		err := CheckMongo(ctx, "find", map[string]any{"$where": "this.a == 1 || true"})
		if b := AsBlocked(err); b == nil || b.Rule != "nosqli.where" {
			t.Fatalf("want nosqli.where, got %v", err)
		}
		if ev := log.all(); len(ev) != 1 || ev[0].Attrs["shield360.rasp.sink"] != "db.mongodb.find" {
			t.Fatalf("events %v", ev)
		}
	})
}

// A wrapped ErrSkip is not database/sql's retry signal: the error goes back
// to the caller, and a later Prepare of the same text is checked.
func TestSQLWrappedErrSkipIsNotASkip(t *testing.T) {
	log := setupEngine(t, engineSettings{mode: ModeMonitor})
	db := OpenSQLDB("postgres", &fakeDB{wrappedSkip: true})
	defer db.Close()
	ctx := requestCtx(sqliInputs(), nil)
	c, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.QueryContext(ctx, sqliQuery); !errors.Is(err, driver.ErrSkip) {
		t.Fatalf("want the wrapped error back, got %v", err)
	}
	s, err := c.PrepareContext(ctx, sqliQuery)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if ev := eventsOf(log, SQLInjection); len(ev) != 2 {
		t.Fatalf("want the query and the prepare checked, got %d events", len(ev))
	}
}

// SessionResetter and Validator are exposed exactly when the driver's
// connection has them.
func TestSQLConnOptionalInterfaces(t *testing.T) {
	for _, session := range []bool{false, true} {
		db := OpenSQLDB("postgres", &fakeDB{session: session})
		c, err := db.Conn(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		err = c.Raw(func(dc any) error {
			_, r := dc.(driver.SessionResetter)
			_, v := dc.(driver.Validator)
			if r != session || v != session {
				t.Errorf("driver session=%v: wrapper resetter=%v validator=%v", session, r, v)
			}
			if _, ok := dc.(driver.QueryerContext); !ok {
				t.Error("lost QueryerContext")
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
		db.Close()
	}
}
