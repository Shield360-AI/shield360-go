package rasp

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
)

// database/sql sink (README "SQL", "NoSQL"). A driver wrapper checks the
// query text of every Query, Exec and Prepare (and their Context variants,
// on the DB, a Conn and a Tx alike) before the driver sees it, with the
// dialect from the driver name. Prepared statements are checked once, at
// Prepare; executing one sends no new text. Rows, statements and
// transactions are the driver's own.
//
// Inputs come from the context.Context database/sql passes down, so use the
// Context variants (QueryContext, ExecContext, PrepareContext, BeginTx)
// with the request's context; db.Query has no request in scope.

// SQLDialectOf maps a database/sql driver name to the SQL lexer's dialect.
func SQLDialectOf(driverName string) SQLDialect {
	n := strings.ToLower(driverName)
	switch {
	case strings.Contains(n, "postgres"), n == "pgx", strings.HasPrefix(n, "pgx/"), n == "pq", strings.Contains(n, "cockroach"), strings.Contains(n, "redshift"):
		return DialectPostgres
	case strings.Contains(n, "mysql"), strings.Contains(n, "mariadb"), strings.Contains(n, "tidb"):
		return DialectMySQL
	case strings.Contains(n, "sqlite"):
		return DialectSQLite
	case strings.Contains(n, "sqlserver"), strings.Contains(n, "mssql"), strings.Contains(n, "azuresql"):
		return DialectMSSQL
	// Oracle: godror, go-ora ("oracle"), go-oci8 ("oci8"); Db2: go_ibm_db. The
	// lexer's own oracle and db2 rules land separately; until then a dialect it
	// does not know is lexed with the rules every dialect shares.
	case strings.Contains(n, "oracle"), strings.Contains(n, "godror"), strings.Contains(n, "go-ora"), strings.Contains(n, "oci8"):
		return SQLDialect("oracle")
	case strings.Contains(n, "ibm_db"), strings.Contains(n, "db2"):
		return SQLDialect("db2")
	}
	return DialectGeneric
}

type sqlSpec struct {
	sink    string // db.<driver>
	dialect SQLDialect
}

func newSQLSpec(driverName string) sqlSpec {
	return sqlSpec{sink: "db." + sinkWord(driverName, "sql"), dialect: SQLDialectOf(driverName)}
}

// OpenSQL is sql.Open with RASP checks on every statement: the driver
// registered under driverName, wrapped. Like sql.Open it does not connect.
func OpenSQL(driverName, dataSourceName string) (*sql.DB, error) {
	probe, err := sql.Open(driverName, dataSourceName)
	if err != nil {
		return nil, err
	}
	d := probe.Driver()
	_ = probe.Close()
	var c driver.Connector
	if dc, ok := d.(driver.DriverContext); ok {
		if c, err = dc.OpenConnector(dataSourceName); err != nil {
			return nil, err
		}
	} else {
		c = dsnConnector{dsn: dataSourceName, d: d}
	}
	return sql.OpenDB(WrapConnector(driverName, c)), nil
}

// OpenSQLDB is sql.OpenDB with RASP checks: driverName names the dialect
// and the event sink (db.<driverName>.query).
func OpenSQLDB(driverName string, c driver.Connector) *sql.DB {
	return sql.OpenDB(WrapConnector(driverName, c))
}

// WrapDriver returns d with RASP checks, for sql.Register:
//
//	sql.Register("postgres+rasp", rasp.WrapDriver("postgres", &pq.Driver{}))
//
// name gives the dialect and the event sink. Wrapping a wrapped driver
// returns it unchanged.
func WrapDriver(name string, d driver.Driver) driver.Driver {
	switch d.(type) {
	case *sqlDriver, *sqlDriverContext:
		return d
	}
	base := &sqlDriver{d: d, spec: newSQLSpec(name)}
	if dc, ok := d.(driver.DriverContext); ok {
		return &sqlDriverContext{sqlDriver: base, dc: dc}
	}
	return base
}

// WrapConnector returns c with RASP checks (for sql.OpenDB). name gives the
// dialect and the event sink. Wrapping a wrapped connector returns it
// unchanged.
func WrapConnector(name string, c driver.Connector) driver.Connector {
	if w, ok := c.(*sqlConnector); ok {
		return w
	}
	return &sqlConnector{c: c, spec: newSQLSpec(name), name: name}
}

type sqlDriver struct {
	d    driver.Driver
	spec sqlSpec
}

func (w *sqlDriver) Open(dsn string) (driver.Conn, error) {
	c, err := w.d.Open(dsn)
	if err != nil {
		return nil, err
	}
	return wrapConn(c, w.spec), nil
}

type sqlDriverContext struct {
	*sqlDriver
	dc driver.DriverContext
}

func (w *sqlDriverContext) OpenConnector(dsn string) (driver.Connector, error) {
	c, err := w.dc.OpenConnector(dsn)
	if err != nil {
		return nil, err
	}
	return &sqlConnector{c: c, spec: w.spec, drv: w}, nil
}

// dsnConnector is database/sql's own fallback for drivers without
// DriverContext.
type dsnConnector struct {
	dsn string
	d   driver.Driver
}

func (c dsnConnector) Connect(context.Context) (driver.Conn, error) { return c.d.Open(c.dsn) }
func (c dsnConnector) Driver() driver.Driver                        { return c.d }

type sqlConnector struct {
	c    driver.Connector
	spec sqlSpec
	name string
	drv  driver.Driver
}

func (w *sqlConnector) Connect(ctx context.Context) (driver.Conn, error) {
	c, err := w.c.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return wrapConn(c, w.spec), nil
}

func (w *sqlConnector) Driver() driver.Driver {
	if w.drv != nil {
		return w.drv
	}
	return &sqlDriver{d: w.c.Driver(), spec: w.spec}
}

// Close closes the underlying connector when it is an io.Closer (DB.Close
// calls it).
func (w *sqlConnector) Close() error {
	if cl, ok := w.c.(interface{ Close() error }); ok {
		return cl.Close()
	}
	return nil
}

// sqlConn is the checked connection. database/sql never uses a driver
// connection from two goroutines at once, so its fields need no lock.
type sqlConn struct {
	c    driver.Conn
	spec sqlSpec
	// skipped is the text of a statement the driver declined with
	// driver.ErrSkip after it was checked: database/sql now prepares the same
	// text, which is not checked again (one check per statement).
	skipped    string
	hasSkipped bool
}

var (
	_ driver.Conn               = (*sqlConn)(nil)
	_ driver.ConnPrepareContext = (*sqlConn)(nil)
	_ driver.ConnBeginTx        = (*sqlConn)(nil)
	_ driver.ExecerContext      = (*sqlConn)(nil)
	_ driver.QueryerContext     = (*sqlConn)(nil)
	_ driver.Pinger             = (*sqlConn)(nil)
	_ driver.NamedValueChecker  = (*sqlConn)(nil)
)

// wrapConn wraps a driver connection. SessionResetter and Validator are
// exposed only when the driver's connection has them: database/sql keeps a
// connection after a cancelled transaction only when it has both.
func wrapConn(c driver.Conn, spec sqlSpec) driver.Conn {
	w := &sqlConn{c: c, spec: spec}
	r, hasR := c.(driver.SessionResetter)
	v, hasV := c.(driver.Validator)
	switch {
	case hasR && hasV:
		return struct {
			*sqlConn
			driver.SessionResetter
			driver.Validator
		}{w, r, v}
	case hasR:
		return struct {
			*sqlConn
			driver.SessionResetter
		}{w, r}
	case hasV:
		return struct {
			*sqlConn
			driver.Validator
		}{w, v}
	}
	return w
}

// Unwrap returns the driver's connection (for sql.Conn.Raw callers).
func (w *sqlConn) Unwrap() driver.Conn { return w.c }

func (w *sqlConn) check(ctx context.Context, op, query string) error {
	if !Active() {
		return nil
	}
	inputs := inputsOf(ctx)
	if len(inputs) == 0 {
		return nil
	}
	return checkSink(ctx, w.spec.sink+"."+op, func(slot *iastSlot) *Finding { return detectSQLWith(query, inputs, w.spec.dialect, slot) })
}

// takeSkipped reports whether query is the statement the driver just
// declined after its check, and forgets it either way.
func (w *sqlConn) takeSkipped(query string) bool {
	hit := w.hasSkipped && w.skipped == query
	w.skipped, w.hasSkipped = "", false
	return hit
}

func (w *sqlConn) markSkipped(query string, err error) {
	// database/sql retries with a prepare only on the exact sentinel
	// (err != driver.ErrSkip); a wrapped one goes back to the caller.
	if err == driver.ErrSkip {
		w.skipped, w.hasSkipped = query, true
	}
}

func (w *sqlConn) Prepare(query string) (driver.Stmt, error) {
	return w.PrepareContext(context.Background(), query)
}

func (w *sqlConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	if !w.takeSkipped(query) {
		if err := w.check(ctx, "prepare", query); err != nil {
			return nil, err
		}
	}
	if pc, ok := w.c.(driver.ConnPrepareContext); ok {
		return pc.PrepareContext(ctx, query)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return w.c.Prepare(query)
}

func (w *sqlConn) Close() error { return w.c.Close() }

// Begin is required by driver.Conn; database/sql calls BeginTx.
func (w *sqlConn) Begin() (driver.Tx, error) {
	return w.BeginTx(context.Background(), driver.TxOptions{})
}

func (w *sqlConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	w.takeSkipped("")
	if bt, ok := w.c.(driver.ConnBeginTx); ok {
		return bt.BeginTx(ctx, opts)
	}
	// database/sql's own fallback for drivers without ConnBeginTx.
	if opts.Isolation != driver.IsolationLevel(sql.LevelDefault) {
		return nil, errors.New("sql: driver does not support non-default isolation level")
	}
	if opts.ReadOnly {
		return nil, errors.New("sql: driver does not support read-only transactions")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	//lint:ignore SA1019 the fallback for drivers without ConnBeginTx
	return w.c.Begin()
}

func namedToValues(args []driver.NamedValue) ([]driver.Value, error) {
	out := make([]driver.Value, len(args))
	for i, a := range args {
		if a.Name != "" {
			return nil, errors.New("sql: driver does not support the use of Named Parameters")
		}
		out[i] = a.Value
	}
	return out, nil
}

func (w *sqlConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	w.takeSkipped("")
	ec, hasCtx := w.c.(driver.ExecerContext)
	//lint:ignore SA1019 legacy drivers implement only Execer
	e, hasLegacy := w.c.(driver.Execer)
	if !hasCtx && !hasLegacy {
		// database/sql prepares the statement instead; it is checked there.
		return nil, driver.ErrSkip
	}
	if err := w.check(ctx, "exec", query); err != nil {
		return nil, err
	}
	var (
		res driver.Result
		err error
	)
	if hasCtx {
		res, err = ec.ExecContext(ctx, query, args)
	} else {
		var vals []driver.Value
		if vals, err = namedToValues(args); err != nil {
			return nil, err
		}
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		res, err = e.Exec(query, vals)
	}
	w.markSkipped(query, err)
	return res, err
}

func (w *sqlConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	w.takeSkipped("")
	qc, hasCtx := w.c.(driver.QueryerContext)
	//lint:ignore SA1019 legacy drivers implement only Queryer
	q, hasLegacy := w.c.(driver.Queryer)
	if !hasCtx && !hasLegacy {
		return nil, driver.ErrSkip
	}
	if err := w.check(ctx, "query", query); err != nil {
		return nil, err
	}
	var (
		rows driver.Rows
		err  error
	)
	if hasCtx {
		rows, err = qc.QueryContext(ctx, query, args)
	} else {
		var vals []driver.Value
		if vals, err = namedToValues(args); err != nil {
			return nil, err
		}
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		rows, err = q.Query(query, vals)
	}
	w.markSkipped(query, err)
	return rows, err
}

func (w *sqlConn) Ping(ctx context.Context) error {
	if p, ok := w.c.(driver.Pinger); ok {
		return p.Ping(ctx)
	}
	return nil
}

func (w *sqlConn) CheckNamedValue(nv *driver.NamedValue) error {
	if c, ok := w.c.(driver.NamedValueChecker); ok {
		return c.CheckNamedValue(nv)
	}
	return driver.ErrSkip
}

// CheckMongo checks MongoDB filter, update and pipeline documents before
// they reach the driver (README "NoSQL"): nosqli.operator when an operator
// object of the request's parsed body or query reaches the query, and
// nosqli.where for tainted code in $where / $function. It does not import
// the MongoDB driver: bson.D, bson.M, mongo.Pipeline, maps and slices are
// read generically. operation names the event sink (db.mongodb.<operation>).
// It returns only the block error:
//
//	if err := rasp.CheckMongo(ctx, "find", filter); err != nil { return err }
//	cur, err := coll.Find(ctx, filter)
func CheckMongo(ctx context.Context, operation string, docs ...any) error {
	if !Active() {
		return nil
	}
	rc := FromContext(ctx)
	if rc == nil {
		return nil
	}
	inputs, trees := rc.Inputs(), rc.Trees()
	if len(inputs) == 0 && len(trees) == 0 {
		return nil
	}
	return checkSink(ctx, "db.mongodb."+sinkWord(operation, "command"), func(*iastSlot) *Finding {
		for _, d := range docs {
			if f := DetectNoSQL(d, trees, inputs); f != nil {
				return f
			}
		}
		return nil
	})
}
