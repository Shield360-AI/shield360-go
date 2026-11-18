// Package goredis traces go-redis (github.com/redis/go-redis/v9) commands
// inside the request trace, recorded by command name only.
//
//	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
//	if err := goredis.Instrument(rdb); err != nil { ... }
//
// SHIELD: data minimisation. The upstream hook (redisotel) records each
// command with its keys and values in db.statement by default; here that is
// off, so a span is the command name ("get", "set") and the server, never a
// key or value. Call shield360.Init first so the spans are exported.
package goredis

import (
	"github.com/redis/go-redis/extra/redisotel/v9"
	"github.com/redis/go-redis/v9"
)

// Instrument adds tracing to rdb (a *redis.Client, *redis.ClusterClient or
// *redis.Ring). Options are passed on to redisotel after the Shield360
// defaults, so an app can opt back in to statements with
// redisotel.WithDBStatement(true).
func Instrument(rdb redis.UniversalClient, opts ...redisotel.TracingOption) error {
	return redisotel.InstrumentTracing(rdb, append(defaults(), opts...)...)
}

func defaults() []redisotel.TracingOption {
	return []redisotel.TracingOption{redisotel.WithDBStatement(false)}
}
