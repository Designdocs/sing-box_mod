package dynamicuser

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func TestRevocationAndFailedPublication(t *testing.T) {
	var r Registry
	alice := User{Name: "alice", Secret: "first"}
	bob := User{Name: "bob", Secret: "second"}
	if err := r.Update([]User{alice, bob}, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	server, client := net.Pipe()
	defer client.Close()
	ctx, done, ok := r.Track(context.Background(), server, alice, nil)
	if !ok {
		t.Fatal("active user rejected")
	}
	defer done(nil)
	failure := errors.New("bad credentials")
	if err := r.Update([]User{bob}, func() error { return failure }); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	if ctx.Err() != nil {
		t.Fatal("failed publication revoked a user")
	}
	if err := r.Update([]User{bob}, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if ctx.Err() == nil {
		t.Fatal("removed user context is still active")
	}
	client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("removed user's connection remains open")
	}
	stale, other := net.Pipe()
	defer stale.Close()
	defer other.Close()
	if _, _, ok := r.Track(context.Background(), stale, alice, nil); ok {
		t.Fatal("stale handshake was admitted")
	}
	if len(r.entries) != 0 {
		t.Fatal("revocation retained connection entries")
	}
}

func TestConcurrentAdmissionChurnAndClose(t *testing.T) {
	var r Registry
	user := User{Name: "same", Secret: "credential"}
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 100 {
				s, c := net.Pipe()
				_, done, ok := r.Track(context.Background(), s, user, nil)
				if ok {
					done(nil)
				}
				s.Close()
				c.Close()
			}
		})
	}
	wg.Go(func() {
		for range 100 {
			_ = r.Update([]User{user}, func() error { return nil })
			_ = r.Update(nil, func() error { return nil })
		}
	})
	wg.Wait()
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := r.Update([]User{user}, func() error { return nil }); !errors.Is(err, net.ErrClosed) {
		t.Fatal("closed registry accepted update", err)
	}
	if len(r.entries) != 0 {
		t.Fatal("connection entries leaked")
	}
}
