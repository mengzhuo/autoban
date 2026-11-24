package ban

import (
	"testing"
	"time"
)

func newTestTracker(t *testing.T, now *time.Time, opts Options) *Tracker {
	t.Helper()
	opts.Now = func() time.Time { return *now }
	if opts.MaxRetry == 0 {
		opts.MaxRetry = 3
	}
	if opts.FindTime == 0 {
		opts.FindTime = 10 * time.Minute
	}
	if opts.BanTime == 0 {
		opts.BanTime = time.Hour
	}
	tr, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func TestThresholdAndExpiry(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	tr := newTestTracker(t, &now, Options{IgnoreIP: []string{"127.0.0.1/8", "::1"}})

	if r := tr.AddFailure("127.0.0.1", now, "ignored"); r.Counted {
		t.Fatal("loopback should be ignored")
	}
	for i := 1; i <= 2; i++ {
		r := tr.AddFailure("203.0.113.5", now, "bad line")
		if !r.Counted || r.Ban != nil || r.Count != i {
			t.Fatalf("failure %d: %#v", i, r)
		}
	}
	r := tr.AddFailure("203.0.113.5", now, "bad line")
	if r.Ban == nil {
		t.Fatal("expected ban")
	}
	if r.Ban.IP != "203.0.113.5" || r.Ban.Duration != time.Hour || r.Ban.BanCount != 1 || len(r.Ban.Matches) != 3 {
		t.Fatalf("ban = %#v", r.Ban)
	}
	if !tr.IsBanned("203.0.113.5") {
		t.Fatal("not banned")
	}
	if r := tr.AddFailure("203.0.113.5", now, "more"); r.Counted {
		t.Fatal("failures while banned should not count")
	}
	if got := tr.Expire(now.Add(30 * time.Minute)); len(got) != 0 {
		t.Fatalf("early expiry = %#v", got)
	}
	expired := tr.Expire(now.Add(time.Hour + time.Second))
	if len(expired) != 1 || expired[0].IP != "203.0.113.5" {
		t.Fatalf("expired = %#v", expired)
	}
	if tr.IsBanned("203.0.113.5") {
		t.Fatal("still banned")
	}
}

func TestMaxLinesInMatches(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	tr := newTestTracker(t, &now, Options{MaxRetry: 4, MaxLines: 2})
	for i, line := range []string{"first", "second", "third"} {
		r := tr.AddFailure("203.0.113.5", now, line)
		if r.Ban != nil {
			t.Fatalf("ban on failure %d: %#v", i+1, r.Ban)
		}
	}
	r := tr.AddFailure("203.0.113.5", now, "fourth")
	if r.Ban == nil {
		t.Fatal("expected ban")
	}
	if got := r.Ban.Matches; len(got) != 2 || got[0] != "third" || got[1] != "fourth" {
		t.Fatalf("matches = %#v, want last two lines", got)
	}
	if r.Ban.Failures != 4 {
		t.Fatalf("failures = %d, want 4", r.Ban.Failures)
	}
}

func TestSetMaxLines(t *testing.T) {
	now := time.Now()
	tr := newTestTracker(t, &now, Options{MaxRetry: 2, MaxLines: 1})
	if err := tr.SetMaxLines(3); err != nil {
		t.Fatal(err)
	}
	if got := tr.Options().MaxLines; got != 3 {
		t.Fatalf("maxlines = %d, want 3", got)
	}
	if err := tr.SetMaxLines(0); err == nil {
		t.Fatal("expected invalid maxlines error")
	}
}

func TestFindTimeWindowAndStale(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	tr := newTestTracker(t, &now, Options{MaxRetry: 2})
	if r := tr.AddFailure("203.0.113.5", now.Add(-11*time.Minute), "old"); !r.Stale {
		t.Fatalf("expected stale, got %#v", r)
	}
	if r := tr.AddFailure("203.0.113.5", now.Add(-9*time.Minute), "recent"); !r.Counted || r.Ban != nil {
		t.Fatalf("recent = %#v", r)
	}
	if r := tr.AddFailure("203.0.113.5", now, "now"); r.Ban == nil {
		t.Fatalf("expected ban, got %#v", r)
	}
}

func TestIgnoreIP(t *testing.T) {
	now := time.Now()
	tr := newTestTracker(t, &now, Options{MaxRetry: 1, IgnoreIP: []string{
		"192.0.2.0/24", "2001:db8::/32", "localhost",
	}})
	for _, ip := range []string{"192.0.2.55", "2001:db8::1", "localhost"} {
		if !tr.IsIgnored(ip) {
			t.Fatalf("%s should be ignored", ip)
		}
		if r := tr.AddFailure(ip, now, "x"); r.Counted || r.Ban != nil {
			t.Fatalf("%s counted: %#v", ip, r)
		}
	}
	if tr.IsIgnored("198.51.100.1") {
		t.Fatal("198.51.100.1 should not be ignored")
	}
	if r := tr.AddFailure("198.51.100.1", now, "x"); r.Ban == nil {
		t.Fatal("expected ban")
	}
}

func TestIncrementAndMaxTime(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	tr := newTestTracker(t, &now, Options{
		MaxRetry:         1,
		BanTime:          10 * time.Minute,
		BanTimeIncrement: true,
		BanTimeFactor:    2,
		BanTimeMax:       25 * time.Minute,
		DBPurgeAge:       24 * time.Hour,
	})
	if r := tr.AddFailure("203.0.113.5", now, "x"); r.Ban == nil || r.Ban.Duration != 10*time.Minute || r.Ban.BanCount != 1 {
		t.Fatalf("first = %#v", r.Ban)
	}
	now = now.Add(5 * time.Minute)
	if _, err := tr.Unban("203.0.113.5"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if r := tr.AddFailure("203.0.113.5", now, "x"); r.Ban == nil || r.Ban.Duration != 20*time.Minute || r.Ban.BanCount != 2 {
		t.Fatalf("second = %#v", r.Ban)
	}
	now = now.Add(5 * time.Minute)
	_, _ = tr.Unban("203.0.113.5")
	now = now.Add(time.Minute)
	if r := tr.AddFailure("203.0.113.5", now, "x"); r.Ban == nil || r.Ban.Duration != 25*time.Minute || r.Ban.BanCount != 3 {
		t.Fatalf("third = %#v", r.Ban)
	}
}

func TestPermanentBan(t *testing.T) {
	now := time.Now()
	tr := newTestTracker(t, &now, Options{MaxRetry: 1, BanTime: -time.Second})
	r := tr.AddFailure("203.0.113.5", now, "x")
	if r.Ban == nil || !r.Ban.Until.IsZero() || r.Ban.Duration >= 0 {
		t.Fatalf("permanent = %#v", r.Ban)
	}
	if got := tr.Expire(now.Add(100 * 365 * 24 * time.Hour)); len(got) != 0 {
		t.Fatalf("permanent expired: %#v", got)
	}
	if _, err := tr.Unban("203.0.113.5"); err != nil {
		t.Fatal(err)
	}
}

func TestManualBanUnban(t *testing.T) {
	now := time.Now()
	tr := newTestTracker(t, &now, Options{})
	b, err := tr.BanIP("203.0.113.5")
	if err != nil || b == nil || b.IP != "203.0.113.5" {
		t.Fatalf("ban = %#v, %v", b, err)
	}
	if b2, err := tr.BanIP("203.0.113.5"); err != nil || b2 != nil {
		t.Fatalf("second ban = %#v, %v", b2, err)
	}
	b, err = tr.Unban("203.0.113.5")
	if err != nil || b == nil {
		t.Fatalf("unban = %#v, %v", b, err)
	}
	if b, err := tr.Unban("203.0.113.5"); err != nil || b != nil {
		t.Fatalf("second unban = %#v, %v", b, err)
	}
}

func TestSnapshotRestore(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	tr := newTestTracker(t, &now, Options{MaxRetry: 1, BanTime: time.Hour})
	if r := tr.AddFailure("203.0.113.5", now, "bad"); r.Ban == nil {
		t.Fatal("expected ban")
	}
	snap := tr.Snapshot(now)

	now = now.Add(10 * time.Minute)
	tr2 := newTestTracker(t, &now, Options{MaxRetry: 1, BanTime: time.Hour})
	tr2.Restore(snap)
	if !tr2.IsBanned("203.0.113.5") {
		t.Fatal("ban not restored")
	}
	st := tr2.Status(now)
	if st.CurrentlyBanned != 1 || st.Banned[0].Restored != true {
		t.Fatalf("status = %#v", st)
	}

	now = now.Add(2 * time.Hour)
	expired := tr2.Expire(now)
	if len(expired) != 1 || expired[0].IP != "203.0.113.5" {
		t.Fatalf("expired = %#v", expired)
	}
}

func TestNormalizeIP(t *testing.T) {
	cases := map[string]string{
		"::ffff:192.0.2.1": "192.0.2.1",
		"[2001:db8::1]":    "2001:db8::1",
		"Example.COM.":     "example.com",
		"2001:db8::1%eth0": "2001:db8::1",
	}
	for in, want := range cases {
		got, err := NormalizeIP(in)
		if err != nil || got != want {
			t.Fatalf("%q = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "999.999.999.999", "not a host", "-option", "bad-"} {
		if _, err := NormalizeIP(bad); err == nil {
			t.Fatalf("%q should be invalid", bad)
		}
	}
}
