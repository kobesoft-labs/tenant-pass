package redis

import "testing"

func TestPrivileged(t *testing.T) {
	cases := map[string]bool{
		"-@all +get +set":                  false,
		"-@all +@read +@write ~t:acme:*":   false,
		"-@all +@keyspace +@string":        false, // DRYRUN covers dangerous members
		"+@all":                            true,
		"-@all +@admin":                    true,
		"-@all +@dangerous":                true,
		"-@all +config|get":                true,
		"-@all +ACL":                       true,
		"-@all +acl|whoami":                true, // acl: every subcommand refused
		"-@all +get -acl":                  false,
		"-@all +flushall":                  true,
		"-@all +client|setname +get +hset": false,
		"-@all +client":                    true,
		"-@all +client|kill":               true,
		"-@all +function|load":             true,
		"-@all +function|list +fcall":      false,
		"-@all +keys":                      true,
	}
	for rules, want := range cases {
		u := aclUser{commands: []string{rules}}
		if got := u.privileged() != ""; got != want {
			t.Errorf("%q: privileged = %v", rules, got)
		}
	}
	for _, flag := range []string{"allcommands", "allkeys"} {
		if (aclUser{flags: []string{"on", flag}}).privileged() == "" {
			t.Errorf("%s flag not detected", flag)
		}
	}
	// Selectors count too.
	if (aclUser{commands: []string{"-@all +get", "+@all"}}).privileged() == "" {
		t.Error("selector not checked")
	}
}

func TestMarker(t *testing.T) {
	u := aclUser{channels: "&t:acme:* &tenant-pass:managed"}
	if !u.hasMarker("tenant-pass:managed") {
		t.Error("marker not found")
	}
	for _, ch := range []string{"&tenant-pass:managed*", "&*", "", "&tenant-pass:managedX"} {
		if (aclUser{channels: ch}).hasMarker("tenant-pass:managed") {
			t.Errorf("%q counted as marker", ch)
		}
	}
}

func TestParseUserRESP2(t *testing.T) {
	raw := []any{
		"flags", []any{"on"},
		"passwords", []any{"aa", "bb"},
		"commands", "-@all +get",
		"keys", "~t:*",
		"channels", "&tenant-pass:managed",
		"selectors", []any{[]any{"commands", "+@all", "keys", "~x", "channels", ""}},
	}
	u, err := parseUser(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(u.passwords) != 2 || len(u.commands) != 2 || u.privileged() == "" || !u.hasMarker("tenant-pass:managed") {
		t.Fatalf("parsed %+v", u)
	}
	bad := map[string][]any{
		"odd length":      {"odd"},
		"no flags":        {"passwords", []any{}, "commands", "", "channels", ""},
		"no commands":     {"flags", []any{}, "passwords", []any{}, "channels", ""},
		"no channels":     {"flags", []any{}, "passwords", []any{}, "commands", ""},
		"commands array":  {"flags", []any{}, "passwords", []any{}, "commands", []any{"+@all"}, "channels", ""},
		"duplicate key":   {"flags", []any{}, "passwords", []any{}, "commands", "", "commands", "+@all", "channels", ""},
		"bad selector":    {"flags", []any{}, "passwords", []any{}, "commands", "", "channels", "", "selectors", []any{[]any{"keys", "~*"}}},
		"non-string pass": {"flags", []any{}, "passwords", []any{int64(1)}, "commands", "", "channels", ""},
	}
	for name, r := range bad {
		if _, err := parseUser(r); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
