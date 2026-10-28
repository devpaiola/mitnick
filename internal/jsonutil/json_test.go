package jsonutil

import "testing"

func TestRejectDuplicateKeys(t *testing.T) {
	for _, input := range []string{
		`{"packages":{"node_modules/lodash":{"version":"4.17.23"},"node_modules/lodash":{"version":"4.18.0"}}}`,
		`{"version":1,"ai":{"provider":"codex","provider":"claude"}}`,
		`{} {}`,
		`{"value": [1,}`,
	} {
		if err := RejectDuplicateKeys([]byte(input)); err == nil {
			t.Errorf("accepted invalid or ambiguous JSON: %s", input)
		}
	}
	for _, input := range []string{`{}`, `{"items":[1,2,{"ok":true}]}`, `{"large":1e10000}`, `null`, `42`} {
		if err := RejectDuplicateKeys([]byte(input)); err != nil {
			t.Errorf("rejected valid JSON %s: %v", input, err)
		}
	}
}

func FuzzRejectDuplicateKeys(f *testing.F) {
	f.Add(`{"version":1,"nested":{"value":true}}`)
	f.Add(`{"value":1,"value":2}`)
	f.Add(`[]`)
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 1<<20 {
			t.Skip()
		}
		_ = RejectDuplicateKeys([]byte(input))
	})
}
