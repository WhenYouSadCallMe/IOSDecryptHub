package profile

import "testing"

func TestLoadGenericProfile(t *testing.T) {
	data := []byte(`{
      "schemaVersion": 1,
      "name": "generic-network",
      "mode": "record-only",
      "hooks": [{
        "id": "request.resume",
        "type": "objc",
        "target": {"class": "NSURLSessionTask", "selector": "resume"},
        "capture": ["arguments", "stack"],
        "sampleRate": 1
      }]
    }`)
	p, err := Load(data)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "generic-network" || len(p.Hooks) != 1 {
		t.Fatalf("unexpected profile: %+v", p)
	}
}

func TestProfileValidationRejectsDuplicateAndInvalidRate(t *testing.T) {
	data := []byte(`{
      "schemaVersion": 1,
      "name": "bad",
      "hooks": [
        {"id":"same", "type":"c-import", "target":{"symbol":"a"}, "sampleRate":1.1},
        {"id":"same", "type":"c-import", "target":{"symbol":"b"}}
      ]
    }`)
	if _, err := Load(data); err == nil {
		t.Fatal("expected profile validation error")
	}
}

func TestYAMLProfileUsesSameValidationContract(t *testing.T) {
	profile, err := LoadYAML([]byte(`schemaVersion: 1
name: yaml-profile
mode: record-only
hooks:
  - id: request
    type: objc
    target:
      class: NSURLSessionTask
      selector: resume
`))
	if err != nil {
		t.Fatal(err)
	}
	if profile.Name != "yaml-profile" || len(profile.Hooks) != 1 || profile.Hooks[0].Target.Selector != "resume" {
		t.Fatalf("unexpected YAML profile: %+v", profile)
	}
}
