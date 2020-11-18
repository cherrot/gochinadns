package gochinadns

import (
	"reflect"
	"testing"
)

func Test_schemaToResolver(t *testing.T) {

	tests := []struct {
		input   string
		wantR   resolver
		wantErr bool
	}{
		{"8.8.8.8:53", resolver{
			addr:      "8.8.8.8:53",
			protocols: []string{"udp", "tcp"},
		}, false},
		{"udp@8.8.8.8:54", resolver{
			addr:      "8.8.8.8:54",
			protocols: []string{"udp"},
		}, false},
		{"UDP+tcp@8.8.8.8:53", resolver{
			addr:      "8.8.8.8:53",
			protocols: []string{"udp", "tcp"},
		}, false},
		{"UDP+udp+tcp@8.8.8.8:53", resolver{
			addr:      "8.8.8.8:53",
			protocols: []string{"udp", "tcp"},
		}, false},
		{"tcp+udp@8.8.8.8:53", resolver{
			addr:      "8.8.8.8:53",
			protocols: []string{"tcp", "udp"},
		}, false},
		{"@8.8.8.8:53", resolver{}, true},
		{"asdf@8.8.8.8:53", resolver{}, true},
		{"wut+tcp@8.8.8.8:53", resolver{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			gotR, err := schemaToResolver(tt.input, false)
			if (err != nil) != tt.wantErr {
				t.Errorf("schemaToResolver() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotR, tt.wantR) {
				t.Errorf("schemaToResolver() gotR = %v, want %v", gotR, tt.wantR)
			}
		})
	}
}
