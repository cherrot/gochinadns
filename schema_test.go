package gochinadns

import (
	"reflect"
	"testing"
)

func Test_schemaToResolver(t *testing.T) {

	tests := []struct {
		input   string
		wantR   *Resolver
		wantErr bool
	}{
		{"8.8.8.8:53", &Resolver{
			Addr:      "8.8.8.8:53",
			Protocols: []string{"udp"},
		}, false},
		{"udp@8.8.8.8:54", &Resolver{
			Addr:      "8.8.8.8:54",
			Protocols: []string{"udp"},
		}, false},
		{"UDP+tcp@8.8.8.8:53", &Resolver{
			Addr:      "8.8.8.8:53",
			Protocols: []string{"udp", "tcp"},
		}, false},
		{"UDP+udp+tcp@8.8.8.8:53", &Resolver{
			Addr:      "8.8.8.8:53",
			Protocols: []string{"udp", "tcp"},
		}, false},
		{"tcp+udp@8.8.8.8:53", &Resolver{
			Addr:      "8.8.8.8:53",
			Protocols: []string{"tcp", "udp"},
		}, false},
		{"@8.8.8.8:53", nil, true},
		{"asdf@8.8.8.8:53", nil, true},
		{"wut+tcp@8.8.8.8:53", nil, true},
		{"2a09::", &Resolver{
			Addr:      "[2a09::]:53",
			Protocols: []string{"udp"},
		}, false},
		{"[2a09::]", &Resolver{
			Addr:      "[2a09::]:53",
			Protocols: []string{"udp"},
		}, false},
		{"[2a09::]:123", &Resolver{
			Addr:      "[2a09::]:123",
			Protocols: []string{"udp"},
		}, false},
		{"tcp+udp@2a09::", &Resolver{
			Addr:      "[2a09::]:53",
			Protocols: []string{"tcp", "udp"},
		}, false},
		{"doh@https://doh.serv/query", &Resolver{
			Addr:      "https://doh.serv/query",
			Protocols: []string{"doh"},
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			gotR, err := ParseResolver(tt.input, false)
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
