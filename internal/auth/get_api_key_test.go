package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		wantKey     string
		wantErr     error
		wantAnyErr  bool
	}{
		{
			name:    "no authorization header",
			headers: http.Header{},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:       "malformed header - missing key value",
			headers:    http.Header{"Authorization": []string{"ApiKey"}},
			wantKey:    "",
			wantAnyErr: true,
		},
		{
			name:       "malformed header - wrong scheme",
			headers:    http.Header{"Authorization": []string{"Bearer sometoken"}},
			wantKey:    "",
			wantAnyErr: true,
		},
		{
			name:    "valid api key",
			headers: http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			wantKey: "my-secret-key",
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotErr := GetAPIKey(tt.headers)
			if gotKey != tt.wantKey {
				t.Errorf("key: got %q, want %q", gotKey, tt.wantKey)
			}
			if tt.wantErr != nil && gotErr != tt.wantErr {
				t.Errorf("error: got %v, want %v", gotErr, tt.wantErr)
			}
			if tt.wantAnyErr && gotErr == nil {
				t.Errorf("expected an error but got nil")
			}
			if !tt.wantAnyErr && tt.wantErr == nil && gotErr != nil {
				t.Errorf("unexpected error: %v", gotErr)
			}
		})
	}
}
