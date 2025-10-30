package auth_test

import (
	"testing"
	"time"

	"github.com/crowspin/chirpy-server/internal/auth"
	"github.com/google/uuid"
)

func TestMakeJWT(t *testing.T) {
	uuids := make([]uuid.UUID, 2)
	uuids[0], _ = uuid.Parse("00000000-0000-0000-0000-000000000000")
	uuids[1], _ = uuid.Parse("00000000-0000-0000-0000-000000000001")

	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		userID       uuid.UUID
		encodeSecret string
		decodeSecret string
		expiresIn    time.Duration
		want         uuid.UUID
		wantErr      bool
	}{
		{
			name:         "positive test simple",
			userID:       uuids[0],
			encodeSecret: "egbduff",
			decodeSecret: "egbduff",
			expiresIn:    30 * time.Second,
			want:         uuids[0],
			wantErr:      false,
		},
		{
			name:         "expired tokens",
			userID:       uuids[0],
			encodeSecret: "egbduff",
			decodeSecret: "egbduff",
			expiresIn:    0 * time.Second,
			want:         uuids[0],
			wantErr:      true,
		},
		{
			name:         "wrong secret",
			userID:       uuids[0],
			encodeSecret: "egbduff",
			decodeSecret: "egbduasdfff",
			expiresIn:    30 * time.Second,
			want:         uuids[0],
			wantErr:      true,
		},
		{
			name:         "uuid mismatch",
			userID:       uuids[1],
			encodeSecret: "egbduff",
			decodeSecret: "egbduff",
			expiresIn:    30 * time.Second,
			want:         uuids[0],
			wantErr:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rv_a, err_a := auth.MakeJWT(tt.userID, tt.encodeSecret, tt.expiresIn)
			if err_a != nil {
				if !tt.wantErr {
					t.Errorf("auth.MakeJWT() err=%v", err_a)
				}
				return
			}
			rv_b, err_b := auth.ValidateJWT(rv_a, tt.decodeSecret)
			if err_b != nil {
				if !tt.wantErr {
					t.Errorf("auth.ValidateJWT() err=%v", err_b)
				}
				return
			}
			if rv_b != tt.want {
				if !tt.wantErr {
					t.Errorf("got %v, wanted %v", rv_b, tt.want)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("Functions succeeded unexpectedly")
			}
		})
	}
}
