package auth

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/CzarSimon/user-service/pkg/models"
	"github.com/stretchr/testify/assert"
)

func TestReadJWTCredentials(t *testing.T) {
	issuer := "test-issuer"
	secret, err := GenSalt(10)
	assert.NoError(t, err)
	credentialString := fmt.Sprintf("{\"issuer\":\"%s\",\"secret\":\"%s\"}", issuer, secret)
	buffer := bytes.NewReader([]byte(credentialString))

	creds, err := ReadJWTCredentials(buffer)
	assert.NoError(t, err)
	assert.Equal(t, issuer, creds.Issuer)
	assert.Equal(t, secret, creds.Secret)
}

func TestJWTIssueAndVerify(t *testing.T) {
	creds := JWTCredentials{
		Issuer: "issuer-name",
		Secret: "super-secret-token",
	}

	issuer := NewJWTIssuer(creds)
	verifier := NewJWTVerifier(creds, time.Minute)
	expiredIssuer := NewJWTIssuer(creds)
	expiredIssuer.tokenAge = -5 * time.Minute

	wrongIssuerCreds := JWTCredentials{
		Issuer: "wrong-issuer-name",
		Secret: "super-secret-token",
	}
	wrongIssuerVerfifier := NewJWTVerifier(wrongIssuerCreds, time.Minute)

	wrongSecretCreds := JWTCredentials{
		Issuer: "issuer-name",
		Secret: "super-secret-token-but-wrong",
	}
	wrongSecretVerfifier := NewJWTVerifier(wrongSecretCreds, time.Minute)

	type args struct {
		sub  string
		role string
	}
	tests := []struct {
		name                string
		issuer              Issuer
		verifier            Verifier
		args                args
		wantErr             error
		wantVerificationErr error
	}{
		{
			name:     "happy-path",
			issuer:   issuer,
			verifier: verifier,
			args: args{
				sub:  "user-id-1",
				role: models.UserRole,
			},
			wantErr:             nil,
			wantVerificationErr: nil,
		},
		{
			name:     "happy-path",
			issuer:   issuer,
			verifier: verifier,
			args: args{
				sub:  "user-id-2",
				role: models.AdminRole,
			},
			wantErr:             nil,
			wantVerificationErr: nil,
		},
		{
			name:   "sad-path-missing-id",
			issuer: issuer,
			args: args{
				role: models.UserRole,
			},
			wantErr: ErrInvalidTokenContent,
		},
		{
			name:   "sad-path-missing-role",
			issuer: issuer,
			args: args{
				sub: "user-id-2",
			},
			wantErr: ErrInvalidTokenContent,
		},
		{
			name:     "sad-path-expired-token",
			issuer:   expiredIssuer,
			verifier: verifier,
			args: args{
				sub:  "user-id-3",
				role: models.UserRole,
			},
			wantErr:             nil,
			wantVerificationErr: ErrExpiredToken,
		},
		{
			name:     "sad-path-wrong-issuer-name-in-verifier",
			issuer:   issuer,
			verifier: wrongIssuerVerfifier,
			args: args{
				sub:  "user-id-1",
				role: models.UserRole,
			},
			wantErr:             nil,
			wantVerificationErr: ErrInvalidTokenContent,
		},
		{
			name:     "sad-path-wrong-secret-name-in-verifier",
			issuer:   issuer,
			verifier: wrongSecretVerfifier,
			args: args{
				sub:  "user-id-1",
				role: models.UserRole,
			},
			wantErr:             nil,
			wantVerificationErr: ErrInvalidToken,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loopStartTime := time.Now().UTC().Add(-2 * time.Second)
			rawToken, err := tt.issuer.Issue(tt.args.sub, tt.args.role)
			if err != tt.wantErr {
				t.Errorf("JWTIssuer.Issue() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr != nil {
				return
			}

			if rawToken == "" {
				t.Errorf("JWTIssuer.Issue() token is empty, should not be")
				return
			}

			token, err := tt.verifier.Verify(rawToken)
			if err != tt.wantVerificationErr {
				t.Errorf("JWTVerifier.Verify() error = %v, wantVerificationErr %v", err, tt.wantVerificationErr)
				return
			}

			if tt.wantVerificationErr != nil {
				return
			}

			assert.Equal(t, tt.args.sub, token.Subject)
			assert.Equal(t, tt.args.role, token.Role)
			if loopStartTime.After(token.CreatedAt) {
				t.Errorf("JWTVerifier.Verify() token.CreatedAt = %v, Should be after: %v", token.CreatedAt, loopStartTime)
				return
			}
		})
	}
}
