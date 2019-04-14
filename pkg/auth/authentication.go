package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/CzarSimon/user-service/pkg/id"
	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// Common errors.
var (
	ErrInvalidTokenContent = errors.New("invalid token content")
	ErrInvalidToken        = errors.New("token is invalid")
	ErrExpiredToken        = errors.New("token has expired")
)

// Issuer interface for issuing auth tokens.
type Issuer interface {
	Issue(sub, role string) (string, error)
}

// Verifier interface for verifying tokens.
type Verifier interface {
	Verify(token string) (Token, error)
}

// Token body of a JWT token.
type Token struct {
	ID        string
	Subject   string
	Role      string
	CreatedAt time.Time
}

// newToken creates a new token with a unique ID.
func newToken(sub, role string) Token {
	return Token{
		ID:        id.New(),
		Subject:   sub,
		Role:      role,
		CreatedAt: time.Now().UTC(),
	}
}

// JWTCredentials credentials to issue and verify JWT tokens.
type JWTCredentials struct {
	Issuer string `json:"issuer"`
	Secret string `json:"secret"`
}

// ReadJWTCredentials reads JWTCredentials from an io.Reader.
func ReadJWTCredentials(r io.Reader) (JWTCredentials, error) {
	var credentials JWTCredentials
	err := json.NewDecoder(r).Decode(&credentials)
	return credentials, err
}

type customJWTClaims struct {
	Role string `json:"role"`
}

// JWTIssuer issuer implementation that issues JWT tokens.
type JWTIssuer struct {
	name     string
	signer   jose.Signer
	tokenAge time.Duration
}

// NewJWTIssuer creates a new JWTIssuer.
func NewJWTIssuer(creds JWTCredentials) *JWTIssuer {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte(creds.Secret)}, nil)
	if err != nil {
		log.Fatal("Failed to create jose.Signer. Error:", err)
	}

	return &JWTIssuer{
		name:     creds.Issuer,
		signer:   signer,
		tokenAge: 24 * time.Hour,
	}
}

// Issue issues a JWT token.
func (i *JWTIssuer) Issue(sub, role string) (string, error) {
	err := i.verifyTokenContent(sub, role)
	if err != nil {
		return "", err
	}

	token := newToken(sub, role)
	claims := jwt.Claims{
		Subject:   token.Subject,
		ID:        token.ID,
		Issuer:    i.name,
		NotBefore: jwt.NewNumericDate(token.CreatedAt.Add(-1 * time.Minute)),
		IssuedAt:  jwt.NewNumericDate(token.CreatedAt),
		Expiry:    jwt.NewNumericDate(token.CreatedAt.Add(i.tokenAge)),
	}
	customClaims := customJWTClaims{Role: role}
	return jwt.Signed(i.signer).Claims(claims).Claims(customClaims).CompactSerialize()
}

func (i *JWTIssuer) verifyTokenContent(sub, role string) error {
	if sub == "" {
		return ErrInvalidTokenContent
	}
	if role == "" {
		return ErrInvalidTokenContent
	}

	return nil
}

// JWTVerifier issuer implementation that issues JWT tokens.
type JWTVerifier struct {
	secret         []byte
	expectedIssuer string
	leeway         time.Duration
}

// NewJWTVerifier creates a new JWTVerifier.
func NewJWTVerifier(creds JWTCredentials, leeway time.Duration) *JWTVerifier {
	return &JWTVerifier{
		secret:         []byte(creds.Secret),
		expectedIssuer: creds.Issuer,
		leeway:         leeway,
	}
}

// Verify verifies a JWT token string.
func (v *JWTVerifier) Verify(rawToken string) (Token, error) {
	token, err := jwt.ParseSigned(rawToken)
	if err != nil {
		return Token{}, ErrInvalidToken
	}

	var claims jwt.Claims
	err = token.Claims(v.secret, &claims)
	if err != nil {
		fmt.Println(err)
		return Token{}, ErrInvalidToken
	}

	var customClaims customJWTClaims
	err = token.Claims(v.secret, &customClaims)
	if err != nil {
		return Token{}, ErrInvalidToken
	}

	err = v.validateClaims(claims)
	if err != nil {
		return Token{}, err
	}

	return getTokenFromClaims(claims, customClaims), nil
}

func (v *JWTVerifier) validateClaims(claims jwt.Claims) error {
	err := claims.ValidateWithLeeway(jwt.Expected{Issuer: v.expectedIssuer}, v.leeway)
	if err != nil {
		return ErrInvalidTokenContent
	}

	err = v.checkTokenExpiry(claims)
	if err != nil {
		return err
	}

	if claims.Subject == "" {
		return ErrInvalidTokenContent
	}

	if claims.ID == "" {
		return ErrInvalidTokenContent
	}

	return nil
}

func (v *JWTVerifier) checkTokenExpiry(claims jwt.Claims) error {
	earliestDate := claims.NotBefore.Time().UTC()
	latestDate := claims.Expiry.Time().Add(v.leeway).UTC()
	now := time.Now().UTC()

	if now.Before(earliestDate) {
		return ErrInvalidToken
	}

	if now.After(latestDate) {
		return ErrExpiredToken
	}

	return nil
}

func getTokenFromClaims(claims jwt.Claims, customClaims customJWTClaims) Token {
	return Token{
		ID:        claims.ID,
		Subject:   claims.Subject,
		Role:      customClaims.Role,
		CreatedAt: claims.IssuedAt.Time().UTC(),
	}
}
