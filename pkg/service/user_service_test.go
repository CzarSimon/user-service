package service

import (
	"testing"
	"time"

	"github.com/CzarSimon/user-service/pkg/auth"
	"github.com/CzarSimon/user-service/pkg/models"
	"github.com/CzarSimon/user-service/pkg/repository"
	"github.com/CzarSimon/user-service/pkg/repository/repotest"
	"github.com/stretchr/testify/assert"
)

var hasher = auth.NewHasher("secret-pepper")

var issuer = auth.NewJWTIssuer(auth.JWTCredentials{
	Issuer: "user-service-name",
	Secret: "jwt-secret",
})

var verifier = auth.NewJWTVerifier(auth.JWTCredentials{
	Issuer: "user-service-name",
	Secret: "jwt-secret",
}, time.Minute)

func Test_userSvc_SignUp(t *testing.T) {
	okRepo := &repotest.MockUserRepo{
		FindByEmailErr: repository.ErrNoSuchUser,
	}

	type fields struct {
		userRepo *repotest.MockUserRepo
	}
	type args struct {
		req models.SignupRequest
	}
	type want struct {
		user                models.User
		saveUserInvocations int
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    want
		wantErr bool
	}{
		{
			name: "happy-path",
			fields: fields{
				userRepo: okRepo,
			},
			args: args{
				req: models.SignupRequest{
					Email:             "mail@mail.com",
					Password:          "secret-drowssap",
					RepeatPassword:    "secret-drowssap",
					Surname:           "Tester",
					MiddleAndLastName: "McTest",
				},
			},
			want: want{
				user: models.User{
					Email:             "mail@mail.com",
					Surname:           "Tester",
					MiddleAndLastName: "McTest",
					Role:              models.UserRole,
				},
				saveUserInvocations: 1,
			},
			wantErr: false,
		},
		{
			name: "sad-path-already-existing-user",
			fields: fields{
				userRepo: &repotest.MockUserRepo{},
			},
			args: args{
				req: models.SignupRequest{
					Email:             "mail@mail.com",
					Password:          "secret-drowssap",
					RepeatPassword:    "secret-drowssap",
					Surname:           "Tester",
					MiddleAndLastName: "McTest",
				},
			},
			want: want{
				user:                models.User{},
				saveUserInvocations: 0,
			},
			wantErr: true,
		},
		{
			name: "sad-path-too-short-password",
			fields: fields{
				userRepo: okRepo,
			},
			args: args{
				req: models.SignupRequest{
					Email:             "mail@mail.com",
					Password:          "short",
					RepeatPassword:    "short",
					Surname:           "Tester",
					MiddleAndLastName: "McTest",
				},
			},
			want: want{
				user:                models.User{},
				saveUserInvocations: 0,
			},
			wantErr: true,
		},
		{
			name: "sad-path-password-missmatch",
			fields: fields{
				userRepo: okRepo,
			},
			args: args{
				req: models.SignupRequest{
					Email:             "mail@mail.com",
					Password:          "secret-drowssap",
					RepeatPassword:    "secret+drowssap",
					Surname:           "Tester",
					MiddleAndLastName: "McTest",
				},
			},
			want: want{
				user:                models.User{},
				saveUserInvocations: 0,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &userSvc{
				hasher:          hasher,
				issuer:          issuer,
				userRepo:        tt.fields.userRepo,
				passwordChecker: &defaultChecker{minLength: 8},
			}
			got, err := svc.SignUp(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("userSvc.SignUp() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			assert.NotEqual(t, "", got.Token)
			// assert.NotEqual(t, "", got.RefreshToken)
			assert.Equal(t, tt.want.user.Email, got.User.Email)
			assert.Equal(t, tt.want.user.Surname, got.User.Surname)
			assert.Equal(t, tt.want.user.MiddleAndLastName, got.User.MiddleAndLastName)
			assert.Equal(t, tt.want.user.Role, got.User.Role)
			assert.Equal(t, tt.want.saveUserInvocations, tt.fields.userRepo.SaveInvocations)

			token, err := verifier.Verify(got.Token)
			assert.NoError(t, err)
			assert.Equal(t, got.User.ID, token.Subject)
			assert.Equal(t, tt.want.user.Role, token.Role)

			tt.fields.userRepo.UnsetArgs()
		})
	}
}
