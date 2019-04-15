package service

import (
	"testing"
	"time"

	"github.com/CzarSimon/user-service/pkg/auth"
	"github.com/CzarSimon/user-service/pkg/id"
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
			var svc UserService = &userSvc{
				hasher:          hasher,
				issuer:          issuer,
				userRepo:        tt.fields.userRepo,
				passwordChecker: &defaultChecker{minLength: 8},
				saltLength:      25,
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
			assert.NotEqual(t, "", got.User.Credentials.PasswordHash)
			assert.NotEqual(t, "", got.User.Credentials.Salt)

			token, err := verifier.Verify(got.Token)
			assert.NoError(t, err)
			assert.Equal(t, got.User.ID, token.Subject)
			assert.Equal(t, tt.want.user.Role, token.Role)

			tt.fields.userRepo.UnsetArgs()
		})
	}
}

func Test_userSvc_Login(t *testing.T) {
	user := models.User{
		ID:                id.New(),
		Email:             "mail@mail.com",
		Surname:           "Tester",
		MiddleAndLastName: "McTest",
		Role:              models.AdminRole,
		CreatedAt:         time.Now().UTC(),
		Credentials: models.Credentials{
			PasswordHash: "SCRYPT$32768$1$8$64$e741da717da8b684c6b512704e1dbcb999f38bf3b3ccf4729166b37da305e9770927c90ec6c6b1537d61a2a10d6a8295c23c46276e4d0e0019ed4c95fc238270",
			Salt:         "94f61dca8108138e98580d174a6eec493b4be51ca748109862",
		},
	}

	type fields struct {
		userRepo *repotest.MockUserRepo
	}
	type args struct {
		req models.LoginRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    models.User
		wantErr bool
	}{
		{
			name: "happy-path",
			fields: fields{
				userRepo: &repotest.MockUserRepo{
					FindByEmailUser: user,
				},
			},
			args: args{
				req: models.LoginRequest{
					Email:    "mail@mail.com",
					Password: "secret-drowssap",
				},
			},
			want:    user,
			wantErr: false,
		},
		{
			name: "sad-path-wrong-password",
			fields: fields{
				userRepo: &repotest.MockUserRepo{
					FindByEmailUser: user,
				},
			},
			args: args{
				req: models.LoginRequest{
					Email:    "mail@mail.com",
					Password: "wrong-password",
				},
			},
			want:    models.User{},
			wantErr: true,
		},
		{
			name: "sad-path-no-such-user",
			fields: fields{
				userRepo: &repotest.MockUserRepo{
					FindByEmailErr: repository.ErrNoSuchUser,
				},
			},
			args: args{
				req: models.LoginRequest{
					Email:    "mail@mail.com",
					Password: "secret-drowssap",
				},
			},
			want:    models.User{},
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
				saltLength:      25,
			}
			got, err := svc.Login(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("userSvc.Login() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			assert.NotEqual(t, "", got.Token)
			// assert.NotEqual(t, "", got.RefreshToken)
			assert.Equal(t, tt.want.ID, got.User.ID)
			assert.Equal(t, tt.want.Email, got.User.Email)
			assert.Equal(t, tt.want.Surname, got.User.Surname)
			assert.Equal(t, tt.want.MiddleAndLastName, got.User.MiddleAndLastName)
			assert.Equal(t, tt.want.Role, got.User.Role)
			assert.Equal(t, tt.want.CreatedAt, got.User.CreatedAt)

			token, err := verifier.Verify(got.Token)
			assert.NoError(t, err)
			assert.Equal(t, got.User.ID, token.Subject)
			assert.Equal(t, tt.want.Role, token.Role)
			tt.fields.userRepo.UnsetArgs()
		})
	}
}

func Test_userSvc_Find(t *testing.T) {
	user := models.User{
		ID:                id.New(),
		Email:             "mail@mail.com",
		Surname:           "Tester",
		MiddleAndLastName: "McTest",
		Role:              models.AdminRole,
		CreatedAt:         time.Now().UTC(),
		Credentials: models.Credentials{
			PasswordHash: "SCRYPT$32768$1$8$64$e741da717da8b684c6b512704e1dbcb999f38bf3b3ccf4729166b37da305e9770927c90ec6c6b1537d61a2a10d6a8295c23c46276e4d0e0019ed4c95fc238270",
			Salt:         "94f61dca8108138e98580d174a6eec493b4be51ca748109862",
		},
	}

	type fields struct {
		userRepo *repotest.MockUserRepo
	}
	tests := []struct {
		name    string
		fields  fields
		arg     string
		want    models.User
		wantErr bool
	}{
		{
			name: "happy-path",
			fields: fields{
				userRepo: &repotest.MockUserRepo{
					FindUser: user,
				},
			},
			arg:     user.ID,
			want:    user,
			wantErr: false,
		},
		{
			name: "sad-path-no-such-user",
			fields: fields{
				userRepo: &repotest.MockUserRepo{
					FindErr: repository.ErrNoSuchUser,
				},
			},
			arg:     id.New(),
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
				saltLength:      25,
			}
			got, err := svc.Find(tt.arg)
			if (err != nil) != tt.wantErr {
				t.Errorf("userSvc.Find() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			assert.Equal(t, tt.want.ID, got.ID)
			assert.Equal(t, tt.want.Email, got.Email)
			assert.Equal(t, tt.want.Surname, got.Surname)
			assert.Equal(t, tt.want.MiddleAndLastName, got.MiddleAndLastName)
			assert.Equal(t, tt.want.Role, got.Role)
			assert.Equal(t, tt.want.CreatedAt, got.CreatedAt)

			tt.fields.userRepo.UnsetArgs()
		})
	}
}
