package hash

import (
	"testing"
)

func TestHmac(t *testing.T) {
	type args struct {
		data []byte
		key  []byte
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Happy path",
			args: args{
				data: []byte("plaintext"),
				key:  []byte("secret-key"),
			},
			want:    "59df6b41c364548f11368045d33d51688dc3af3794047198d103582598de89cf",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Hmac(tt.args.data, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("Hmac() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Hmac() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGenSalt(t *testing.T) {
	lastSalt := ""
	testCases := 100
	for i := 1; i < testCases+1; i++ {
		newSalt, err := GenSalt(10)
		if err != nil {
			t.Errorf("%d. Unexpected error: %s", i, err)
		}

		if lastSalt == newSalt {
			t.Errorf("%d. Should not equal:\nLastSalt: %s\nNewSalt: %s", i, lastSalt, newSalt)
		}

		if len(newSalt) != 20 {
			t.Errorf("%d, len(GenSalt(10) = %d, want %d)", i, len(newSalt), 20)
		}

		lastSalt = newSalt
	}
}

func TestSha512HasherHash(t *testing.T) {
	var hasher Hasher = &Sha512Hasher{
		pepper: []byte("secret-pepper"),
	}

	type args struct {
		plaintext string
		salt      string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Happy path",
			args: args{
				plaintext: "my-password",
				salt:      "random-salt",
			},
			want:    "11257fb35d0158d1f0bb68336fbc504dcf6040b207457c9035949579983648f76d630e001db6d3f339619581d7c5e323255adb87382a71c23e8d975f54da6258",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := hasher.Hash(tt.args.plaintext, tt.args.salt)
			if (err != nil) != tt.wantErr {
				t.Errorf("Sha512Hasher.Hash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Sha512Hasher.Hash() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSha512HasherVerify(t *testing.T) {
	hasher := &Sha512Hasher{pepper: []byte("secret-pepper")}
	wrongHasher := &Sha512Hasher{pepper: []byte("wrong-secret-pepper")}

	type args struct {
		plaintext string
		salt      string
		hash      string
	}
	tests := []struct {
		name    string
		hasher  Hasher
		args    args
		wantErr error
	}{
		{
			name:   "happy-path",
			hasher: hasher,
			args: args{
				plaintext: "my-password",
				salt:      "random-salt",
				hash:      "11257fb35d0158d1f0bb68336fbc504dcf6040b207457c9035949579983648f76d630e001db6d3f339619581d7c5e323255adb87382a71c23e8d975f54da6258",
			},
			wantErr: nil,
		},
		{
			name:   "sad-wrong-hash",
			hasher: hasher,
			args: args{
				plaintext: "my-password",
				salt:      "random-salt",
				hash:      "01257fb35d0158d1f0bb68336fbc504dcf6040b207457c9035949579983648f76d630e001db6d3f339619581d7c5e323255adb87382a71c23e8d975f54da6258",
			},
			wantErr: ErrHashMissmatch,
		},
		{
			name:   "sad-wrong-pepper",
			hasher: wrongHasher,
			args: args{
				plaintext: "my-password",
				salt:      "random-salt",
				hash:      "11257fb35d0158d1f0bb68336fbc504dcf6040b207457c9035949579983648f76d630e001db6d3f339619581d7c5e323255adb87382a71c23e8d975f54da6258",
			},
			wantErr: ErrHashMissmatch,
		},
		{
			name:   "sad-wrong-salt",
			hasher: hasher,
			args: args{
				plaintext: "my-password",
				salt:      "random-salt-wrong",
				hash:      "11257fb35d0158d1f0bb68336fbc504dcf6040b207457c9035949579983648f76d630e001db6d3f339619581d7c5e323255adb87382a71c23e8d975f54da6258",
			},
			wantErr: ErrHashMissmatch,
		},
		{
			name:   "sad-wrong-password",
			hasher: hasher,
			args: args{
				plaintext: "my-password-wrong",
				salt:      "random-salt",
				hash:      "11257fb35d0158d1f0bb68336fbc504dcf6040b207457c9035949579983648f76d630e001db6d3f339619581d7c5e323255adb87382a71c23e8d975f54da6258",
			},
			wantErr: ErrHashMissmatch,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.hasher.Verify(tt.args.plaintext, tt.args.salt, tt.args.hash)
			if err != tt.wantErr {
				t.Errorf("Sha512Hasher.Verify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
