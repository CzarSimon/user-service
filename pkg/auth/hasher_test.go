package auth

import (
	"crypto/sha512"
	"testing"
)

// HMAC-SHA256(my-password-random-salt, secret-pepper) = 8d3410761bba854a10ee99277d7f8851d2dc18dc5273b1933369e898675c8264

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

func TestScrypHasherHash(t *testing.T) {
	var hasher Hasher = &ScryptHasher{
		pepper: []byte("secret-pepper"),
		cost:   1024,
		p:      1,
		r:      8,
		keyLen: 64,
	}
	fullCostHasher := NewHasher("secret-pepper")

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
			want:    "SCRYPT$1024$1$8$64$65fe22a1e99bdf22bab227fca3c06be019e5ee9aee6f462d7c07626dca7bf41c4ee60cc15d575471c3a407f16b8bf2fb096a1a3a336bdafcc98accdb6e11d626",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := hasher.Hash(tt.args.plaintext, tt.args.salt)
			if (err != nil) != tt.wantErr {
				t.Errorf("ScryptHasher.Hash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ScryptHasher.Hash() = %v, want %v", got, tt.want)
			}
		})
	}
	hash1, err := hasher.Hash("other-secret-password", "long-random-salt")
	if err != nil {
		t.Errorf("ScryptHasher.Hash() unexpected error = %v", err)
	}

	hash2, err := fullCostHasher.Hash("other-secret-password", "long-random-salt")
	if err != nil {
		t.Errorf("ScryptHasher.Hash() unexpected error = %v", err)
	}

	if hash1 == hash2 {
		t.Errorf("ScryptHasher.Hash() generated same hash with different costs 1024 = %s, 32768 = %s", hash1, hash2)
	}
}

func TestScryptHasherVerify(t *testing.T) {
	hasher := &ScryptHasher{
		pepper: []byte("secret-pepper"),
		cost:   1024,
		p:      1,
		r:      8,
		keyLen: 64,
	}
	wrongPepperHasher := &ScryptHasher{
		pepper: []byte("wrong-secret-pepper"),
		cost:   1024,
		p:      1,
		r:      8,
		keyLen: 64,
	}
	fullCostHasher := NewHasher("secret-pepper")

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
			name:   "happy-path-same-params",
			hasher: hasher,
			args: args{
				plaintext: "my-password",
				salt:      "random-salt",
				hash:      "SCRYPT$1024$1$8$64$65fe22a1e99bdf22bab227fca3c06be019e5ee9aee6f462d7c07626dca7bf41c4ee60cc15d575471c3a407f16b8bf2fb096a1a3a336bdafcc98accdb6e11d626",
			},
			wantErr: nil,
		},
		{
			name:   "happy-path-full-cost-hasher",
			hasher: fullCostHasher,
			args: args{
				plaintext: "my-password",
				salt:      "random-salt",
				hash:      "SCRYPT$1024$1$8$64$65fe22a1e99bdf22bab227fca3c06be019e5ee9aee6f462d7c07626dca7bf41c4ee60cc15d575471c3a407f16b8bf2fb096a1a3a336bdafcc98accdb6e11d626",
			},
			wantErr: nil,
		},
		{
			name:   "sad-wrong-hash",
			hasher: hasher,
			args: args{
				plaintext: "my-password",
				salt:      "random-salt",
				hash:      "SCRYPT$1024$1$8$64$05fe22a1e99bdf22bab227fca3c06be019e5ee9aee6f462d7c07626dca7bf41c4ee60cc15d575471c3a407f16b8bf2fb096a1a3a336bdafcc98accdb6e11d626",
			},
			wantErr: ErrHashMissmatch,
		},
		{
			name:   "sad-wrong-salt",
			hasher: hasher,
			args: args{
				plaintext: "my-password",
				salt:      "random-salt-wrong",
				hash:      "SCRYPT$1024$1$8$64$65fe22a1e99bdf22bab227fca3c06be019e5ee9aee6f462d7c07626dca7bf41c4ee60cc15d575471c3a407f16b8bf2fb096a1a3a336bdafcc98accdb6e11d626",
			},
			wantErr: ErrHashMissmatch,
		},
		{
			name:   "sad-wrong-password",
			hasher: hasher,
			args: args{
				plaintext: "my-password-wrong",
				salt:      "random-salt",
				hash:      "SCRYPT$1024$1$8$64$65fe22a1e99bdf22bab227fca3c06be019e5ee9aee6f462d7c07626dca7bf41c4ee60cc15d575471c3a407f16b8bf2fb096a1a3a336bdafcc98accdb6e11d626",
			},
			wantErr: ErrHashMissmatch,
		},
		{
			name:   "sad-wrong-pepper",
			hasher: wrongPepperHasher,
			args: args{
				plaintext: "my-password",
				salt:      "random-salt",
				hash:      "SCRYPT$1024$1$8$64$65fe22a1e99bdf22bab227fca3c06be019e5ee9aee6f462d7c07626dca7bf41c4ee60cc15d575471c3a407f16b8bf2fb096a1a3a336bdafcc98accdb6e11d626",
			},
			wantErr: ErrHashMissmatch,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.hasher.Verify(tt.args.plaintext, tt.args.salt, tt.args.hash)
			if err != tt.wantErr {
				t.Errorf("ScryptHasher.Verify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestPBKDF2HasherHash(t *testing.T) {
	var hasher Hasher = &PBKDF2Hasher{
		pepper:     []byte("secret-pepper"),
		iterations: 100,
		keyLen:     64,
		hashFn:     sha512.New,
	}
	doubleIterationsHasher := &PBKDF2Hasher{
		pepper:     []byte("secret-pepper"),
		iterations: 200,
		keyLen:     64,
		hashFn:     sha512.New,
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
			want:    "PBKDF2$100$64$66d2f4812bd6a27acc9c27b7d590097654612a2d2189d88cc4272055bfcdfe0d864e26494a252ad6cdaa37c78d3662d4bae7dfa410d71884dc6896667e008e6f",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := hasher.Hash(tt.args.plaintext, tt.args.salt)
			if (err != nil) != tt.wantErr {
				t.Errorf("PBKDF2Hasher.Hash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("PBKDF2Hasher.Hash() = %v, want %v", got, tt.want)
			}
		})
	}

	hash1, err := hasher.Hash("other-secret-password", "long-random-salt")
	if err != nil {
		t.Errorf("PBKDF2Hasher.Hash() unexpected error = %v", err)
	}

	hash2, err := doubleIterationsHasher.Hash("other-secret-password", "long-random-salt")
	if err != nil {
		t.Errorf("PBKDF2Hasher.Hash() unexpected error = %v", err)
	}

	if hash1 == hash2 {
		t.Errorf("PBKDF2Hasher.Hash() generated same hash with different iterations 100 = %s, 200 = %s", hash1, hash2)
	}
}

func TestPBKDF2HasherVerify(t *testing.T) {
	hasher := &PBKDF2Hasher{
		pepper:     []byte("secret-pepper"),
		iterations: 100,
		keyLen:     64,
		hashFn:     sha512.New,
	}
	wrongPepperHasher := &PBKDF2Hasher{
		pepper:     []byte("wrong-secret-pepper"),
		iterations: 100,
		keyLen:     64,
		hashFn:     sha512.New,
	}
	doubleIterationsHasher := &PBKDF2Hasher{
		pepper:     []byte("secret-pepper"),
		iterations: 200,
		keyLen:     64,
		hashFn:     sha512.New,
	}

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
			name:   "happy-path-same-params",
			hasher: hasher,
			args: args{
				plaintext: "my-password",
				salt:      "random-salt",
				hash:      "PBKDF2$100$64$66d2f4812bd6a27acc9c27b7d590097654612a2d2189d88cc4272055bfcdfe0d864e26494a252ad6cdaa37c78d3662d4bae7dfa410d71884dc6896667e008e6f",
			},
			wantErr: nil,
		},
		{
			name:   "happy-path-double-iterations-hasher",
			hasher: doubleIterationsHasher,
			args: args{
				plaintext: "my-password",
				salt:      "random-salt",
				hash:      "PBKDF2$100$64$66d2f4812bd6a27acc9c27b7d590097654612a2d2189d88cc4272055bfcdfe0d864e26494a252ad6cdaa37c78d3662d4bae7dfa410d71884dc6896667e008e6f",
			},
			wantErr: nil,
		},
		{
			name:   "sad-wrong-hash",
			hasher: hasher,
			args: args{
				plaintext: "my-password",
				salt:      "random-salt",
				hash:      "PBKDF2$100$64$06d2f4812bd6a27acc9c27b7d590097654612a2d2189d88cc4272055bfcdfe0d864e26494a252ad6cdaa37c78d3662d4bae7dfa410d71884dc6896667e008e6f",
			},
			wantErr: ErrHashMissmatch,
		},
		{
			name:   "sad-wrong-salt",
			hasher: hasher,
			args: args{
				plaintext: "my-password",
				salt:      "random-salt-wrong",
				hash:      "PBKDF2$100$64$06d2f4812bd6a27acc9c27b7d590097654612a2d2189d88cc4272055bfcdfe0d864e26494a252ad6cdaa37c78d3662d4bae7dfa410d71884dc6896667e008e6f",
			},
			wantErr: ErrHashMissmatch,
		},
		{
			name:   "sad-wrong-password",
			hasher: hasher,
			args: args{
				plaintext: "my-password-wrong",
				salt:      "random-salt",
				hash:      "PBKDF2$100$64$06d2f4812bd6a27acc9c27b7d590097654612a2d2189d88cc4272055bfcdfe0d864e26494a252ad6cdaa37c78d3662d4bae7dfa410d71884dc6896667e008e6f",
			},
			wantErr: ErrHashMissmatch,
		},
		{
			name:   "sad-wrong-pepper",
			hasher: wrongPepperHasher,
			args: args{
				plaintext: "my-password",
				salt:      "random-salt",
				hash:      "PBKDF2$100$64$66d2f4812bd6a27acc9c27b7d590097654612a2d2189d88cc4272055bfcdfe0d864e26494a252ad6cdaa37c78d3662d4bae7dfa410d71884dc6896667e008e6f",
			},
			wantErr: ErrHashMissmatch,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.hasher.Verify(tt.args.plaintext, tt.args.salt, tt.args.hash)
			if err != tt.wantErr {
				t.Errorf("PBKDF2Hasher.Verify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
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
