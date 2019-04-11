package hash

import "testing"

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
			name: "Test 1",
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
