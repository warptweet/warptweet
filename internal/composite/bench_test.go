package composite

import (
	"testing"
)

func BenchmarkCompositeSign(b *testing.B) {
	key, err := Generate()
	if err != nil {
		b.Fatal(err)
	}
	msg := []byte("WarpTweet exchange hash")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := key.Sign(msg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCompositeVerify(b *testing.B) {
	key, err := Generate()
	if err != nil {
		b.Fatal(err)
	}
	pub, err := key.Public()
	if err != nil {
		b.Fatal(err)
	}
	msg := []byte("WarpTweet exchange hash")
	sig, err := key.Sign(msg)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := Verify(pub, msg, sig); err != nil {
			b.Fatal(err)
		}
	}
}
