package scramauth

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"testing"
)

func TestClientStart(t *testing.T) {
	auth := NewClientScramAuth(TlsUnique, sha1.New)
	r := auth.Request("hello-world", "yang-zhong")
	var buf bytes.Buffer
	io.Copy(&buf, r)
	cnonce, _ := auth.scramAuth.gs2Header.Params.Val([]byte{'r'})
	rsc := fmt.Sprintf("p=tls-unique,a=hello-world,n=yang-zhong,r=%s", cnonce)
	res := base64.StdEncoding.EncodeToString([]byte(rsc))
	if res != buf.String() {
		t.Logf("\n%s\n%s\n", res, buf.String())
		rr, _ := base64.StdEncoding.DecodeString(buf.String())
		t.Logf("\n%s\n%s\n", rsc, rr)
		t.Fatalf("client start error")
	}
}

func TestServerChallenge(t *testing.T) {
	auth := NewServerScramAuth(sha1.New)
	cnonce, _ := auth.scramAuth.gs2Header.Params.Val([]byte{'r'})
	input := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("p=tls-unique,a=hello-world,n=yang-zhong,r=%s", cnonce)))
	buf := bytes.NewBuffer([]byte(input))
	r, err := auth.Challenge(buf, func(username []byte) (salt []byte, iter int, err error) {
		return []byte("12345678"), 4, nil
	})
	if err != nil {
		t.Fatalf("challenge error")
	}
	var res bytes.Buffer
	io.Copy(&res, r)
	rr := fmt.Sprintf("r=%s,s=%s,i=%d", auth.scramAuth.sNonce, auth.scramAuth.salt, auth.scramAuth.iter)
	rrr := base64.StdEncoding.EncodeToString([]byte(rr))
	if res.String() != rrr {
		rrrr, err := base64.StdEncoding.DecodeString(res.String())
		if err == nil {
			t.Logf("%s - %s\n", rrrr, rr)
		}
		t.Fatalf("server challenge error")
	}
}

func TestAuth(t *testing.T) {
	auth1 := NewClientScramAuth(TlsUnique, sha256.New)
	// genarate client first message
	r := auth1.Request("hello-world", "yang-zhong")
	auth2 := NewServerScramAuth(sha256.New)
	// generate server first message
	cr, _ := auth2.Challenge(r, func(username []byte) (salt []byte, iter int, err error) {
		return []byte("12345678"), 4, nil
	})
	// response
	r, e := auth1.Response(cr, "123456")
	if e != nil {
		t.Fatalf("client response error: %s", e.Error())
	}
	saltedPassword := auth2.SaltedPassword([]byte("123456"), []byte("12345678"), 4)
	err := auth2.Verify(r, saltedPassword)
	if err != nil {
		t.Fatalf("server verify error: %s", err.Error())
	}
	r, err = auth2.Signature(r, saltedPassword)
	if err != nil {
		t.Fatalf("server signature error: %s", err.Error())
	}
	if err := auth1.Verify(r, "123456"); err != nil {
		t.Fatalf("client verify error: %s", err.Error())
	}
}
