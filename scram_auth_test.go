package scramauth

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"
)

func TestClientWriteReqMsg(t *testing.T) {
	auth := NewClientScramAuth(sha1.New, TlsUnique, []byte{'1', '2', '3'})
	var buf bytes.Buffer
	if err := auth.WriteReqMsg("hello-world", "yang-zhong", &buf); err != nil {
		t.Fatalf("write req msg error: %s", err.Error())
	}
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
	auth := NewServerScramAuth(sha1.New, TlsUnique, []byte{'1', '2', '3'})
	cnonce, _ := auth.scramAuth.gs2Header.Params.Val([]byte{'r'})
	input := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("p=tls-unique,a=hello-world,n=yang-zhong,r=%s", cnonce)))
	buf := bytes.NewBuffer([]byte(input))
	var res bytes.Buffer
	if err := auth.WriteChallengeMsg(buf, func(username []byte) (salt []byte, iter int, err error) {
		return []byte("12345678"), 4, nil
	}, &res); err != nil {
		t.Fatalf("write challenge msg error: %s", err.Error())
	}
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
	auth1 := NewClientScramAuth(sha256.New, TlsUnique, []byte{'1', '2', '3'})
	var rmb bytes.Buffer
	// genarate client first message
	if err := auth1.WriteReqMsg("hello-world", "yang-zhong", &rmb); err != nil {
		t.Fatalf("write req msg error: %s", err.Error())
	}
	auth2 := NewServerScramAuth(sha256.New, TlsUnique, []byte{'1', '2', '3'})
	// generate server first message
	var cmb bytes.Buffer
	if err := auth2.WriteChallengeMsg(&rmb, func(username []byte) (salt []byte, iter int, err error) {
		return []byte("12345678"), 4, nil
	}, &cmb); err != nil {
		t.Fatalf("write challenge msg error: %s", err.Error())
	}
	var crb bytes.Buffer
	// response
	if e := auth1.WriteResMsg(&cmb, "123456", &crb); e != nil {
		t.Fatalf("client response error: %s", e.Error())
	}
	saltedPassword := auth2.SaltedPassword([]byte("123456"), []byte("12345678"), 4)
	err := auth2.Verify(&crb, saltedPassword)
	if err != nil {
		t.Fatalf("server verify error: %s", err.Error())
	}
	var smb bytes.Buffer
	if err := auth2.WriteSignatureMsg(&crb, saltedPassword, &smb); err != nil {
		t.Fatalf("server signature error: %s", err.Error())
	}
	if err := auth1.Verify(&smb, "123456"); err != nil {
		t.Fatalf("client verify error: %s", err.Error())
	}
}
