package scramauth

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"testing"
)

func TestEncode(t *testing.T) {
	p := NewParams()
	p.Append([]Param{
		{Key: []byte{'n'}, Val: []byte("helloworld")},
		{Key: []byte{'r'}, Val: []byte("123456")}}...)

	header := Gs2Header{Authzid: []byte("123456"), CB: TlsUnique, Params: p}

	var buf bytes.Buffer
	header.Encode(&buf)
	res := base64.StdEncoding.EncodeToString([]byte("p=tls-unique,a=123456,n=helloworld,r=123456"))
	if buf.String() != res {
		fmt.Printf("%s - %s\n", buf.String(), res)
		t.Fatalf("encode gs2 header error")
	}
}

func TestDecode(t *testing.T) {
	str := "cD10bHMtdW5pcXVlLGE9MTIzNDU2LG49aGVsbG93b3JsZCxyPTEyMzQ1Ng=="
	header := Gs2Header{}
	buf1 := bytes.NewBuffer([]byte(str))
	if err := header.Decode(buf1); err != nil {
		t.Fatalf(err.Error())
	}
	var buf2 bytes.Buffer
	header.Encode(&buf2)
	p := header.Params.All()
	if string(header.Authzid) != "123456" ||
		CB(string(header.CB)) != TlsUnique ||
		header.Params.Len() != 2 ||
		string(p[0].Key) != "n" ||
		string(p[0].Val) != "helloworld" ||
		string(p[1].Key) != "r" ||
		string(p[1].Val) != "123456" {

		t.Fatalf("decode gs2 header error")
	}
}
