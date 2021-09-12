package scramauth

import (
	"bytes"
	"fmt"
	"testing"
)

func TestMsgEncode(t *testing.T) {
	p := NewParams()
	p.Append(Param{Key: []byte{'n'}}, Param{}, Param{Key: []byte{'a'}, Val: []byte("hello")})
	var buf bytes.Buffer
	if err := NewEncoding().Encode(&buf, p); err != nil {
		t.Fatalf("encoding error: %s", err.Error())
	}
	if buf.String() != "n,,a=hello" {
		t.Fatalf("encoding encode error")
	}
}

func TestMsgDecode(t *testing.T) {
	buf := bytes.NewBuffer([]byte("n,,a=hello"))
	params := NewParams()
	if err := NewEncoding().Decode(buf, params); err != nil {
		t.Fatalf("encoding error: %s", err.Error())
	}
	p := params.All()
	if len(p) != 3 {
		t.Fatalf("encoding encode error")
	}
	if !bytes.Equal(p[0].Key, []byte{'n'}) || len(p[0].Val) != 0 ||
		len(p[1].Key) != 0 ||
		len(p[1].Val) != 0 ||
		!bytes.Equal(p[2].Key, []byte{'a'}) ||
		!bytes.Equal(p[2].Val, []byte("hello")) {
		fmt.Printf("input: %s\n%s - %s\n%s - %s\n%s - %s\n", buf.String(), p[0].Key, p[0].Val, p[1].Key, p[1].Val, p[2].Key, p[2].Val)
		t.Fatalf("encoding encode error")
	}
}
