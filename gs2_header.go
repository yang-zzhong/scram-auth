package scramauth

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
)

type CB string

const (
	TlsUnique          = CB("tls-unique")
	TlsServerEndPoint  = CB("tls-server-end-point")
	TlsUniqueForTelnet = CB("tls-unqiue-for-telnet")
	None               = CB("none")
	Unset              = CB("unset")
)

// UTF8-1-safe    = %x01-2B / %x2D-3C / %x3E-7F
//
//	;; As UTF8-1 in RFC 3629 except
//	;; NUL, "=", and ",".
//
// UTF8-2         = <as defined in RFC 3629 (STD 63)>
// UTF8-3         = <as defined in RFC 3629 (STD 63)>
// UTF8-4         = <as defined in RFC 3629 (STD 63)>
// UTF8-char-safe = UTF8-1-safe / UTF8-2 / UTF8-3 / UTF8-4
//
// saslname       = 1*(UTF8-char-safe / "=2C" / "=3D")
// gs2-authzid    = "a=" saslname
//
//	;; GS2 has to transport an authzid since
//	;; the GSS-API has no equivalent
//
// gs2-nonstd-flag = "F"
//
//	;; "F" means the mechanism is not a
//	;; standard GSS-API mechanism in that the
//	;; RFC 2743, Section 3.1 header was missing
//
// cb-name         = 1*(ALPHA / DIGIT / "." / "-")
//
//	;; See RFC 5056, Section 7.
//
// gs2-cb-flag     = ("p=" cb-name) / "n" / "y"
//
//	;; GS2 channel binding (CB) flag
//	;; "p" -> client supports and used CB
//	;; "n" -> client does not support CB
//	;; "y" -> client supports CB, thinks the server
//	;;           does not
//
// gs2-header = [gs2-nonstd-flag ","] gs2-cb-flag "," [gs2-authzid] ","
//
//	;; The GS2 header is gs2-header.
type Gs2Header struct {
	CB      CB
	Authzid []byte
	Params  *Params
}

func (header *Gs2Header) Encode(w io.Writer) error {
	p := NewParams()
	switch header.CB {
	case None:
		p.Append(Param{Key: []byte{'n'}})
	case TlsUnique:
		p.Append(Param{Key: []byte{'p'}, Val: []byte(TlsUnique)})
	}
	if len(header.Authzid) != 0 {
		p.Append(Param{Key: []byte{'a'}, Val: []byte(header.Authzid)})
	} else {
		p.Append(Param{})
	}
	p.Append(header.Params.All()...)
	var buf bytes.Buffer
	if err := NewEncoding().Encode(&buf, p); err != nil {
		return err
	}
	return FullWrite(w, []byte(base64.StdEncoding.EncodeToString(buf.Bytes())))
}

func (header *Gs2Header) Decode(r io.Reader) error {
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, base64.NewDecoder(base64.StdEncoding, r)); err != nil {
		return err
	}
	params := NewParams()
	if err := NewEncoding().Decode(&buf, params); err != nil {
		return err
	}
	p := params.All()
	if len(p) < 2 {
		return errors.New("invalid gs2 header")
	}
	switch string(p[0].Key) {
	case "p":
		header.CB = CB(string(p[0].Val))
	case "n", "y":
		header.CB = None
	default:
		return errors.New("invalid gs2 headder")
	}
	// if !bytes.Equal(p[1].Key, []byte{'a'}) {
	// 	return errors.New("invalid gs2 headder")
	// }
	header.Authzid = p[1].Val
	header.Params = NewParams()
	header.Params.Append(p[2:]...)
	return nil
}
