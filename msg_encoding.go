package scramauth

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

func errOccured(offset int, char []byte) error {
	return fmt.Errorf("error on %d: unexpected char [%s]", offset, string(char))
}

const (
	statekey = iota
	stateval
)

type Param struct {
	Key []byte
	Val []byte
}

type Params struct {
	params []Param
}

func NewParams() *Params {
	return &Params{[]Param{}}
}

func NewParamsWith(params []Param) *Params {
	return &Params{params}
}

func (ps *Params) Val(k []byte) ([]byte, bool) {
	for _, p := range ps.params {
		if bytes.Equal(k, p.Key) {
			return p.Val, true
		}
	}
	return []byte{}, false
}

func (ps *Params) Append(p ...Param) {
	ps.params = append(ps.params, p...)
}

func (ps *Params) All() []Param {
	return ps.params
}

func (ps *Params) Len() int {
	return len(ps.params)
}

type Encoding struct {
	state  int
	offset int
}

func NewEncoding() *Encoding {
	return &Encoding{}
}

func (encoding *Encoding) read(b []byte, r io.Reader) error {
	if _, err := r.Read(b); err != nil {
		return err
	}
	encoding.offset = encoding.offset + 1
	return nil
}

func (encoding *Encoding) param(key, val []byte) Param {
	param := Param{Key: make([]byte, len(key)), Val: make([]byte, len(val))}
	copy(param.Key, key)
	copy(param.Val, val)
	return param
}

func (encoding *Encoding) Encode(w io.Writer, p *Params) (err error) {
	defer func() {
		if e := recover(); e != nil {
			err = e.(error)
		}
	}()
	write := func(w io.Writer, b []byte) {
		if err := FullWrite(w, b); err != nil {
			panic(err)
		}
	}
	params := p.All()
	l := len(params)
	for i, p := range params {
		write(w, p.Key)
		if len(p.Val) != 0 {
			write(w, []byte{'='})
		}
		write(w, p.Val)
		if i < l-1 {
			write(w, []byte{','})
		}
	}
	return
}

func (encoding *Encoding) Decode(r io.Reader, params *Params) error {
	b := make([]byte, 1)
	encoding.state = statekey
	encoding.offset = 0
	var key []byte
	var val []byte
	forward := 0
	pushFrag := func() {
		params.Append(encoding.param(key, val))
		key = []byte{}
		val = []byte{}
		forward = forward + 1
		encoding.state = statekey
	}
	for {
		if err := encoding.read(b, r); err != nil {
			if errors.Is(err, io.EOF) {
				params.Append(encoding.param(key, val))
				return nil
			}
			return err
		}
		switch encoding.state {
		case statekey:
			if b[0] >= 'a' && b[0] <= 'z' || b[0] == '_' || b[0] == '-' {
				key = append(key, b[0])
			} else if b[0] == '=' {
				encoding.state = stateval
			} else if b[0] == ',' {
				pushFrag()
			} else {
				return errOccured(encoding.offset, b)
			}
		case stateval:
			if b[0] != ',' {
				val = append(val, b[0])
				continue
			}
			pushFrag()
		}
	}
}
