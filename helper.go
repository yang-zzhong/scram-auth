package scramauth

import (
	"hash"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

func FullWrite(w io.Writer, b []byte) error {
	total := len(b)
	wrote := 0
	for wrote < total {
		l, err := w.Write(b)
		if err != nil {
			return err
		}
		wrote = wrote + l
	}
	return nil
}

func SaltPassword(h func() hash.Hash, password, salt []byte, iter int) []byte {
	return pbkdf2.Key(password, salt, iter, h().Size(), h)
}
