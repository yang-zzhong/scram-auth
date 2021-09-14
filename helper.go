package scramauth

import (
	"io"
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
