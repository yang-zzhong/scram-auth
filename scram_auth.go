package scramauth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"hash"
	"io"
	"math"
	"math/rand"
	"strconv"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
)

const (
	SCRAM_SHA_1         = "SCRAM-SHA-1"
	SCRAM_SHA_1_PLUS    = "SCRAM-SHA-1-PLUS"
	SCRAM_SHA_256       = "SCRAM-SHA-256"
	SCRAM_SHA_256_PLUS  = "SCRAM-SHA-256-PLUS"
	SCRAM_SHA_512       = "SCRAM-SHA-512"
	SCRAM_SHA_512_PLUS  = "SCRAM-SHA-512-PLUS"
	SCRAM_SHA_224       = "SCRAM-SHA-224"
	SCRAM_SHA_224_PLUS  = "SCRAM-SHA-224-PLUS"
	SCRAM_SHA_384       = "SCRAM-SHA-384"
	SCRAM_SHA_384_PLUS  = "SCRAM-SHA-384-PLUS"
	SCRAM_SHA3_224      = "SCRAM-SHA3-224"
	SCRAM_SHA3_224_PLUS = "SCRAM-SHA3-224-PLUS"
	SCRAM_SHA3_256      = "SCRAM-SHA3-256"
	SCRAM_SHA3_256_PLUS = "SCRAM-SHA3-256-PLUS"
	SCRAM_SHA3_384      = "SCRAM-SHA3-384"
	SCRAM_SHA3_384_PLUS = "SCRAM-SHA3-384-PLUS"
	SCRAM_SHA3_512      = "SCRAM-SHA3-512"
	SCRAM_SHA3_512_PLUS = "SCRAM-SHA3-512-PLUS"
)

type ClientScramAuth struct {
	scramAuth *scramAuth
}

func NewClientScramAuth(hashBuild func() hash.Hash, channelBinding CB, cbData []byte) *ClientScramAuth {
	return &ClientScramAuth{
		scramAuth: &scramAuth{
			channelBinding: channelBinding,
			cbData:         cbData,
			hashBuild:      hashBuild,
			gs2Header: Gs2Header{
				Params: NewParams()}}}
}

func (client *ClientScramAuth) WriteReqMsg(authzid, username string, w io.Writer) error {
	return client.scramAuth.clientRequest(authzid, username, w)
}

func (client *ClientScramAuth) WriteResMsg(r io.Reader, password string, w io.Writer) error {
	return client.scramAuth.clientResponse(r, password, w)
}

func (client *ClientScramAuth) Verify(r io.Reader, password string) error {
	return client.scramAuth.clientVerify(r, password)
}

type ServerScramAuth struct {
	scramAuth *scramAuth
}

func NewServerScramAuth(hashBuild func() hash.Hash, channelBinding CB, cbData []byte) *ServerScramAuth {
	return &ServerScramAuth{
		scramAuth: &scramAuth{
			channelBinding: channelBinding,
			cbData:         cbData,
			hashBuild:      hashBuild,
			gs2Header: Gs2Header{
				Params: NewParams()}}}
}

type FindSaltIter func(username []byte) (salt []byte, iter int, err error)

func (server *ServerScramAuth) WriteChallengeMsg(r io.Reader, finder FindSaltIter, w io.Writer) error {
	return server.scramAuth.serverChallenge(r, finder, w)
}

func (server *ServerScramAuth) WriteSignatureMsg(r io.Reader, saltedPassword []byte, w io.Writer) error {
	return server.scramAuth.serverSignature(r, saltedPassword, w)
}

func (server *ServerScramAuth) Gs2Header() Gs2Header {
	return server.scramAuth.gs2Header
}

func (server *ServerScramAuth) Verify(r io.Reader, storedKey []byte) error {
	return server.scramAuth.serverVerify(r, storedKey)
}

func (server *ServerScramAuth) SaltedPassword(password, salt []byte, iter int) []byte {
	return server.scramAuth.saltedPassword(password, salt, iter)
}

type scramAuth struct {
	hashBuild      func() hash.Hash
	channelBinding CB
	cbData         []byte

	gs2Header    Gs2Header
	sNonce, salt []byte
	iter         int
}

func (sa *scramAuth) clientRequest(authzid, username string, w io.Writer) error {
	p := NewParams()
	p.Append([]Param{
		{Key: []byte("n"), Val: []byte(username)},
		{Key: []byte("r"), Val: sa.genNonce(16)},
	}...)
	sa.gs2Header = Gs2Header{
		Authzid: []byte(authzid),
		CB:      sa.channelBinding,
		Params:  p}
	return sa.gs2Header.Encode(w)
}

func (sa *scramAuth) serverChallenge(r io.Reader, find FindSaltIter, w io.Writer) error {
	if err := sa.gs2Header.Decode(r); err != nil {
		return err
	}
	username, ok := sa.gs2Header.Params.Val([]byte("n"))
	if !ok {
		return errors.New("no username found")
	}
	var err error
	sa.salt, sa.iter, err = find(username)
	if err != nil {
		return err
	}
	sa.sNonce = sa.genNonce(16)
	return FullWrite(w, []byte(base64.StdEncoding.EncodeToString(sa.challengeMsg())))
}

func (sa *scramAuth) challengeMsg() []byte {
	ps := NewParams()
	ps.Append([]Param{
		{Key: []byte{'r'}, Val: []byte(sa.sNonce)},
		{Key: []byte{'s'}, Val: sa.salt},
		{Key: []byte{'i'}, Val: []byte(strconv.Itoa(sa.iter))},
	}...)
	var buf bytes.Buffer
	NewEncoding().Encode(&buf, ps)
	return buf.Bytes()
}

// ClientKey       := HMAC(SaltedPassword, "Client Key")
// StoredKey       := H(ClientKey)
// AuthMessage     := client-first-message-bare + "," +
//
//	server-first-message + "," +
//	client-final-message-without-proof
//
// ClientSignature := HMAC(StoredKey, AuthMessage)
// ClientProof     := ClientKey XOR ClientSignature
// ServerKey       := HMAC(SaltedPassword, "Server Key")
// ServerSignature := HMAC(ServerKey, AuthMessage)
func (sa *scramAuth) clientResponse(r io.Reader, password string, w io.Writer) error {
	var buf bytes.Buffer
	_, err := io.Copy(&buf, base64.NewDecoder(base64.StdEncoding, r))
	if err != nil {
		return err
	}
	sa.sNonce, sa.salt, sa.iter, err = sa.rsi(buf.String())
	if err != nil {
		return err
	}
	authMsg, err := sa.authMsg()
	if err != nil {
		return err
	}
	saltedPassword := sa.saltedPassword([]byte(password), []byte(sa.salt), sa.iter)
	clientKey := sa.hmac(saltedPassword, []byte("Client Key"))
	storedKey := sa.hash(clientKey)
	signature := sa.hmac(storedKey, authMsg)
	if err != nil {
		return err
	}
	clientProof := sa.xor(clientKey, signature)
	out, err := sa.clientFinalMsgWithoutProof(sa.sNonce)
	if err != nil {
		return err
	}
	out = append(out, ",p="...)
	out = append(out, []byte(base64.StdEncoding.EncodeToString(clientProof))...)
	_, err = w.Write(out)
	return err
}

func (sa *scramAuth) authMsg() ([]byte, error) {
	fmb, err := sa.clientFirstMsgBare()
	if err != nil {
		return []byte{}, err
	}
	fmwp, err := sa.clientFinalMsgWithoutProof(sa.sNonce)
	if err != nil {
		return []byte{}, err
	}
	var buf bytes.Buffer
	p := NewParams()
	p.Append([]Param{
		{Key: []byte(fmb)},
		{Key: []byte(sa.challengeMsg())},
		{Key: []byte(fmwp)},
	}...)
	err = NewEncoding().Encode(&buf, p)
	return buf.Bytes(), err
}

func (sa *scramAuth) rsi(msg string) (r, s []byte, i int, err error) {
	rd := bytes.NewBuffer([]byte(msg))
	p := NewParams()
	if err = NewEncoding().Decode(rd, p); err != nil {
		return
	}
	if len(p.All()) < 3 {
		err = errors.New("incorrect challenge format")
		return
	}
	var ok bool
	if r, ok = p.Val([]byte{'r'}); !ok {
		err = errors.New("incorrect challenge format")
		return
	}
	if s, ok = p.Val([]byte{'s'}); !ok {
		err = errors.New("incorrect challenge format")
		return
	}
	var ti []byte
	if ti, ok = p.Val([]byte{'i'}); !ok {
		err = errors.New("incorrect challenge format")
		return
	}
	i, err = strconv.Atoi(string(ti))
	return
}

func (sa *scramAuth) clientFirstMsgBare() ([]byte, error) {
	out := []byte("n=")
	if n, ok := sa.gs2Header.Params.Val([]byte("n")); ok {
		out = append(out, n...)
	} else {
		return []byte{}, errors.New("error occured")
	}
	out = append(out, ",r="...)
	if r, ok := sa.gs2Header.Params.Val([]byte("r")); ok {
		out = append(out, r...)
	} else {
		return []byte{}, errors.New("error occured")
	}
	return out, nil
}

func (sa *scramAuth) xor(a, b []byte) []byte {
	count := int(math.Min(float64(len(a)), float64(len(b))))
	out := make([]byte, count)
	for i := 0; i < count; i++ {
		out[i] = a[i] ^ b[i]
	}
	return out
}

func (sa *scramAuth) clientFinalMsgWithoutProof(sNonce []byte) ([]byte, error) {
	cNonce, ok := sa.gs2Header.Params.Val([]byte("r"))
	if !ok {
		return []byte{}, errors.New("invalid gs2 header")
	}
	nonce := append(cNonce, sNonce...)
	out := []byte("c=")
	switch sa.channelBinding {
	case None:
		out = append(out, []byte("biws")...)
	case TlsUnique:
		out = append(out, []byte(base64.StdEncoding.EncodeToString(sa.cbData))...)
	}
	if sa.channelBinding != None {
	} else {
	}
	out = append(out, ",r="...)
	out = append(out, nonce...)
	return out, nil
}

func (sa *scramAuth) serverSignature(r io.Reader, saltedPassword []byte, w io.Writer) error {
	authMsg, err := sa.authMsg()
	if err != nil {
		return err
	}
	serverKey := sa.hmac(saltedPassword, []byte("Server Key"))

	signature := sa.hmac(serverKey, authMsg)
	p := NewParams()
	p.Append(Param{Key: []byte{'v'}, Val: []byte(base64.StdEncoding.EncodeToString(signature))})

	return NewEncoding().Encode(w, p)
}

func (sa *scramAuth) clientVerify(r io.Reader, password string) error {
	authMsg, err := sa.authMsg()
	if err != nil {
		return err
	}
	serverKey := sa.hmac(sa.saltedPassword([]byte(password), sa.salt, sa.iter), []byte("Server Key"))
	p := NewParams()
	if err := NewEncoding().Decode(r, p); err != nil {
		return err
	}
	ssb, ok := p.Val([]byte{'v'})
	if !ok {
		return errors.New("server signature not found")
	}
	ss, err := base64.StdEncoding.DecodeString(string(ssb))
	if err != nil {
		return err
	}
	if !bytes.Equal(ss, sa.hmac(serverKey, authMsg)) {
		return errors.New("failed")
	}
	return nil
}

func (sa *scramAuth) serverVerify(r io.Reader, saltedPassword []byte) error {
	if sa.channelBinding != sa.gs2Header.CB {
		return errors.New("channel binding type not match")
	}
	p := NewParams()
	if err := NewEncoding().Decode(r, p); err != nil {
		return err
	}
	authMsg, err := sa.authMsg()
	if err != nil {
		return err
	}
	clientKey := sa.hmac(saltedPassword, []byte("Client Key"))
	storedKey := sa.hash(clientKey)
	signature := sa.hmac(storedKey, authMsg)
	pr, ok := p.Val([]byte{'p'})
	if !ok {
		return errors.New("invalid client message")
	}
	proof, err := base64.StdEncoding.DecodeString(string(pr))
	if err != nil {
		return err
	}
	clientKey = sa.xor(signature, proof)
	attemptingStoredKey := sa.hash(clientKey)

	if bytes.Equal(attemptingStoredKey, storedKey) {
		return nil
	}

	return errors.New("failed")
}

func (sa *scramAuth) saltedPassword(password, salt []byte, iter int) []byte {
	return sa.hi(sa.normalizePassword(password), salt, iter)
}

func (scram *scramAuth) hi(str, salt []byte, iter int) []byte {
	l := scram.hashBuild().Size()
	return pbkdf2.Key(str, salt, iter, l, scram.hashBuild)
}

func (sa *scramAuth) normalizePassword(password []byte) []byte {
	return password
}

func (scram *scramAuth) hmac(b []byte, key []byte) []byte {
	m := hmac.New(scram.hashBuild, key)
	m.Write(b)
	return m.Sum(nil)
}

func (scram *scramAuth) hash(b []byte) []byte {
	h := scram.hashBuild()
	h.Write(b)
	return h.Sum(nil)
}

func (scram *scramAuth) genNonce(n int) []byte {
	var letters = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return b
}

func HashBuild(mechanism string) func() hash.Hash {
	switch mechanism {
	case SCRAM_SHA_1, SCRAM_SHA_1_PLUS:
		return sha1.New
	case SCRAM_SHA_256, SCRAM_SHA_256_PLUS:
		return sha256.New
	case SCRAM_SHA_512, SCRAM_SHA_512_PLUS:
		return sha512.New
	case SCRAM_SHA_224, SCRAM_SHA_224_PLUS:
		return sha256.New224
	case SCRAM_SHA_384, SCRAM_SHA_384_PLUS:
		return sha512.New384
	case SCRAM_SHA3_224, SCRAM_SHA3_224_PLUS:
		return sha3.New224
	case SCRAM_SHA3_256, SCRAM_SHA3_256_PLUS:
		return sha3.New256
	case SCRAM_SHA3_384, SCRAM_SHA3_384_PLUS:
		return sha3.New384
	case SCRAM_SHA3_512, SCRAM_SHA3_512_PLUS:
		return sha3.New512
	}
	return nil
}
