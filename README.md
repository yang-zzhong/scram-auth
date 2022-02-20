## Overview

A tool for scram authorization. Support

* scram-sha-1
* scram-sha-256
* scram-sha-512

## Basic usage

server side with xmpp

```golang
package xmppcore

import (
	"bytes"
	"fmt"
	"hash"
	"strings"

	"github.com/jackal-xmpp/stravaganza/v2"
	scramauth "github.com/yang-zzhong/scram-auth"
)

// rfc5802

const (
	ErrHashNotSupported = "hash not supported"
)

type ScramAuthUser interface {
	Salt() string
	Password(hashName string) (string, error)
	ID() string
	IterationCount() int
}

type ScramAuthUserFetcher interface {
	UserByUsername(username string) (ScramAuthUser, error)
}

type ScramAuth struct {
	hashBuild   func() hash.Hash
	useCB       bool
	userFetcher ScramAuthUserFetcher
	user        ScramAuthUser
}

func NewScramAuth(userFetcher ScramAuthUserFetcher, hashBuild func() hash.Hash, useCB bool) *ScramAuth {
	return &ScramAuth{
		hashBuild:   hashBuild,
		useCB:       useCB,
		userFetcher: userFetcher}
}

func (scram *ScramAuth) Auth(mechanism, authInfo string, part Part) (username string, err error) {
	var auth *scramauth.ServerScramAuth
	if scram.useCB {
		var buf bytes.Buffer
		if err := part.Conn().BindTlsUnique(&buf); err != nil {
			return "", err
		}
		fmt.Printf("server challenge bind string: %s\n", buf.String())
		auth = scramauth.NewServerScramAuth(scram.hashBuild, scramauth.TlsUnique, buf.Bytes())
	} else {
		auth = scramauth.NewServerScramAuth(scram.hashBuild, scramauth.None, []byte{})
	}
	r := bytes.NewBuffer([]byte(authInfo))
	var buf bytes.Buffer
	if err := auth.WriteChallengeMsg(r, func(username []byte) ([]byte, int, error) {
		if err := scram.initUser(username); err != nil {
			return nil, 0, err
		}
		return []byte(scram.user.Salt()), scram.user.IterationCount(), nil
	}, &buf); err != nil {
		return "", err
	}
	msg := stravaganza.NewBuilder("challenge").
		WithAttribute(stravaganza.Namespace, NSSasl).
		WithText(buf.String()).
		Build()
	if err = part.Channel().SendElement(msg); err != nil {
		return
	}
	if err = scram.waitChallengeResponse(&msg, part.Channel()); err != nil {
		return
	}
	hashName := scram.hashNameFromMechanism(mechanism)
	if err = scram.verifyPassword(auth, part, &msg, hashName); err != nil {
		return
	}
	return
}

func (scram *ScramAuth) initUser(username []byte) error {
	var err error
	scram.user, err = scram.userFetcher.UserByUsername(string(username))
	if err != nil {
		return SaslFailureError(SFTemporaryAuthFailure, err.Error())
	}
	return nil
}

func (scram *ScramAuth) waitChallengeResponse(msg *stravaganza.Element, receiver Receiver) error {
	if err := receiver.NextElement(msg); err != nil {
		return err
	}
	if (*msg).Name() != "response" {
		return SaslFailureError(SFTemporaryAuthFailure, "not a response required")
	}
	return nil
}

func (scram *ScramAuth) hashNameFromMechanism(mechanism string) string {
	hashName := strings.Replace(mechanism, "SCRAM-", "", 1)
	return strings.Replace(hashName, "-PLUS", "", 1)
}

func (scram *ScramAuth) verifyPassword(auth *scramauth.ServerScramAuth, part Part, msg *stravaganza.Element, hashName string) error {
	password, err := scram.user.Password(hashName)
	if err != nil {
		return SaslFailureError(SFTemporaryAuthFailure, err.Error())
	}
	r := bytes.NewBuffer([]byte((*msg).Text()))
	if err := auth.Verify(r, []byte(password)); err != nil {
		return SaslFailureError(SFTemporaryAuthFailure, err.Error())
	}
	var buf bytes.Buffer
	if err := auth.WriteSignatureMsg(r, []byte(password), &buf); err != nil {
		return SaslFailureError(SFTemporaryAuthFailure, err.Error())
	}
	return part.Channel().SendElement(stravaganza.NewBuilder("success").
		WithAttribute(stravaganza.Namespace, NSSasl).
		WithText(buf.String()).
		Build())
}
```

client side with xmpp

```golang
package xmppcore

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"io"

	"github.com/google/uuid"
	"github.com/jackal-xmpp/stravaganza/v2"
	scramauth "github.com/yang-zzhong/scram-auth"
)

type ScramToAuth struct {
	authzid   string
	username  string
	password  string
	mechanism string
	useCB     bool
}

func NewScramToAuth(u, p string, mechanism string, useCB bool) *ScramToAuth {
	return &ScramToAuth{
		useCB:     useCB,
		authzid:   uuid.New().String(),
		mechanism: mechanism,
		username:  u, password: p}
}

func (sta *ScramToAuth) hashBuild() func() hash.Hash {
	switch sta.mechanism {
	case SM_SCRAM_SHA_1:
		return sha1.New
	case SM_SCRAM_SHA_1_PLUS:
		return sha1.New
	case SM_SCRAM_SHA_256:
		return sha256.New
	case SM_SCRAM_SHA_256_PLUS:
		return sha256.New
	case SM_SCRAM_SHA_512:
		return sha512.New
	case SM_SCRAM_SHA_512_PLUS:
		return sha512.New
	}
	return nil
}

func (sta *ScramToAuth) ToAuth(mechemism string, part Part) error {
	var auth *scramauth.ClientScramAuth
	hashBuild := sta.hashBuild()
	if hashBuild == nil {
		return errors.New("hash not supported")
	}
	if sta.useCB {
		var buf bytes.Buffer
		if err := part.Conn().BindTlsUnique(&buf); err != nil {
			return err
		}
		fmt.Printf("client challenge bind string: %s\n", buf.String())
		auth = scramauth.NewClientScramAuth(hashBuild, scramauth.TlsUnique, buf.Bytes())
	} else {
		auth = scramauth.NewClientScramAuth(hashBuild, scramauth.None, []byte{})
	}
	if err := sta.sendRequest(auth, part); err != nil {
		return err
	}
	cha, err := sta.challenge(part)
	if err != nil {
		return err
	}
	if err := sta.sendResponse(auth, cha, part); err != nil {
		return err
	}
	sign, err := sta.signature(part)
	if err != nil {
		return err
	}
	return auth.Verify(bytes.NewBuffer(sign), sta.password)
}

func (sta *ScramToAuth) signature(part Part) ([]byte, error) {
	var elem stravaganza.Element
	if err := part.Channel().NextElement(&elem); err != nil {
		return nil, err
	}
	if elem.Name() != "success" {
		return nil, errors.New("server failed auth")
	}
	return []byte(elem.Text()), nil
}

func (sta *ScramToAuth) sendResponse(auth *scramauth.ClientScramAuth, r io.Reader, part Part) error {
	var wr bytes.Buffer
	if err := auth.WriteResMsg(r, sta.password, &wr); err != nil {
		return err
	}
	elem := stravaganza.NewBuilder("response").
		WithAttribute("xmlns", NSSasl).
		WithText(wr.String()).Build()

	return part.Channel().SendElement(elem)
}

func (sta *ScramToAuth) challenge(part Part) (io.Reader, error) {
	var elem stravaganza.Element
	if err := part.Channel().NextElement(&elem); err != nil {
		return nil, err
	}
	if elem.Name() != "challenge" {
		return nil, errors.New("not a challenge element")
	}
	return bytes.NewBuffer([]byte(elem.Text())), nil
}

func (sta *ScramToAuth) sendRequest(auth *scramauth.ClientScramAuth, part Part) error {
	var buf bytes.Buffer
	if err := auth.WriteReqMsg(sta.authzid, sta.username, &buf); err != nil {
		return err
	}
	elem := stravaganza.NewBuilder("auth").
		WithAttribute("mechanism", sta.mechanism).
		WithAttribute("xmlns", NSSasl).WithText(buf.String()).Build()
	return part.Channel().SendElement(elem)
}
```
