package proof

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/domikedos/ton-proof-go/pkg/model"
	"github.com/golang-jwt/jwt"
	"github.com/tonkeeper/tongo"
	"github.com/tonkeeper/tongo/boc"
	"github.com/tonkeeper/tongo/tlb"
	"github.com/tonkeeper/tongo/wallet"
	"math/big"
	"time"
)

const (
	tonProofPrefix   = "ton-proof-item-v2/"
	tonConnectPrefix = "ton-connect"
)

var knownHashes = make(map[string]wallet.Version)

type parsedMessage struct {
	Workchain int32
	Address   []byte
	Timestamp int64
	Domain    model.Domain
	Signature []byte
	Payload   string
	StateInit string
	PublicKey string
}

type claims struct {
	Address string
	jwt.StandardClaims
}

func Proof(config *model.ProofConfig) (*model.JWTToken, error) {
	err := checkPayload(config.TonProof.Proof.Payload, config.Secret)

	message, err := convertTonProofMessage(&config.TonProof)
	if err != nil {
		return nil, err
	}

	addr, err := tongo.ParseAddress(config.TonProof.Address)
	if err != nil {
		return nil, err
	}

	check, err := checkProof(config.ProofTTL, config.Domain, addr.ID, message)
	if err != nil {
		return nil, err
	}
	if !check {
		return nil, fmt.Errorf("proof verification failed")
	}
	// TODO: add to config days
	jwtClaims := &claims{
		Address: config.TonProof.Address,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().AddDate(0, 0, 7).Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtClaims)

	jwtToken, err := token.SignedString([]byte(config.Secret))
	if err != nil {
		return nil, err
	}

	response := &model.JWTToken{
		Token: jwtToken,
	}
	return response, nil
}

func convertTonProofMessage(tonProof *model.TonProof) (*parsedMessage, error) {
	addr, err := tongo.ParseAddress(tonProof.Address)
	if err != nil {
		return nil, err
	}

	var msg parsedMessage

	sig, err := base64.StdEncoding.DecodeString(tonProof.Proof.Signature)
	if err != nil {
		return nil, err
	}

	msg.Workchain = addr.ID.Workchain
	msg.Address = addr.ID.Address[:]
	msg.Domain = tonProof.Proof.Domain
	msg.Timestamp = tonProof.Proof.Timestamp
	msg.Signature = sig
	msg.Payload = tonProof.Proof.Payload
	msg.StateInit = tonProof.Proof.StateInit
	msg.PublicKey = tonProof.PublicKey

	return &msg, nil
}

func signatureVerify(pubKey ed25519.PublicKey, message, signature []byte) bool {
	return ed25519.Verify(pubKey, message, signature)
}

func createMessage(msg *parsedMessage) ([]byte, error) {
	wc := make([]byte, 4)
	binary.BigEndian.PutUint32(wc, uint32(msg.Workchain))

	ts := make([]byte, 8)
	binary.LittleEndian.PutUint64(ts, uint64(msg.Timestamp))

	dl := make([]byte, 4)
	binary.LittleEndian.PutUint32(dl, msg.Domain.LengthBytes)

	m := []byte(tonProofPrefix)
	m = append(m, wc...)
	m = append(m, msg.Address...)
	m = append(m, dl...)
	m = append(m, []byte(msg.Domain.Value)...)
	m = append(m, ts...)
	m = append(m, []byte(msg.Payload)...)

	messageHash := sha256.Sum256(m)
	fullMes := []byte{0xff, 0xff}
	fullMes = append(fullMes, []byte(tonConnectPrefix)...)
	fullMes = append(fullMes, messageHash[:]...)
	res := sha256.Sum256(fullMes)

	return res[:], nil
}

func checkProof(proofTTL int64, domain string, address tongo.AccountID, msg *parsedMessage) (bool, error) {
	pubKey, err := getWalletPubKey(msg.PublicKey)
	if err != nil {
		if msg.StateInit != "" {
			return false, err
		}

		if ok, err := compareStateInitWithAddress(address, msg.StateInit); err != nil || !ok {
			return ok, err
		}

		pubKey, err = parseStateInit(msg.StateInit)
		if err != nil {
			return false, err
		}
	}

	if time.Now().After(time.Unix(msg.Timestamp, 0).Add(time.Duration(proofTTL) * time.Second)) {
		return false, fmt.Errorf("proof has been expired")
	}

	if msg.Domain.Value != domain {
		return false, fmt.Errorf("wrong domain: %v", msg.Domain.Value)
	}

	mes, err := createMessage(msg)
	if err != nil {
		return false, err
	}

	return signatureVerify(pubKey, mes, msg.Signature), nil
}

func checkPayload(payload, secret string) error {
	b, err := hex.DecodeString(payload)
	if err != nil {
		return err
	}
	if len(b) != 32 {
		return fmt.Errorf("invalid payload length")
	}

	h := hmac.New(sha256.New, []byte(secret))
	h.Write(b[:16])
	sign := h.Sum(nil)
	if subtle.ConstantTimeCompare(b[16:], sign[:16]) != 1 {
		return fmt.Errorf("invalid payload signature")
	}
	if time.Since(time.Unix(int64(binary.BigEndian.Uint64(b[8:16])), 0)) > 0 {
		return fmt.Errorf("payload expired")
	}

	return nil
}

func getWalletPubKey(pubKey string) (ed25519.PublicKey, error) {
	i := new(big.Int)
	i, ok := i.SetString(pubKey, 16)
	if !ok {
		return nil, fmt.Errorf("invalid public key")
	}

	b := i.Bytes()
	if len(b) < 24 || len(b) > 32 {
		return nil, fmt.Errorf("invalid public key")
	}

	return append(make([]byte, 32-len(b)), b...), nil
}

func parseStateInit(stateInit string) ([]byte, error) {
	cells, err := boc.DeserializeBocBase64(stateInit)
	if err != nil || len(cells) != 1 {
		return nil, err
	}

	var state tlb.StateInit
	err = tlb.Unmarshal(cells[0], &state)
	if err != nil {
		return nil, err
	}

	if !state.Data.Exists || !state.Code.Exists {
		return nil, fmt.Errorf("empty init state")
	}

	codeHash, err := state.Code.Value.Value.HashString()
	if err != nil {
		return nil, err
	}

	if len(knownHashes) < 2 {
		initKnownHashes()
	}

	version, prs := knownHashes[codeHash]
	if !prs {
		return nil, fmt.Errorf("unknown code hash")
	}

	var pubKey tlb.Bits256
	switch version {
	case wallet.V1R1, wallet.V1R2, wallet.V1R3, wallet.V2R1, wallet.V2R2:
		var data wallet.DataV1V2
		err = tlb.Unmarshal(&state.Data.Value.Value, &data)
		if err != nil {
			return nil, err
		}

		pubKey = data.PublicKey
	case wallet.V3R1, wallet.V3R2:
		var data wallet.DataV3
		err = tlb.Unmarshal(&state.Data.Value.Value, &data)
		if err != nil {
			return nil, err
		}

		pubKey = data.PublicKey
	case wallet.V4R1, wallet.V4R2:
		var data wallet.DataV4
		err = tlb.Unmarshal(&state.Data.Value.Value, &data)
		if err != nil {
			return nil, err
		}

		pubKey = data.PublicKey
	case wallet.V5R1:
		var data wallet.DataV5R1
		err = tlb.Unmarshal(&state.Data.Value.Value, &data)
		if err != nil {
			return nil, err
		}

		pubKey = data.PublicKey
	case wallet.V5Beta:
		var data wallet.DataV5Beta
		err = tlb.Unmarshal(&state.Data.Value.Value, &data)
		if err != nil {
			return nil, err
		}

		pubKey = data.PublicKey
	default:
		panic("unknown wallet version")
	}

	return pubKey[:], nil
}

func compareStateInitWithAddress(a tongo.AccountID, stateInit string) (bool, error) {
	cells, err := boc.DeserializeBocBase64(stateInit)
	if err != nil || len(cells) != 1 {
		return false, err
	}

	h, err := cells[0].Hash()
	if err != nil {
		return false, err
	}

	return bytes.Equal(h, a.Address[:]), nil
}

func initKnownHashes() {
	for i := wallet.Version(0); i <= wallet.V5R1; i++ {
		ver := wallet.GetCodeHashByVer(i)
		knownHashes[hex.EncodeToString(ver[:])] = i
	}
}
