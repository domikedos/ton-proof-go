package proof

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/domikedos/ton-proof-go/pkg/model"
	"time"
)

func GeneratePayload(config *model.ProofConfig) (*model.Payload, error) {
	payload := make([]byte, 16, 48)
	_, err := rand.Read(payload[:8])
	if err != nil {
		return nil, fmt.Errorf("could not generate payload")
	}

	binary.BigEndian.PutUint64(payload[8:16], uint64(time.Now().Add(time.Duration(config.PayloadTTL)*time.Second).Unix()))
	h := hmac.New(sha256.New, []byte(config.Secret))
	h.Write(payload)

	payload = h.Sum(payload)
	return &model.Payload{
		Payload: hex.EncodeToString(payload[:32]),
	}, nil
}
