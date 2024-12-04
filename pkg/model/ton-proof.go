package model

type PayloadConfig struct {
	Secret     string
	PayloadTTL int64
}

type ProofConfig struct {
	Secret     string
	Domain     string
	ProofTTL   int64
	JWTExpDays int
	TonProof   TonProofRequest
}

type Domain struct {
	LengthBytes uint32 `json:"lengthBytes"`
	Value       string `json:"value"`
}

type Proof struct {
	Timestamp int64  `json:"timestamp"`
	Domain    Domain `json:"domain"`
	Signature string `json:"signature"`
	Payload   string `json:"payload"`
	StateInit string `json:"stateInit"`
}

type TonProofRequest struct {
	Address   string `json:"address"`
	Network   string `json:"network"`
	PublicKey string `json:"publicKey"`
	Proof     Proof  `json:"proof"`
}

type JWTToken struct {
	Token string `json:"token"`
}

type Payload struct {
	Payload string `json:"payload"`
}
