package model

type PayloadConfig struct {
	Secret     string
	PayloadTTL int64
}

type ProofConfig struct {
	Secret   string
	Domain   string
	ProofTTL int64
	TonProof TonProof
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
	StateInit string `json:"state_init"`
}

type TonProof struct {
	Address   string `json:"address"`
	Network   string `json:"network"`
	PublicKey string `json:"public_key"`
	Proof     Proof  `json:"proof"`
}

type JWTToken struct {
	Token string
}

type Payload struct {
	Payload string
}
