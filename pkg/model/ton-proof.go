package model

type PayloadConfig struct {
	Secret     string
	PayloadTTL int64
}

type ProofConfig struct {
	Secret   string
	Domain   string
	ProofTTL int64
}

type Domain struct {
	LengthBytes uint32
	Value       string
}

type Proof struct {
	Timestamp int64
	Signature string
	Payload   string
	StateInit string
}

type TonProof struct {
	Address   string
	Network   string
	PublicKey string
}

type TonProofConfig struct {
	ProofConfig
	TonProof
	Proof
	Domain
}

type JWTToken struct {
	Token string `json:"token"`
}

type Payload struct {
	Payload string `json:"payload"`
}
