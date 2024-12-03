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
	LengthBytes uint32
	Value       string
}

type Proof struct {
	Timestamp int64
	Domain    Domain
	Signature string
	Payload   string
	StateInit string
}

type TonProof struct {
	Address   string
	Network   string
	PublicKey string
	Proof     Proof
}

type JWTToken struct {
	Token string `json:"token"`
}

type Payload struct {
	Payload string `json:"payload"`
}
