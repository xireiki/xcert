package option

type KeyOptions struct {
	Cipher  string
	Bits    int
	Subject string
	Days    int
}

type CAOptions struct {
	KeyUsage       []string
	ExtKeyUsage    []string
	PathLength     int
	Digest         string
	SubjectKeyID   bool
	AuthorityKeyID bool
}

type CRLOptions struct {
	CACert string
	CAKey  string
	CRL    string
	Days   int
}
