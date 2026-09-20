package main

import (
	"math/big"

	"xcert/pki"
	"xcert/store"
)

func nextSerial(st *store.Store, sequential bool) (*big.Int, error) {
	if sequential {
		return st.NextSequentialSerial()
	}
	return pki.RandomSerial()
}
