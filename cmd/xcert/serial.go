package main

import (
	"math/big"

	"github.com/xireiki/xcert/pki"
	"github.com/xireiki/xcert/store"
)

func nextSerial(st *store.Store, sequential bool) (*big.Int, error) {
	if sequential {
		return st.NextSequentialSerial()
	}
	return pki.RandomSerial()
}
