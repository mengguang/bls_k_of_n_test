package main

import (
	"fmt"
	"log"

	"github.com/herumi/bls-eth-go-binary/bls"
)

func k_of_n_multisig() {
	const K = 3
	const N = 5
	ids := make([]bls.ID, N)
	secs := make([]bls.SecretKey, N)
	pubs := make([]bls.PublicKey, N)
	sigs := make([]bls.Sign, N)

	msg := []byte("message to be signed.")

	// All ids must be non-zero and different from each other.
	for i := 0; i < N; i++ {
		ids[i].SetDecString(fmt.Sprintf("%d", i+1))
	}

	for k, id := range ids {
		fmt.Printf("id of %d: %v\n", k, id.SerializeToHexStr())
	}

	fmt.Println()
	/*
		A trusted third party distributes N secret keys.
		If you want to avoid it, then see DKG (distributed key generation),
		which is out of the scope of this library.
	*/
	msk := make([]bls.SecretKey, K)
	for i := 0; i < K; i++ {
		msk[i].SetByCSPRNG()
	}

	for k, sk := range msk {
		fmt.Printf("sk of %d: %v\n", k, sk.SerializeToHexStr())
	}
	fmt.Println()
	// share secret key
	// https://github.com/herumi/bls/issues/94
	for i := 0; i < N; i++ {
		secs[i].Set(msk, &ids[i])
	}

	for k, sec := range secs {
		fmt.Printf("sec of %d: %v\n", k, sec.SerializeToHexStr())
	}
	fmt.Println()
	// get master public key
	mpk := msk[0].GetPublicKey()
	fmt.Printf("mpk: %v\n", mpk.SerializeToHexStr())
	fmt.Println()

	for i := 0; i < N; i++ {
		pubs[i] = *secs[i].GetPublicKey()
	}

	for k, pub := range pubs {
		fmt.Printf("pub of %d: %v\n", k, pub.SerializeToHexStr())
	}
	fmt.Println()

	// each user signs the message
	for i := 0; i < N; i++ {
		sigs[i] = *secs[i].SignByte(msg)
	}

	//use 0,1,2 for verify
	subSigs := sigs[0:3]
	subIds := ids[0:3]

	// var sig bls.Sign
	sig := &bls.Sign{}
	err := sig.Recover(subSigs, subIds)
	if err != nil {
		log.Fatal(err)
	}
	result := sig.VerifyByte(mpk, msg)
	fmt.Printf("Verify result: %v\n", result)

}

func main() {
	bls.Init(bls.BLS12_381)
	bls.SetETHmode(bls.EthModeDraft07)
	k_of_n_multisig()
}
