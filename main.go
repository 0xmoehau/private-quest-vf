package main

import (
	b64 "encoding/base64"
	"errors"
	"fmt"
	"math/big"

	"github.com/incognitochain/go-incognito-sdk/privacy"
	"github.com/incognitochain/go-incognito-sdk/privacy/curve25519"
)

const EQDLProofLength = 96
const VRFProofLength = 128

//Witness for proving equality of discrete logarithms
//i.e. g^x = a and h^x = b
type EQDLWitness struct {
	x    *privacy.Scalar
	g, h *privacy.Point
	a, b *privacy.Point
}

//Proof for discrete logarithm equality with respect to two different bases
//i.e. g^x = a and h^x = b
type EQDLProof struct {
	k      *privacy.Point
	kPrime *privacy.Point
	z      *privacy.Scalar
}

func NewEQDLWitness(x *privacy.Scalar, g, h, a, b *privacy.Point) EQDLWitness {
	return EQDLWitness{x, g, h, a, b}
}

func (eqdlProof EQDLProof) Bytes() []byte {
	res := eqdlProof.k.ToBytesS()
	res = append(res, eqdlProof.kPrime.ToBytesS()...)
	res = append(res, eqdlProof.z.ToBytesS()...)

	return res
}

func (eqdlProof EQDLProof) SetBytes(data []byte) (*EQDLProof, error) {
	if len(data) != EQDLProofLength {
		return nil, fmt.Errorf("length of EQDLProof should be equal to %v", EQDLProofLength)
	}
	k, err := new(privacy.Point).FromBytesS(data[:32])
	if err != nil {
		return nil, err
	}

	kPrime, err := new(privacy.Point).FromBytesS(data[32:64])
	if err != nil {
		return nil, err
	}

	z := new(privacy.Scalar).FromBytesS(data[64:])

	return &EQDLProof{k, kPrime, z}, nil
}

func (eqdlWitness EQDLWitness) Prove(msg []byte) *EQDLProof {
	r := privacy.RandomScalar()

	k := new(privacy.Point).ScalarMult(eqdlWitness.g, r)
	kPrime := new(privacy.Point).ScalarMult(eqdlWitness.h, r)

	msgToBeHased := []byte{}
	msgToBeHased = append(msgToBeHased, msg...)
	msgToBeHased = append(msgToBeHased, eqdlWitness.g.ToBytesS()...)
	msgToBeHased = append(msgToBeHased, eqdlWitness.a.ToBytesS()...)
	msgToBeHased = append(msgToBeHased, k.ToBytesS()...)
	msgToBeHased = append(msgToBeHased, eqdlWitness.h.ToBytesS()...)
	msgToBeHased = append(msgToBeHased, eqdlWitness.b.ToBytesS()...)
	msgToBeHased = append(msgToBeHased, kPrime.ToBytesS()...)

	c := privacy.HashToScalar(msgToBeHased)

	z := new(privacy.Scalar).Add(r, new(privacy.Scalar).Mul(eqdlWitness.x, c))

	return &EQDLProof{k, kPrime, z}
}

func (eqdlProof EQDLProof) Verify(msg []byte, g, h, a, b *privacy.Point) (bool, error) {
	msgToBeHased := []byte{}
	msgToBeHased = append(msgToBeHased, msg...)
	msgToBeHased = append(msgToBeHased, g.ToBytesS()...)
	msgToBeHased = append(msgToBeHased, a.ToBytesS()...)
	msgToBeHased = append(msgToBeHased, eqdlProof.k.ToBytesS()...)
	msgToBeHased = append(msgToBeHased, h.ToBytesS()...)
	msgToBeHased = append(msgToBeHased, b.ToBytesS()...)
	msgToBeHased = append(msgToBeHased, eqdlProof.kPrime.ToBytesS()...)

	c := privacy.HashToScalar(msgToBeHased)

	leftPoint1 := new(privacy.Point).Add(eqdlProof.k, new(privacy.Point).ScalarMult(a, c))
	rightPoint1 := new(privacy.Point).ScalarMult(g, eqdlProof.z)

	if !privacy.IsPointEqual(leftPoint1, rightPoint1) {
		return false, errors.New("EQDLProof: verify first statement FAILED")
	}

	leftPoint2 := new(privacy.Point).Add(eqdlProof.kPrime, new(privacy.Point).ScalarMult(b, c))
	rightPoint2 := new(privacy.Point).ScalarMult(h, eqdlProof.z)

	if !privacy.IsPointEqual(leftPoint2, rightPoint2) {
		return false, errors.New("EQDLProof: verify second statement FAILED")
	}

	return true, nil
}

//Witness for proving the validity of VRF output
//x: the secret key
//g: the base point
type VRFWitness struct {
	x *privacy.Scalar //the privateKey
	g *privacy.Point
}

type VRFProof struct {
	u         *privacy.Point
	eqdlProof *EQDLProof
}

func NewVRFWitness(x *privacy.Scalar, g *privacy.Point) VRFWitness {
	return VRFWitness{x, g}
}

func (vrfProof VRFProof) Bytes() []byte {
	res := vrfProof.u.ToBytesS()
	res = append(res, vrfProof.eqdlProof.Bytes()...)

	return res
}

func (vrfProof VRFProof) SetBytes(data []byte) (*VRFProof, error) {
	if len(data) != VRFProofLength {
		return nil, fmt.Errorf("length of EQDLProof should be equal to %v", EQDLProofLength)
	}
	u, err := new(privacy.Point).FromBytesS(data[:32])
	if err != nil {
		return nil, err
	}

	eqdlProof, err := new(EQDLProof).SetBytes(data[32:])
	if err != nil {
		return nil, err
	}

	return &VRFProof{u, eqdlProof}, nil
}

//This module implements the VRF algorithm described in the Ouroboros Praos Paper
//https://eprint.iacr.org/2017/573.pdf
func (vrfWitness VRFWitness) Compute(msg []byte) (*privacy.Scalar, *VRFProof) {
	hPrime := privacy.HashToPoint(msg)
	u := new(privacy.Point).ScalarMult(hPrime, vrfWitness.x)

	//compute the output of the VRF, with respect to the input msg
	y := privacy.HashToScalar(append(msg, u.ToBytesS()...))

	eqdlWitness := EQDLWitness{
		x: vrfWitness.x,
		g: vrfWitness.g,
		h: hPrime,
		a: new(privacy.Point).ScalarMult(vrfWitness.g, vrfWitness.x),
		b: u,
	}

	//Produce the proof for correct computation of y on input msg.
	eqdlProof := eqdlWitness.Prove(msg)

	vrfProof := VRFProof{
		u:         u,
		eqdlProof: eqdlProof,
	}

	return y, &vrfProof
}

func (vrfProof VRFProof) Verify(msg []byte, g, pubKey *privacy.Point, output *privacy.Scalar) (bool, error) {
	y := privacy.HashToScalar(append(msg, vrfProof.u.ToBytesS()...))
	if !privacy.IsScalarEqual(y, output) {
		return false, errors.New("VRFProof: verify first statement FAILED")
	}

	hPrime := privacy.HashToPoint(msg)
	return vrfProof.eqdlProof.Verify(msg, g, hPrime, pubKey, vrfProof.u)
}

func MySpinRandomNumberBTC(txInfo []byte) (string, *big.Int, string) {

	y, proof := vrfWitness.Compute(txInfo)
	isValid, err := proof.Verify(txInfo, g, pubKey, y)
	if err != nil || !isValid {
		panic("something went wrong ...")
	}
	yInt := new(big.Int)
	yInt = ConvertByte2BigInt(y.ToBytesS())
	//=======
	pointString := b64.StdEncoding.EncodeToString(y.ToBytesS())
	piString := b64.StdEncoding.EncodeToString(proof.Bytes())
	return piString, yInt, pointString
}

func PublicVerify(txID []byte, yStr, proofStr, pubKeyStr string) (bool, error) {
	proofBytes, err := b64.StdEncoding.DecodeString(proofStr)
	if err != nil {
		return false, err
	}
	proof, err := new(VRFProof).SetBytes(proofBytes)
	if err != nil {
		return false, err
	}
	yBytes, err := b64.StdEncoding.DecodeString(yStr)
	if err != nil {
		return false, err
	}
	y := new(privacy.Scalar).FromBytesS(yBytes)
	if err != nil {
		return false, err
	}
	// txHash, err := b64.StdEncoding.DecodeString(txID)
	// if err != nil {
	// 	return false, err
	// }
	pubkeyBytes, err := b64.StdEncoding.DecodeString(pubKeyStr)
	if err != nil {
		return false, err
	}
	pubKey, err := new(privacy.Point).FromBytesS(pubkeyBytes)
	if err != nil {
		return false, err
	}
	isValid, err := proof.Verify(txID, g, pubKey, y)
	if err != nil {
		return false, err
	}
	return isValid, nil
}

func ConvertByte2BigInt(b []byte) *big.Int {
	bLE := b
	for i := 0; i < len(bLE)/2; i++ {
		bLE[i], bLE[len(bLE)-i-1] = bLE[len(bLE)-i-1], bLE[i]
	}
	return new(big.Int).SetBytes(bLE)

}

var x = &privacy.Scalar{}
var g = &privacy.Point{}
var pubKey = new(privacy.Point).ScalarMult(g, x)
var vrfWitness = NewVRFWitness(x, g)
var L = ConvertByte2BigInt(curve25519.L[:])

// var x = privacy.RandomScalar()
// var g = privacy.RandomPoint()
// var pubKey = new(privacy.Point).ScalarMult(g, x)
// var vrfWitness = NewVRFWitness(x, g)
// var L = ConvertByte2BigInt(curve25519.L[:])

func getRand() {

	//set manual x,g
	var xkeyString = "myuy8H3d+FVCUPWqfrdFvspekP2wulB/02/aCrG1TgM="
	var gkeyString = "bq+wTtNofW3V7RSjIhg7F9k5z5uoLnonLjNol64QWpM="

	gkeyBytes, _ := b64.StdEncoding.DecodeString(gkeyString)
	g.FromBytesS(gkeyBytes)
	xkeyBytes, _ := b64.StdEncoding.DecodeString(xkeyString)
	x.FromBytesS(xkeyBytes)
	
	// or random X, G
	//x = privacy.RandomScalar()
	//g = privacy.RandomPoint()

	var pubKey = new(privacy.Point).ScalarMult(g, x)
	var xkeyStr = b64.StdEncoding.EncodeToString(x.ToBytesS())
	var gkeyStr = b64.StdEncoding.EncodeToString(g.ToBytesS())
	var pubKeyStr = b64.StdEncoding.EncodeToString(pubKey.ToBytesS())

	var vrfWitness = NewVRFWitness(x, g)

	fmt.Println("Demo ,v")
	fmt.Println("xkeyStr:", xkeyStr)
	fmt.Println("gkeyStr:", gkeyStr)
	fmt.Println("pubKeyStr:", pubKeyStr)
	byteOfTx := []byte("c17e6beadf7ffa32a607e32cd4bdb1848f65fb39e41b20a4c95b5ec22a56f15d")
	y, proof := vrfWitness.Compute(byteOfTx)
	isValid, err := proof.Verify(byteOfTx, g, pubKey, y)
	if err != nil || !isValid {
		panic("something went wrong ...")
	}

	yInt := ConvertByte2BigInt(y.ToBytesS())
	yStr := b64.StdEncoding.EncodeToString(y.ToBytesS())
	proofStr := b64.StdEncoding.EncodeToString(proof.Bytes())
	//return ...
	fmt.Println("===============================================================")
	fmt.Println("random number", yInt)
	fmt.Println("random", yStr)
	fmt.Println("proof", proofStr)

	isValid, err = PublicVerify(byteOfTx, yStr, proofStr, pubKeyStr)

	if err != nil || !isValid {
		fmt.Println(err)
		panic("something went wrong ...")
	}
	fmt.Println("--=-----")
	fmt.Println(isValid)

}

func main() {

	//Demo Get Random
	//getRand()

	//Config Server VF infomation
	var gkeyString = "bq+wTtNofW3V7RSjIhg7F9k5z5uoLnonLjNol64QWpM="
	var pubKeyStr = "+qD1jlvW68lQ1rba9QhYkiiYjJf8ycU+mhAFrc1KevQ="

	// Your infomation
	var yStr = "u8Opj5v0NUjsrXxeXb4C6vkcuE+DSZDrDGZ5G/yidQI="
	var proofStr = "wUB2dRgZmoVzMJNp56tYe5OpNt9EZz5opqzeHVAfEox2Qs8qTDLGUBraDVUSmqClQnVZSXxi5cpuVIAshaaU8DRc3MW0IrdHuTdrT4YJ9RHmPUBgUmCOM/SBtJ+D5ntkm01gHv/aauKQZig9UiKtF+SWeK8O8e3+wLzxvYWaZwI="
	byteOfTx := []byte("0c402e678d8ecc04cb42d73ff75c24c741859a86300dab441186fdb9b319cd4a")

	gkeyBytes, _ := b64.StdEncoding.DecodeString(gkeyString)
	g.FromBytesS(gkeyBytes)
	var isValid, err = PublicVerify(byteOfTx, yStr, proofStr, pubKeyStr)

	if err != nil || !isValid {
		fmt.Println(err)
		panic("something went wrong ...")
	}
	fmt.Println("--=-----")
	fmt.Println(isValid)

}
