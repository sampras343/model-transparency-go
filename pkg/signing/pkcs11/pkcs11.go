// Copyright 2025 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pkcs11

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"fmt"
	"math/big"
	"strings"

	"github.com/miekg/pkcs11"
	"github.com/sigstore/model-signing/pkg/config"
	"github.com/sigstore/model-signing/pkg/dsse"
	"github.com/sigstore/model-signing/pkg/interfaces"
	"github.com/sigstore/model-signing/pkg/utils"
	bundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	common "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	bundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"
)

// DefaultModulePaths are standard PKCS#11 module search paths.
var DefaultModulePaths = []string{
	"/usr/lib64/pkcs11/", // Fedora, RHEL, openSUSE
	"/usr/lib/pkcs11/",   // Fedora 32-bit, ArchLinux
}

// Signer implements signing using PKCS#11 with elliptic curve keys.
type Signer struct {
	ctx        *pkcs11.Ctx
	session    pkcs11.SessionHandle
	privateKey pkcs11.ObjectHandle
	publicKey  *ecdsa.PublicKey
	uri        *Pkcs11URI
}

// NewSigner creates a new PKCS#11 signer.
func NewSigner(pkcs11URI string, modulePaths []string) (*Signer, error) {
	uri := NewPkcs11URI()
	if err := uri.Parse(pkcs11URI); err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#11 URI: %w", err)
	}

	// Use default module paths if none provided (matches Python behavior)
	if len(modulePaths) == 0 {
		modulePaths = DefaultModulePaths
	}
	uri.SetModuleDirectories(modulePaths)
	uri.SetAllowAnyModule(true)

	// Get module path
	modulePath, err := uri.GetModule()
	if err != nil {
		return nil, fmt.Errorf("failed to get module: %w", err)
	}

	// Initialize PKCS#11 context
	ctx := pkcs11.New(modulePath)
	if ctx == nil {
		return nil, fmt.Errorf("failed to create PKCS#11 context")
	}

	if err := ctx.Initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize PKCS#11: %w", err)
	}

	// Open session
	session, err := openSession(ctx, uri)
	if err != nil {
		ctx.Finalize()
		ctx.Destroy()
		return nil, fmt.Errorf("failed to open session: %w", err)
	}

	// Find private and public keys
	keyID, label, err := uri.GetKeyIDAndLabel()
	if err != nil {
		ctx.CloseSession(session)
		ctx.Finalize()
		ctx.Destroy()
		return nil, err
	}

	privateKey, err := findObject(ctx, session, pkcs11.CKO_PRIVATE_KEY, keyID, label)
	if err != nil {
		ctx.CloseSession(session)
		ctx.Finalize()
		ctx.Destroy()
		return nil, fmt.Errorf("failed to find private key: %w", err)
	}

	publicKeyHandle, err := findObject(ctx, session, pkcs11.CKO_PUBLIC_KEY, keyID, label)
	if err != nil {
		ctx.CloseSession(session)
		ctx.Finalize()
		ctx.Destroy()
		return nil, fmt.Errorf("failed to find public key: %w", err)
	}

	// Extract public key
	publicKey, err := extractPublicKey(ctx, session, publicKeyHandle)
	if err != nil {
		ctx.CloseSession(session)
		ctx.Finalize()
		ctx.Destroy()
		return nil, fmt.Errorf("failed to extract public key: %w", err)
	}

	// Validate the curve is supported
	if err := checkSupportedECKey(publicKey); err != nil {
		ctx.CloseSession(session)
		ctx.Finalize()
		ctx.Destroy()
		return nil, err
	}

	return &Signer{
		ctx:        ctx,
		session:    session,
		privateKey: privateKey,
		publicKey:  publicKey,
		uri:        uri,
	}, nil
}

// Close closes the PKCS#11 session and context.
func (s *Signer) Close() error {
	if s.session != 0 {
		s.ctx.CloseSession(s.session)
	}
	if s.ctx != nil {
		s.ctx.Finalize()
		s.ctx.Destroy()
	}
	return nil
}

// PublicKey returns the ECDSA public key.
func (s *Signer) PublicKey() *ecdsa.PublicKey {
	return s.publicKey
}

// Sign signs the payload and returns a signature bundle.
func (s *Signer) Sign(payload *interfaces.Payload) (interfaces.SignatureBundle, error) {
	// Serialize payload to JSON
	rawPayload, err := protojson.Marshal(payload.Statement)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Compute PAE (Pre-Authentication Encoding)
	pae := computePAE(rawPayload)

	// Hash the PAE
	hashAlg := getHashAlgorithm(s.publicKey)
	hasher := hashAlg.New()
	hasher.Write(pae)
	digest := hasher.Sum(nil)

	// Sign the digest using PKCS#11
	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}
	if err := s.ctx.SignInit(s.session, mechanism, s.privateKey); err != nil {
		return nil, fmt.Errorf("failed to initialize sign operation: %w", err)
	}
	signature, err := s.ctx.Sign(s.session, digest)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	// Convert P1363 format to ASN.1 DER
	derSig, err := p1363ToASN1(signature)
	if err != nil {
		return nil, fmt.Errorf("failed to convert signature format: %w", err)
	}

	// Create DSSE envelope using local helper and convert to protobuf
	env := dsse.CreateEnvelope(utils.InTotoJSONPayloadType, rawPayload, derSig)
	protoEnv, err := env.ToProtobuf()
	if err != nil {
		return nil, fmt.Errorf("failed to convert envelope to protobuf: %w", err)
	}

	// Create bundle
	bundleObj := &bundle.Bundle{
		MediaType:            bundleMediaType,
		VerificationMaterial: s.getVerificationMaterial(),
		Content: &bundle.Bundle_DsseEnvelope{
			DsseEnvelope: protoEnv,
		},
	}

	return &SignatureBundle{bundle: bundleObj}, nil
}

// getVerificationMaterial returns the verification material for the bundle.
func (s *Signer) getVerificationMaterial() *bundle.VerificationMaterial {
	// Compute SHA256 hash of the public key
	keyHash, err := config.ComputePublicKeyHash(s.publicKey)
	if err != nil {
		// Fallback to empty hint if hash computation fails
		keyHash = ""
	}

	return &bundle.VerificationMaterial{
		Content: &bundle.VerificationMaterial_PublicKey{
			PublicKey: &common.PublicKeyIdentifier{
				Hint: keyHash,
			},
		},
	}
}

// openSession opens a PKCS#11 session based on the URI parameters.
func openSession(ctx *pkcs11.Ctx, uri *Pkcs11URI) (pkcs11.SessionHandle, error) {
	slotID, err := uri.GetSlotID()
	if err != nil {
		return 0, err
	}

	tokenLabel := uri.GetTokenLabel()

	// If slot ID is specified, use it directly
	if slotID >= 0 {
		return openSessionForSlot(ctx, uint(slotID), uri, tokenLabel)
	}

	// Otherwise, search for token by label
	if tokenLabel == "" {
		return 0, fmt.Errorf("need a token due to missing slot-id")
	}

	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return 0, fmt.Errorf("failed to get slot list: %w", err)
	}

	for _, slot := range slots {
		tokenInfo, err := ctx.GetTokenInfo(slot)
		if err != nil {
			continue
		}

		// Token labels are padded to 32 characters
		if trimString(tokenInfo.Label) == tokenLabel {
			return openSessionForSlot(ctx, slot, uri, tokenLabel)
		}
	}

	return 0, fmt.Errorf("could not find a token with label %s in any slots", tokenLabel)
}

// openSessionForSlot opens a session for a specific slot.
func openSessionForSlot(ctx *pkcs11.Ctx, slotID uint, uri *Pkcs11URI, expectedLabel string) (pkcs11.SessionHandle, error) {
	// Verify token label if specified
	if expectedLabel != "" {
		tokenInfo, err := ctx.GetTokenInfo(slotID)
		if err != nil {
			return 0, fmt.Errorf("failed to get token info: %w", err)
		}
		if trimString(tokenInfo.Label) != expectedLabel {
			return 0, fmt.Errorf("the token in slot %d is not called '%s'", slotID, expectedLabel)
		}
	}

	// Open session
	session, err := ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return 0, fmt.Errorf("failed to open session: %w", err)
	}

	// Login if PIN is provided
	if uri.HasPIN() {
		pin, err := uri.GetPIN()
		if err != nil {
			ctx.CloseSession(session)
			return 0, err
		}
		if err := ctx.Login(session, pkcs11.CKU_USER, pin); err != nil {
			ctx.CloseSession(session)
			return 0, fmt.Errorf("failed to login: %w", err)
		}
	}

	return session, nil
}

// findObject finds a PKCS#11 object by class, ID, and/or label.
func findObject(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, class uint, id []byte, label string) (pkcs11.ObjectHandle, error) {
	if id == nil && label == "" {
		return 0, fmt.Errorf("missing search criteria for object: either label or id must be provided in URI")
	}

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
	}

	if err := ctx.FindObjectsInit(session, template); err != nil {
		return 0, fmt.Errorf("failed to init find objects: %w", err)
	}
	defer ctx.FindObjectsFinal(session)

	objects, _, err := ctx.FindObjects(session, 100)
	if err != nil {
		return 0, fmt.Errorf("failed to find objects: %w", err)
	}

	for _, obj := range objects {
		attrs := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
		}

		attrs, err := ctx.GetAttributeValue(session, obj, attrs)
		if err != nil {
			continue
		}

		objID := attrs[0].Value
		objLabel := trimString(string(attrs[1].Value))

		// Check if ID matches (if specified)
		if id != nil && !bytesEqual(objID, id) {
			continue
		}

		// Check if label matches (if specified)
		if label != "" && objLabel != label {
			continue
		}

		return obj, nil
	}

	msg := ""
	if label != "" {
		msg = fmt.Sprintf("label %s", label)
	}
	if id != nil {
		if msg != "" {
			msg += " and "
		}
		msg += fmt.Sprintf("id %x", id)
	}

	return 0, fmt.Errorf("could not find any object with %s", msg)
}

// extractPublicKey extracts an ECDSA public key from a PKCS#11 object.
func extractPublicKey(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, obj pkcs11.ObjectHandle) (*ecdsa.PublicKey, error) {
	attrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	}

	attrs, err := ctx.GetAttributeValue(session, obj, attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to get key attributes: %w", err)
	}

	ecParams := attrs[0].Value
	ecPoint := attrs[1].Value

	// Parse EC parameters to get the curve
	curve, err := parseECParams(ecParams)
	if err != nil {
		return nil, fmt.Errorf("failed to parse EC params: %w", err)
	}

	// EC_POINT is an OCTET STRING containing the point
	var pointBytes []byte
	if _, err := asn1.Unmarshal(ecPoint, &pointBytes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal EC point: %w", err)
	}

	// Convert elliptic.Curve to ecdh.Curve for validation
	var ecdhCurve ecdh.Curve
	switch curve {
	case elliptic.P256():
		ecdhCurve = ecdh.P256()
	case elliptic.P384():
		ecdhCurve = ecdh.P384()
	case elliptic.P521():
		ecdhCurve = ecdh.P521()
	default:
		return nil, fmt.Errorf("unsupported curve")
	}

	// Parse and validate the point using crypto/ecdh (non-deprecated)
	ecdhPubKey, err := ecdhCurve.NewPublicKey(pointBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse EC point: %w", err)
	}

	// Extract coordinates from the validated point bytes
	// Point format: 0x04 || X || Y (uncompressed format)
	if len(pointBytes) < 1 || pointBytes[0] != 0x04 {
		return nil, fmt.Errorf("invalid EC point format")
	}

	coordinateSize := (len(pointBytes) - 1) / 2
	x := new(big.Int).SetBytes(pointBytes[1 : 1+coordinateSize])
	y := new(big.Int).SetBytes(pointBytes[1+coordinateSize:])

	// Verify we used all bytes
	_ = ecdhPubKey // Use the validated key to satisfy linter

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

// parseECParams parses EC parameters to determine the curve.
func parseECParams(params []byte) (elliptic.Curve, error) {
	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(params, &oid); err != nil {
		return nil, fmt.Errorf("failed to unmarshal OID: %w", err)
	}

	// Map OIDs to curves
	switch {
	case oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}): // secp256r1 / P-256
		return elliptic.P256(), nil
	case oid.Equal(asn1.ObjectIdentifier{1, 3, 132, 0, 34}): // secp384r1 / P-384
		return elliptic.P384(), nil
	case oid.Equal(asn1.ObjectIdentifier{1, 3, 132, 0, 35}): // secp521r1 / P-521
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported curve OID: %v", oid)
	}
}

// checkSupportedECKey checks if the elliptic curve key is supported.
func checkSupportedECKey(key *ecdsa.PublicKey) error {
	switch key.Curve {
	case elliptic.P256(), elliptic.P384(), elliptic.P521():
		return nil
	default:
		return fmt.Errorf("unsupported key for curve '%s'", key.Curve.Params().Name)
	}
}

// getHashAlgorithm returns the appropriate hash algorithm for the key.
func getHashAlgorithm(key *ecdsa.PublicKey) crypto.Hash {
	switch key.Curve {
	case elliptic.P256():
		return crypto.SHA256
	case elliptic.P384():
		return crypto.SHA384
	case elliptic.P521():
		return crypto.SHA512
	default:
		return crypto.SHA256
	}
}

// computePAE computes the Pre-Authentication Encoding for DSSE.
func computePAE(payload []byte) []byte {
	payloadType := utils.InTotoJSONPayloadType

	// PAE = "DSSEv1" + SP + LEN(type) + SP + type + SP + LEN(payload) + SP + payload
	pae := []byte("DSSEv1 ")
	pae = append(pae, []byte(fmt.Sprintf("%d ", len(payloadType)))...)
	pae = append(pae, []byte(payloadType)...)
	pae = append(pae, ' ')
	pae = append(pae, []byte(fmt.Sprintf("%d ", len(payload)))...)
	pae = append(pae, payload...)

	return pae
}

// p1363ToASN1 converts a P1363 format signature to ASN.1 DER format.
func p1363ToASN1(p1363Sig []byte) ([]byte, error) {
	// P1363 format is r || s where both are the same length
	if len(p1363Sig)%2 != 0 {
		return nil, fmt.Errorf("invalid P1363 signature length")
	}

	halfLen := len(p1363Sig) / 2
	r := new(big.Int).SetBytes(p1363Sig[:halfLen])
	s := new(big.Int).SetBytes(p1363Sig[halfLen:])

	// ASN.1 DER encoding
	type ecdsaSignature struct {
		R, S *big.Int
	}

	return asn1.Marshal(ecdsaSignature{R: r, S: s})
}

// trimString trims null bytes and spaces from a string.
func trimString(s string) string {
	// Remove null bytes
	for i, c := range s {
		if c == 0 {
			s = s[:i]
			break
		}
	}
	// Trim spaces
	return strings.TrimSpace(s)
}

// bytesEqual compares two byte slices.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
