// Claude thinking signature validation.
//
// Spec reference: SIGNATURE-CHANNEL-SPEC.md
//
// Encoding detection (Spec section 3)
//
// Claude signatures use base64 encoding in one or two layers. The raw string's
// first character determines the encoding depth. This is mathematically
// equivalent to the spec's "decode first, check byte" approach:
//
//   - E prefix: single-layer, payload[0] == 0x12, first 6 bits = 000100,
//     base64 index 4 = E.
//   - R prefix: double-layer, inner[0] == E (0x45), first 6 bits = 010001,
//     base64 index 17 = R.
//   - Q prefix: double-layer CAQS, inner[0] == C (0x43); inspected separately
//     with the observed Google version-4 thinking channel schema.
//
// Classic signatures normalize to R-form before Antigravity replay. Valid
// Q-form signatures keep their original wrapper unchanged.
//
// # Protobuf structure (Spec sections 4.1 and 4.2) in strict mode only
//
// After base64 decoding to raw bytes, the first byte must be 0x12:
//
//	Top-level protobuf
//	|- Field 2 (bytes): container                    -> extractClaudeBytesField(payload, 2)
//	|  |- Field 1 (bytes): channel block             -> extractClaudeBytesField(container, 1)
//	|  |  |- Field 1 (varint): channel_id [required] -> routing_class (11 | 12)
//	|  |  |- Field 2 (varint): infra [optional]      -> infrastructure_class (aws=1 | google=2)
//	|  |  |- Field 3 (varint): version=2             -> skipped
//	|  |  |- Field 5 (bytes): ECDSA sig              -> skipped, per Spec section 11
//	|  |  |- Field 6 (bytes): model_text [optional]  -> schema_features
//	|  |  `- Field 7 (varint): unknown [optional]    -> schema_features
//	|  |- Field 2 (bytes): nonce 12B                 -> skipped
//	|  |- Field 3 (bytes): session 12B               -> skipped
//	|  |- Field 4 (bytes): SHA-384 48B               -> skipped
//	|  `- Field 5 (bytes): metadata                  -> skipped, per Spec section 11
//	`- Field 3 (varint): =1                          -> skipped
//
// Output dimensions (Spec section 8)
//
//	routing_class:        routing_class_11 | routing_class_12 | unknown
//	infrastructure_class: infra_default (absent) | infra_aws (1) | infra_google (2) | infra_unknown
//	schema_features:      compact_schema (len 70-72, no f6/f7) | extended_model_tagged_schema (f6 exists) | unknown
//	legacy_route_hint:    only for ch=11, legacy_default_group | legacy_aws_group | legacy_vertex_direct/proxy
//
// # Compatibility
//
// Verified against all confirmed spec samples (Anthropic Max 20x, Azure,
// Vertex, Bedrock) and legacy ch=11 signatures. Both single-layer (E) and
// double-layer (R) encodings are supported. Historical cache-mode modelGroup#
// prefixes are stripped.
//
// # CAIS envelopes (newer Claude Code models)
//
// Newer Claude Code models wrap the channel block in a CAIS envelope whose
// decoded payload starts with 0x08 (top-level field 1 varint) instead of 0x12,
// so the base64 string starts with 'C' instead of 'E'/'R'. For the model-tagged
// generation, the envelope version varint in top-level field 1 is the only
// structural difference from the classic layout above; everything below it is
// unchanged.
//
// The model-tagged channel generation is shared by both envelopes: channel_id
// 16, no infra field 2, plus a block kind (field 8) and a context id (field 11).
// Observed traffic confirms this schema appears under the classic 0x12 envelope
// (opus-4-6/4-7/4-8, sonnet-5) and the CAIS envelope (opus-5, fable-5), so
// envelope form and channel schema generation vary independently and must not be
// inferred from each other:
//
//	Model-tagged CAIS protobuf
//	|- Field 1 (varint): envelope version [required marker, observed as 2]
//	|- Field 2 (bytes): container [required]
//	|  |- Field 1 (bytes): channel block [required]
//	|  |  |- Field 1  (varint): channel_id [required, observed as 16]
//	|  |  |- Field 3  (varint): version [optional, observed as 2]
//	|  |  |- Field 5  (bytes):  opaque signature bytes [required, observed as 64B]
//	|  |  |- Field 6  (bytes):  model_text [required, "claude-" prefixed]
//	|  |  |- Field 7  (varint): unknown [optional, observed as 1]
//	|  |  |- Field 8  (bytes):  block kind [optional, observed as "thinking"]
//	|  |  `- Field 11 (bytes):  context id [optional, canonical UUID]
//	|  |- Field 2 (bytes): nonce [observed as 12B, not required]
//	|  |- Field 3 (bytes): session [observed as 12B, not required]
//	|  |- Field 4 (bytes): digest [observed as 48B, not required]
//	|  `- Field 5 (bytes): opaque carrier [observed non-empty, not required]
//	`- Field 3 (varint): trailer [optional, observed as 1]
//
// The model-free generation keeps the same outer container wire layout but
// removes the two channel fields that carried signature bytes and model text.
// Its opaque carrier remains in container field 5. Independent captures of both
// generations corroborate the same field-1 channel spine, 12/12/48 field widths,
// and non-empty field 5; the widths remain descriptive rather than load-bearing:
//
//	Model-free CAIS protobuf
//	|- Field 1 (varint): envelope version [required, known generation set]
//	|- Field 2 (bytes): container [required]
//	|  |- Field 1 (bytes): channel block [required]
//	|  |  |- Field 1  (varint): channel_id [required, known generation set]
//	|  |  |- Field 3  (varint): version [optional]
//	|  |  |- Field 5  (bytes):  ABSENT
//	|  |  |- Field 6  (bytes):  ABSENT
//	|  |  |- Field 7  (varint): unknown [optional]
//	|  |  |- Field 8  (bytes):  block kind [optional]
//	|  |  `- Field 11 (bytes):  context id [optional, canonical UUID]
//	|  |- Field 2 (bytes): nonce [observed as 12B, not required]
//	|  |- Field 3 (bytes): session [observed as 12B, not required]
//	|  |- Field 4 (bytes): digest [observed as 48B, not required]
//	|  `- Field 5 (bytes): opaque signing carrier [required, non-empty]
//	`- Field 3 (varint): trailer [optional]
//
// CAIS validation is structural rather than an exact replay of the observed
// bytes. The payload is an opaque upstream-issued blob and rejecting it drops
// the whole thinking block. Model-tagged envelopes retain their literal
// "claude-" classification marker. Model-free envelopes instead require the
// complete container/channel tree, absent channel fields 5 and 6, a non-empty
// container field 5 carrier, and known envelope/channel generation identifiers.
// Observed-but-incidental channel-version, field-7, and trailer values are
// checked only for wire type, so an upstream value bump cannot silently erase
// conversation history. Block kind combines both policies deliberately: an
// omitted channel field 8 is not a defect, legacy generations accept any
// well-formed UTF-8 kind, and a CAQS generation (envelope version >= 4, e.g.
// claude-fable-5-1) accepts the kinds its signatures are known to carry --
// "thinking" and "narration" from CAQS captures, plus "tool_use", which the
// model-free compatibility corpus pins. An explicitly present unrecognized kind
// on a CAQS generation is therefore rejected while an absent one is not.
//
// This parser performs no cryptographic verification. The model-tagged branch
// checks only that opaque signature bytes and the model marker are present, and
// the model-free branch is likewise a narrow syntactic heuristic. No
// payload-only discriminator for model-free CAIS is both generation-stable and
// provider-distinguishing. Proof of origin requires trusted provenance from the
// response path or cache envelope, so this result must never be treated as
// authentication. Measured adversarial controls for the predicate that ships:
//
//	uniform-random, first byte forced 0x08       n=1,000,000  shipped=0      spine-only=0
//	random well-formed protobuf, 0x08 first      n=1,000,000  shipped=0      spine-only=25
//	spine-shaped, identifiers randomised         n=200,000    shipped=4,754  (the {2,4}x{16,17} product)
//	spine-shaped, exactly one identifier bumped  n=200,000    shipped=0
//
// The allowlist earns the small measured exclusion over the bare structure in
// the second row. The last row is its residual cost: a future identifier bump
// drops signed history until the list is amended. The executor emits that event
// at operator-visible warning severity with the rejected identifier. Gemini and
// GPT are unreachable here by their 0x12 and 0x80 envelope markers; Kimi and
// Grok have no protobuf tree.
//
// # Which provider emits which envelope
//
// Three providers serve Claude models, and the envelope depends on the model
// generation rather than on the provider:
//
//   - Claude Code OAuth subscription (Claude Code Max): opus-4-5, sonnet-4-6,
//     and later models. Opus-5 and fable-5 emit model-tagged CAIS, fable-5-1
//     emits model-free CAIS, and the opus-4-6/4-7/4-8 and sonnet-5 generation
//     emits the single-layer E envelope.
//   - Claude Messages API: the full Claude model range, same envelopes as the
//     Claude Code OAuth subscription.
//   - Antigravity: legacy Claude models use double-layer R form on Google
//     infrastructure. Claude 5.5 also emits double-layer CAQS (Q-form): one
//     base64 decode yields CAQS, and the second yields an envelope version 4
//     protobuf with Google infrastructure in the channel block. Preserve that
//     wrapper on replay; bare native CAIS/CAQS is not an Antigravity wrapper.
//
// A single conversation therefore mixes envelopes whenever a user switches model
// generations or providers, and every form must stay replayable toward the
// provider that issued it.
package signature

import (
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/tidwall/gjson"
	"google.golang.org/protobuf/encoding/protowire"
)

const MaxClaudeThinkingSignatureLen = 32 * 1024 * 1024

// ClaudeSignatureValidationOptions controls how far Claude thinking signatures
// are inspected. The base validation always checks the cache prefix, base64
// layers, and decoded 0x12 Claude payload marker. Strict mode additionally
// verifies the classic protobuf tree. Q-form always receives full structural
// validation, regardless of these legacy validation options.
type ClaudeSignatureValidationOptions struct {
	// PrefixOnly checks the legacy E/R prefix or a fully validated Q envelope.
	// Use it to preserve legacy shallow cleanup without blindly allowing Q.
	PrefixOnly bool
	// Base64Only checks the optional cache prefix, E/R Claude signature prefix,
	// and base64 layers without validating the decoded Claude marker or protobuf
	// tree for legacy E/R; Q envelopes always receive structural validation.
	// Use it for conservative request cleanup.
	Base64Only bool
	// AllowEmptySignatureWithEmptyText preserves empty thinking placeholders with
	// no signature and no thinking/text payload during strip operations.
	AllowEmptySignatureWithEmptyText bool
	Strict                           bool
}

// ClaudeSignatureTree describes the protobuf fields currently used for Claude
// thinking signature routing.
type ClaudeSignatureTree struct {
	EncodingLayers      int
	ChannelID           uint64
	Field2              *uint64
	RoutingClass        string
	InfrastructureClass string
	SchemaFeatures      string
	ModelText           string
	LegacyRouteHint     string
	HasField7           bool
}

func claudeSignatureValidationOptions(opts []ClaudeSignatureValidationOptions) ClaudeSignatureValidationOptions {
	if len(opts) == 0 {
		return ClaudeSignatureValidationOptions{}
	}
	return opts[0]
}

// IsValidClaudeThinkingSignature returns whether rawSignature is a valid Claude
// thinking signature under the requested validation options.
func IsValidClaudeThinkingSignature(rawSignature string, opts ...ClaudeSignatureValidationOptions) bool {
	opt := claudeSignatureValidationOptions(opts)
	if opt.PrefixOnly {
		return HasClaudeThinkingSignaturePrefix(rawSignature)
	}
	if opt.Base64Only {
		return HasDecodableClaudeThinkingSignature(rawSignature)
	}
	_, err := NormalizeClaudeThinkingSignature(rawSignature, opts...)
	return err == nil
}

// HasDecodableClaudeThinkingSignature checks legacy E/R encoding or a strictly
// validated Antigravity double-layer CAQS envelope.
func HasDecodableClaudeThinkingSignature(rawSignature string) bool {
	sig := stripClaudeSignaturePrefix(rawSignature)
	if sig == "" || len(sig) > MaxClaudeThinkingSignatureLen {
		return false
	}

	switch sig[0] {
	case 'Q':
		_, err := InspectAntigravityClaudeCAQSSignature(sig)
		return err == nil
	case 'E':
		decoded, err := base64.StdEncoding.DecodeString(sig)
		return err == nil && len(decoded) > 0
	case 'R':
		decoded, err := base64.StdEncoding.DecodeString(sig)
		if err != nil || len(decoded) == 0 || decoded[0] != 'E' {
			return false
		}
		innerDecoded, err := base64.StdEncoding.DecodeString(string(decoded))
		return err == nil && len(innerDecoded) > 0
	default:
		return false
	}
}

// HasClaudeThinkingSignaturePrefix reports whether rawSignature has the Claude
// E/R prefix or a structurally validated Q envelope after cache-prefix removal.
func HasClaudeThinkingSignaturePrefix(rawSignature string) bool {
	sig := stripClaudeSignaturePrefix(rawSignature)
	if sig == "" {
		return false
	}
	if sig[0] == 'Q' {
		_, err := InspectAntigravityClaudeCAQSSignature(sig)
		return err == nil
	}
	return sig[0] == 'E' || sig[0] == 'R'
}

func stripClaudeSignaturePrefix(rawSignature string) string {
	sig := strings.TrimSpace(rawSignature)
	if sig == "" {
		return ""
	}
	if idx := strings.IndexByte(sig, '#'); idx >= 0 {
		sig = strings.TrimSpace(sig[idx+1:])
	}
	return sig
}

// ValidateClaudeThinkingSignatures validates every thinking block signature in a
// Claude messages payload.
func ValidateClaudeThinkingSignatures(inputRawJSON []byte, opts ...ClaudeSignatureValidationOptions) error {
	messages := gjson.GetBytes(inputRawJSON, "messages")
	if !messages.IsArray() {
		return nil
	}

	opt := claudeSignatureValidationOptions(opts)
	messageResults := messages.Array()
	for i := 0; i < len(messageResults); i++ {
		contentResults := messageResults[i].Get("content")
		if !contentResults.IsArray() {
			continue
		}
		parts := contentResults.Array()
		for j := 0; j < len(parts); j++ {
			part := parts[j]
			if part.Get("type").String() != "thinking" {
				continue
			}

			rawSignature := strings.TrimSpace(part.Get("signature").String())
			if rawSignature == "" {
				return fmt.Errorf("messages[%d].content[%d]: missing thinking signature", i, j)
			}

			if _, err := NormalizeClaudeThinkingSignature(rawSignature, opt); err != nil {
				return fmt.Errorf("messages[%d].content[%d]: %w", i, j, err)
			}
		}
	}

	return nil
}

// NormalizeClaudeThinkingSignature strips any cache prefix, validates the
// signature, and returns the double-layer R or Q form expected by Antigravity.
// Q envelopes always require structural validation, even in shallow modes.
func NormalizeClaudeThinkingSignature(rawSignature string, opts ...ClaudeSignatureValidationOptions) (string, error) {
	opt := claudeSignatureValidationOptions(opts)
	sig := stripClaudeSignaturePrefix(rawSignature)
	if sig == "" {
		return "", fmt.Errorf("empty signature")
	}

	if len(sig) > MaxClaudeThinkingSignatureLen {
		return "", fmt.Errorf("signature exceeds maximum length (%d bytes)", MaxClaudeThinkingSignatureLen)
	}

	switch sig[0] {
	case 'Q':
		if _, err := InspectAntigravityClaudeCAQSSignature(sig); err != nil {
			return "", err
		}
		return sig, nil
	case 'R':
		if err := validateClaudeDoubleLayerSignature(sig, opt); err != nil {
			return "", err
		}
		return sig, nil
	case 'E':
		if err := validateClaudeSingleLayerSignature(sig, opt); err != nil {
			return "", err
		}
		return base64.StdEncoding.EncodeToString([]byte(sig)), nil
	default:
		return "", fmt.Errorf("invalid signature: expected 'E', 'R' or 'Q' prefix, got %q", string(sig[0]))
	}
}

// NormalizeClaudeProviderNativeThinkingSignature strips any cache prefix,
// validates the signature, and returns the single-layer E-form expected by
// Claude-native providers.
func NormalizeClaudeProviderNativeThinkingSignature(rawSignature string, opts ...ClaudeSignatureValidationOptions) (string, error) {
	opt := claudeSignatureValidationOptions(opts)
	sig := stripClaudeSignaturePrefix(rawSignature)
	if sig == "" {
		return "", fmt.Errorf("empty signature")
	}

	if len(sig) > MaxClaudeThinkingSignatureLen {
		return "", fmt.Errorf("signature exceeds maximum length (%d bytes)", MaxClaudeThinkingSignatureLen)
	}

	switch sig[0] {
	case 'E':
		if err := validateClaudeSingleLayerSignature(sig, opt); err != nil {
			return "", err
		}
		return sig, nil
	case 'R':
		if err := validateClaudeDoubleLayerSignature(sig, opt); err != nil {
			return "", err
		}
		decoded, err := base64.StdEncoding.DecodeString(sig)
		if err != nil {
			return "", fmt.Errorf("invalid double-layer signature: base64 decode failed: %w", err)
		}
		return string(decoded), nil
	default:
		return "", fmt.Errorf("invalid signature: expected 'E' or 'R' prefix, got %q", string(sig[0]))
	}
}

func validateClaudeDoubleLayerSignature(sig string, opt ClaudeSignatureValidationOptions) error {
	decoded, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return fmt.Errorf("invalid double-layer signature: base64 decode failed: %w", err)
	}
	if len(decoded) == 0 {
		return fmt.Errorf("invalid double-layer signature: empty after decode")
	}
	if decoded[0] != 'E' {
		return fmt.Errorf("invalid double-layer signature: inner does not start with 'E', got 0x%02x", decoded[0])
	}
	return validateClaudeSingleLayerSignatureContent(string(decoded), 2, opt)
}

func validateClaudeSingleLayerSignature(sig string, opt ClaudeSignatureValidationOptions) error {
	return validateClaudeSingleLayerSignatureContent(sig, 1, opt)
}

func validateClaudeSingleLayerSignatureContent(sig string, encodingLayers int, opt ClaudeSignatureValidationOptions) error {
	decoded, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return fmt.Errorf("invalid single-layer signature: base64 decode failed: %w", err)
	}
	if len(decoded) == 0 {
		return fmt.Errorf("invalid single-layer signature: empty after decode")
	}
	if decoded[0] != 0x12 {
		return fmt.Errorf("invalid Claude signature: expected first byte 0x12, got 0x%02x", decoded[0])
	}
	if !opt.Strict {
		return nil
	}
	_, err = InspectClaudeSignaturePayload(decoded, encodingLayers)
	return err
}

// InspectClaudeDoubleLayerSignature decodes and inspects a double-layer Claude
// thinking signature.
func InspectClaudeDoubleLayerSignature(sig string) (*ClaudeSignatureTree, error) {
	decoded, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return nil, fmt.Errorf("invalid double-layer signature: base64 decode failed: %w", err)
	}
	if len(decoded) == 0 {
		return nil, fmt.Errorf("invalid double-layer signature: empty after decode")
	}
	if decoded[0] != 'E' {
		return nil, fmt.Errorf("invalid double-layer signature: inner does not start with 'E', got 0x%02x", decoded[0])
	}
	return inspectClaudeSingleLayerSignatureWithLayers(string(decoded), 2)
}

// InspectClaudeSingleLayerSignature decodes and inspects a single-layer Claude
// thinking signature.
func InspectClaudeSingleLayerSignature(sig string) (*ClaudeSignatureTree, error) {
	return inspectClaudeSingleLayerSignatureWithLayers(sig, 1)
}

func inspectClaudeSingleLayerSignatureWithLayers(sig string, encodingLayers int) (*ClaudeSignatureTree, error) {
	decoded, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return nil, fmt.Errorf("invalid single-layer signature: base64 decode failed: %w", err)
	}
	if len(decoded) == 0 {
		return nil, fmt.Errorf("invalid single-layer signature: empty after decode")
	}
	return InspectClaudeSignaturePayload(decoded, encodingLayers)
}

// InspectClaudeSignaturePayload inspects the decoded Claude thinking signature
// protobuf payload.
func InspectClaudeSignaturePayload(payload []byte, encodingLayers int) (*ClaudeSignatureTree, error) {
	if len(payload) == 0 {
		return nil, fmt.Errorf("invalid Claude signature: empty payload")
	}
	if payload[0] != 0x12 {
		return nil, fmt.Errorf("invalid Claude signature: expected first byte 0x12, got 0x%02x", payload[0])
	}
	container, err := extractClaudeBytesField(payload, 2, "top-level protobuf")
	if err != nil {
		return nil, err
	}
	channelBlock, err := extractClaudeBytesField(container, 1, "Claude Field 2 container")
	if err != nil {
		return nil, err
	}
	return inspectClaudeChannelBlock(channelBlock, encodingLayers)
}

func inspectClaudeChannelBlock(channelBlock []byte, encodingLayers int) (*ClaudeSignatureTree, error) {
	tree := &ClaudeSignatureTree{
		EncodingLayers:      encodingLayers,
		RoutingClass:        "unknown",
		InfrastructureClass: "infra_unknown",
		SchemaFeatures:      "unknown_schema_features",
	}
	haveChannelID := false
	hasField6 := false
	hasField7 := false

	err := walkClaudeProtobufFields(channelBlock, func(num protowire.Number, typ protowire.Type, raw []byte) error {
		switch num {
		case 1:
			if typ != protowire.VarintType {
				return fmt.Errorf("invalid Claude signature: Field 2.1.1 channel_id must be varint")
			}
			channelID, err := decodeClaudeVarintField(raw, "Field 2.1.1 channel_id")
			if err != nil {
				return err
			}
			tree.ChannelID = channelID
			haveChannelID = true
		case 2:
			if typ != protowire.VarintType {
				return fmt.Errorf("invalid Claude signature: Field 2.1.2 field2 must be varint")
			}
			field2, err := decodeClaudeVarintField(raw, "Field 2.1.2 field2")
			if err != nil {
				return err
			}
			tree.Field2 = &field2
		case 6:
			if typ != protowire.BytesType {
				return fmt.Errorf("invalid Claude signature: Field 2.1.6 model_text must be bytes")
			}
			modelBytes, err := decodeClaudeBytesField(raw, "Field 2.1.6 model_text")
			if err != nil {
				return err
			}
			if !utf8.Valid(modelBytes) {
				return fmt.Errorf("invalid Claude signature: Field 2.1.6 model_text is not valid UTF-8")
			}
			tree.ModelText = string(modelBytes)
			hasField6 = true
		case 7:
			if typ != protowire.VarintType {
				return fmt.Errorf("invalid Claude signature: Field 2.1.7 must be varint")
			}
			if _, err := decodeClaudeVarintField(raw, "Field 2.1.7"); err != nil {
				return err
			}
			hasField7 = true
			tree.HasField7 = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !haveChannelID {
		return nil, fmt.Errorf("invalid Claude signature: missing Field 2.1.1 channel_id")
	}

	switch tree.ChannelID {
	case 11:
		tree.RoutingClass = "routing_class_11"
	case 12:
		tree.RoutingClass = "routing_class_12"
	}

	if tree.Field2 == nil {
		tree.InfrastructureClass = "infra_default"
	} else {
		switch *tree.Field2 {
		case 1:
			tree.InfrastructureClass = "infra_aws"
		case 2:
			tree.InfrastructureClass = "infra_google"
		default:
			tree.InfrastructureClass = "infra_unknown"
		}
	}

	switch {
	case hasField6:
		tree.SchemaFeatures = "extended_model_tagged_schema"
	case !hasField6 && !hasField7 && len(channelBlock) >= 70 && len(channelBlock) <= 72:
		tree.SchemaFeatures = "compact_schema"
	}

	if tree.ChannelID == 11 {
		switch {
		case tree.Field2 == nil:
			tree.LegacyRouteHint = "legacy_default_group"
		case *tree.Field2 == 1:
			tree.LegacyRouteHint = "legacy_aws_group"
		case *tree.Field2 == 2 && tree.EncodingLayers == 2:
			tree.LegacyRouteHint = "legacy_vertex_direct"
		case *tree.Field2 == 2 && tree.EncodingLayers == 1:
			tree.LegacyRouteHint = "legacy_vertex_proxy"
		}
	}

	return tree, nil
}

func extractClaudeBytesField(msg []byte, fieldNum protowire.Number, scope string) ([]byte, error) {
	var value []byte
	err := walkClaudeProtobufFields(msg, func(num protowire.Number, typ protowire.Type, raw []byte) error {
		if num != fieldNum {
			return nil
		}
		if typ != protowire.BytesType {
			return fmt.Errorf("invalid Claude signature: %s field %d must be bytes", scope, fieldNum)
		}
		bytesValue, err := decodeClaudeBytesField(raw, fmt.Sprintf("%s field %d", scope, fieldNum))
		if err != nil {
			return err
		}
		value = bytesValue
		return nil
	})
	if err != nil {
		return nil, err
	}
	if value == nil {
		return nil, fmt.Errorf("invalid Claude signature: missing %s field %d", scope, fieldNum)
	}
	return value, nil
}

func walkClaudeProtobufFields(msg []byte, visit func(num protowire.Number, typ protowire.Type, raw []byte) error) error {
	for offset := 0; offset < len(msg); {
		num, typ, n := protowire.ConsumeTag(msg[offset:])
		if n < 0 {
			return fmt.Errorf("invalid Claude signature: malformed protobuf tag: %w", protowire.ParseError(n))
		}
		offset += n
		valueLen := protowire.ConsumeFieldValue(num, typ, msg[offset:])
		if valueLen < 0 {
			return fmt.Errorf("invalid Claude signature: malformed protobuf field %d: %w", num, protowire.ParseError(valueLen))
		}
		fieldRaw := msg[offset : offset+valueLen]
		if err := visit(num, typ, fieldRaw); err != nil {
			return err
		}
		offset += valueLen
	}
	return nil
}

func decodeClaudeVarintField(raw []byte, label string) (uint64, error) {
	value, n := protowire.ConsumeVarint(raw)
	if n < 0 {
		return 0, fmt.Errorf("invalid Claude signature: failed to decode %s: %w", label, protowire.ParseError(n))
	}
	return value, nil
}

func decodeClaudeBytesField(raw []byte, label string) ([]byte, error) {
	value, n := protowire.ConsumeBytes(raw)
	if n < 0 {
		return nil, fmt.Errorf("invalid Claude signature: failed to decode %s: %w", label, protowire.ParseError(n))
	}
	return value, nil
}

const (
	// claudeCAISSignatureMarker is the decoded first byte identifying the CAIS
	// envelope (protobuf tag for top-level field 1, varint).
	claudeCAISSignatureMarker = 0x08

	// claudeCAISModelTextPrefix is the model_text prefix that distinguishes a
	// model-tagged CAIS channel block from an arbitrary protobuf payload.
	claudeCAISModelTextPrefix = "claude-"
)

// Model-free CAIS envelopes use explicit known-generation allowlists in
// addition to the structural spine. This is release bookkeeping, not
// cryptographic verification or the source of cross-provider separation. The
// two lists deliberately form a Cartesian product. This policy allows the two
// separately versioned protobuf layers to roll independently; pair-locking would
// instead drop signed history during a staggered rollout. It accepts combinations
// not yet seen in a model-free capture, but only when both identifiers are
// independently observed CAIS generations and the complete model-free spine is
// present. When Anthropic
// adds a generation, confirm its complete protobuf tree against captures, then
// add its envelope version or channel id here. Channel id 11 is intentionally
// absent because it has only been observed under the legacy 0x12 envelope, never
// under CAIS.
var (
	knownClaudeCAISEnvelopeVersions = [...]uint64{2, 4}
	knownClaudeCAISChannelIDs       = [...]uint64{16, 17}
)

// ClaudeCAISUnknownGenerationError identifies a structurally valid model-free
// CAIS signature whose envelope version or channel ID is not yet recognized.
type ClaudeCAISUnknownGenerationError struct {
	identifier string
	value      uint64
}

func (e *ClaudeCAISUnknownGenerationError) Error() string {
	return fmt.Sprintf("invalid Claude model-free CAIS signature: unknown %s %d", e.identifier, e.value)
}

// ClaudeCAISSignatureInfo describes the locally inspected structure of a Claude
// CAIS thinking signature.
type ClaudeCAISSignatureInfo struct {
	FirstByte       byte
	EnvelopeVersion uint64
	Infrastructure  *uint64
	ChannelID       uint64
	ModelText       string
	BlockKind       string
	ContextID       string

	SignatureLen         int
	SignatureInContainer bool
}

// IsValidClaudeCAISSignature reports whether rawSignature has a recognized
// Claude CAIS thinking-signature format. It does not verify cryptographic
// authenticity.
func IsValidClaudeCAISSignature(rawSignature string) bool {
	_, err := InspectClaudeCAISSignature(rawSignature)
	return err == nil
}

// InspectClaudeCAISSignature decodes and classifies a Claude CAIS thinking
// signature syntactically. See the CAIS envelope section in this file's package
// comment for the layout and for why recognition is structural rather than
// exact. This function does not verify cryptographic authenticity.
func InspectClaudeCAISSignature(rawSignature string) (*ClaudeCAISSignatureInfo, error) {
	sig := stripClaudeSignaturePrefix(rawSignature)
	if sig == "" {
		return nil, fmt.Errorf("empty signature")
	}
	if len(sig) > MaxClaudeThinkingSignatureLen {
		return nil, fmt.Errorf("signature exceeds maximum length (%d bytes)", MaxClaudeThinkingSignatureLen)
	}
	// A payload whose first byte is 0x08 always base64-encodes to a string
	// starting with 'C' (0x08>>2 == 2). Checking that first keeps this validator
	// cheap on the hot paths that probe every signature, since classic Claude
	// (E/R) and Gemini envelopes are rejected without a base64 decode.
	if sig[0] != 'C' {
		return nil, fmt.Errorf("invalid Claude CAIS signature: expected 'C' prefix, got %q", string(sig[0]))
	}

	decoded, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return nil, fmt.Errorf("invalid Claude CAIS signature: base64 decode failed: %w", err)
	}
	return inspectClaudeCAISPayload(decoded, false)
}

// inspectClaudeCAISPayload shares native envelope parsing with the Q replay gate.
// Only Q rejects duplicate submessages; native CAIS/CAQS behavior is unchanged.
func inspectClaudeCAISPayload(decoded []byte, rejectDuplicateMessages bool) (*ClaudeCAISSignatureInfo, error) {
	if len(decoded) == 0 {
		return nil, fmt.Errorf("invalid Claude CAIS signature: empty after decode")
	}
	if decoded[0] != claudeCAISSignatureMarker {
		return nil, fmt.Errorf("invalid Claude CAIS signature: expected first byte 0x%02x, got 0x%02x", claudeCAISSignatureMarker, decoded[0])
	}

	info := &ClaudeCAISSignatureInfo{FirstByte: decoded[0]}

	var container []byte
	var haveContainer, haveEnvelopeVersion bool
	err := walkClaudeProtobufFields(decoded, func(num protowire.Number, typ protowire.Type, raw []byte) error {
		switch num {
		case 1:
			value, errField := decodeClaudeCAISVarint(raw, typ, "CAIS top-level field 1 envelope version")
			if errField != nil {
				return errField
			}
			info.EnvelopeVersion = value
			haveEnvelopeVersion = true
		case 2:
			if rejectDuplicateMessages && haveContainer {
				return fmt.Errorf("invalid Antigravity CAQS signature: duplicate container")
			}
			haveContainer = true
			value, errField := decodeClaudeCAISBytes(raw, typ, "CAIS top-level field 2 container")
			if errField != nil {
				return errField
			}
			container = value
		case 3:
			if _, errField := decodeClaudeCAISVarint(raw, typ, "CAIS top-level field 3 trailer"); errField != nil {
				return errField
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if container == nil {
		return nil, fmt.Errorf("invalid Claude CAIS signature: missing top-level field 2 container")
	}

	var channelBlock, containerCarrier []byte
	var containerCarrierType protowire.Type
	var haveChannelBlock, haveContainerCarrier bool
	err = walkClaudeProtobufFields(container, func(num protowire.Number, typ protowire.Type, raw []byte) error {
		switch num {
		case 1:
			if rejectDuplicateMessages && haveChannelBlock {
				return fmt.Errorf("invalid Antigravity CAQS signature: duplicate channel block")
			}
			haveChannelBlock = true
			value, errField := decodeClaudeCAISBytes(raw, typ, "CAIS container field 1 channel block")
			if errField != nil {
				return errField
			}
			channelBlock = value
		case 5:
			haveContainerCarrier = true
			containerCarrierType = typ
			if typ == protowire.BytesType {
				value, errField := decodeClaudeBytesField(raw, "CAIS container field 5 carrier")
				if errField != nil {
					return errField
				}
				containerCarrier = value
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if channelBlock == nil {
		return nil, fmt.Errorf("invalid Claude CAIS signature: missing container field 1 channel block")
	}

	var haveChannelID, haveSignatureBytes, haveModelText, haveBlockKind bool
	err = walkClaudeProtobufFields(channelBlock, func(num protowire.Number, typ protowire.Type, raw []byte) error {
		switch num {
		case 1:
			value, errField := decodeClaudeCAISVarint(raw, typ, "CAIS channel field 1 channel_id")
			if errField != nil {
				return errField
			}
			info.ChannelID = value
			haveChannelID = true
		case 2:
			value, errField := decodeClaudeCAISVarint(raw, typ, "CAIS channel field 2 infrastructure")
			if errField != nil {
				return errField
			}
			info.Infrastructure = &value
		case 3:
			if _, errField := decodeClaudeCAISVarint(raw, typ, "CAIS channel field 3 version"); errField != nil {
				return errField
			}
		case 5:
			value, errField := decodeClaudeCAISBytes(raw, typ, "CAIS channel field 5 signature bytes")
			if errField != nil {
				return errField
			}
			if len(value) == 0 {
				return fmt.Errorf("invalid Claude CAIS signature: channel field 5 signature bytes must not be empty")
			}
			info.SignatureLen = len(value)
			haveSignatureBytes = true
		case 6:
			value, errField := decodeClaudeCAISUTF8(raw, typ, "CAIS channel field 6 model_text")
			if errField != nil {
				return errField
			}
			if !strings.HasPrefix(value, claudeCAISModelTextPrefix) {
				return fmt.Errorf("invalid Claude CAIS signature: channel field 6 model_text must start with %q, got %q", claudeCAISModelTextPrefix, value)
			}
			info.ModelText = value
			haveModelText = true
		case 7:
			if _, errField := decodeClaudeCAISVarint(raw, typ, "CAIS channel field 7"); errField != nil {
				return errField
			}
		case 8:
			value, errField := decodeClaudeCAISUTF8(raw, typ, "CAIS channel field 8 block kind")
			if errField != nil {
				return errField
			}
			info.BlockKind = value
			haveBlockKind = true
		case 11:
			value, errField := decodeClaudeCAISUTF8(raw, typ, "CAIS channel field 11 context id")
			if errField != nil {
				return errField
			}
			if !isCanonicalUUID(value) {
				return fmt.Errorf("invalid Claude CAIS signature: channel field 11 context id must be a canonical UUID, got %q", value)
			}
			info.ContextID = value
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !haveChannelID {
		return nil, fmt.Errorf("invalid Claude CAIS signature: missing channel field 1 channel_id")
	}

	// Model-tagged CAIS keeps its established syntactic classifier: non-empty
	// opaque signature bytes plus claude-prefixed model text. Neither field is
	// cryptographically verified, so callers must not treat recognition as proof.
	if haveSignatureBytes || haveModelText {
		if !haveSignatureBytes {
			// Envelope version >= 4 (CAQS) relocates the opaque signature bytes to
			// container field 5 and omits model_text.
			if info.EnvelopeVersion >= 4 && containerCarrierType == protowire.BytesType && len(containerCarrier) > 0 {
				info.SignatureLen = len(containerCarrier)
				info.SignatureInContainer = true
			} else {
				return nil, fmt.Errorf("invalid Claude CAIS signature: missing channel field 5 signature bytes")
			}
		}
		if !haveModelText && info.EnvelopeVersion < 4 {
			return nil, fmt.Errorf("invalid Claude CAIS signature: missing channel field 6 model_text")
		}
		if errBlockKind := validateClaudeCAQSBlockKind(info, haveBlockKind); errBlockKind != nil {
			return nil, errBlockKind
		}
		return info, nil
	}

	// Model-free CAIS has no provider literal. Require its moved carrier and both
	// known generation identifiers, while retaining the model-tagged sibling's
	// tolerance for incidental varint values and optional fields. The carrier is
	// validated before the generation identifiers so malformed input never
	// reports as an unknown generation.
	switch {
	case !haveEnvelopeVersion:
		return nil, fmt.Errorf("invalid Claude model-free CAIS signature: missing envelope version")
	case !haveContainerCarrier:
		return nil, fmt.Errorf("invalid Claude model-free CAIS signature: missing container field 5 carrier")
	case containerCarrierType != protowire.BytesType:
		return nil, fmt.Errorf("invalid Claude model-free CAIS signature: container field 5 carrier must be bytes")
	case len(containerCarrier) == 0:
		return nil, fmt.Errorf("invalid Claude model-free CAIS signature: container field 5 carrier must not be empty")
	case !slices.Contains(knownClaudeCAISEnvelopeVersions[:], info.EnvelopeVersion):
		return nil, &ClaudeCAISUnknownGenerationError{identifier: "envelope version", value: info.EnvelopeVersion}
	case info.Infrastructure == nil && !slices.Contains(knownClaudeCAISChannelIDs[:], info.ChannelID):
		// Native model-free CAIS carries no infrastructure field. Antigravity's
		// CAQS (channel 18 on Google infrastructure) is scoped by
		// InspectAntigravityClaudeCAQSSignature instead.
		return nil, &ClaudeCAISUnknownGenerationError{identifier: "channel_id", value: info.ChannelID}
	}
	if errBlockKind := validateClaudeCAQSBlockKind(info, haveBlockKind); errBlockKind != nil {
		return nil, errBlockKind
	}
	// The relocated carrier is this generation's signature bytes, so callers see
	// the same signature length they see for a model-tagged envelope.
	info.SignatureLen = len(containerCarrier)
	info.SignatureInContainer = true

	return info, nil
}

// claudeCAQSBlockKinds are the channel block kinds a CAQS generation (envelope
// version >= 4) may declare. Channel field 8 is optional, so an omitted kind is
// not a defect; an explicitly present value must be one of these.
var claudeCAQSBlockKinds = [...]string{"thinking", "narration", "tool_use"}

// validateClaudeCAQSBlockKind applies the block-kind contract for the envelope
// generation in use. CAQS (envelope version >= 4) may omit the optional block
// kind, but a value it does supply must be a kind these signatures are known to
// carry: "thinking" and "narration" were observed in CAQS captures, and
// "tool_use" is pinned by the model-free compatibility corpus. Legacy
// generations are unchanged and keep their tolerance for any well-formed UTF-8
// kind, because an upstream value bump there must not erase signed history.
func validateClaudeCAQSBlockKind(info *ClaudeCAISSignatureInfo, haveBlockKind bool) error {
	if info.EnvelopeVersion < 4 || !haveBlockKind || slices.Contains(claudeCAQSBlockKinds[:], info.BlockKind) {
		return nil
	}
	return fmt.Errorf("invalid Claude CAQS signature: expected block kind \"thinking\", \"narration\" or \"tool_use\", got %q", info.BlockKind)
}

func decodeClaudeCAISVarint(raw []byte, typ protowire.Type, label string) (uint64, error) {
	if typ != protowire.VarintType {
		return 0, fmt.Errorf("invalid Claude CAIS signature: %s must be varint", label)
	}
	return decodeClaudeVarintField(raw, label)
}

func decodeClaudeCAISBytes(raw []byte, typ protowire.Type, label string) ([]byte, error) {
	if typ != protowire.BytesType {
		return nil, fmt.Errorf("invalid Claude CAIS signature: %s must be bytes", label)
	}
	return decodeClaudeBytesField(raw, label)
}

func decodeClaudeCAISUTF8(raw []byte, typ protowire.Type, label string) (string, error) {
	value, err := decodeClaudeCAISBytes(raw, typ, label)
	if err != nil {
		return "", err
	}
	if !utf8.Valid(value) {
		return "", fmt.Errorf("invalid Claude CAIS signature: %s must be valid UTF-8", label)
	}
	return string(value), nil
}

func isCanonicalUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		switch i {
		case 8, 13, 18, 23:
			if b != '-' {
				return false
			}
		default:
			if !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')) {
				return false
			}
		}
	}
	return true
}
