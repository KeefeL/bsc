// Package v2 is used for tendermint v0.34.22 and its compatible version.
package lightclient

import (
	"encoding/hex"
	"testing"

	"github.com/bnb-chain/greenfield-tendermint/crypto/ed25519"
	tmproto "github.com/bnb-chain/greenfield-tendermint/proto/tendermint/types"
	"github.com/bnb-chain/greenfield-tendermint/types"
)

type validatorInfo struct {
	pubKey         string
	votingPower    int64
	relayerAddress string
	relayerBlsKey  string
}

var testcases = []struct {
	chainID              string
	height               uint64
	nextValidatorSetHash string
	vals                 []validatorInfo
	consensusStateBytes  string
}{
	{
		chainID:              "chain_9000-121",
		height:               1,
		nextValidatorSetHash: "0CE856B1DC9CDCF3BF2478291CF02C62AEEB3679889E9866931BF1FB05A10EDA",
		vals: []validatorInfo{
			{
				pubKey:         "c3d9a1082f42ca161402f8668f8e39ec9e30092affd8d3262267ac7e248a959e",
				votingPower:    int64(10000),
				relayerAddress: "B32d0723583040F3A16D1380D1e6AA874cD1bdF7",
				relayerBlsKey:  "a60afe627fd78b19e07e07e19d446009dd53a18c6c8744176a5d851a762bbb51198e7e006f2a6ea7225661a61ecd832d",
			},
		},
		consensusStateBytes: "636861696e5f393030302d31323100000000000000000000000000000000000000000000000000010ce856b1dc9cdcf3bf2478291cf02c62aeeb3679889e9866931bf1fb05a10edac3d9a1082f42ca161402f8668f8e39ec9e30092affd8d3262267ac7e248a959e0000000000002710b32d0723583040f3a16d1380d1e6aa874cd1bdf7a60afe627fd78b19e07e07e19d446009dd53a18c6c8744176a5d851a762bbb51198e7e006f2a6ea7225661a61ecd832d",
	},
	{
		chainID:              "chain_9000-121",
		height:               1,
		nextValidatorSetHash: "A5F1AF4874227F1CDBE5240259A365AD86484A4255BFD65E2A0222D733FCDBC3",
		vals: []validatorInfo{
			{
				pubKey:         "20cc466ee9412ddd49e0fff04cdb41bade2b7622f08b6bdacac94d4de03bdb97",
				votingPower:    int64(10000),
				relayerAddress: "d5e63aeee6e6fa122a6a23a6e0fca87701ba1541",
				relayerBlsKey:  "aa2d28cbcd1ea3a63479f6fb260a3d755853e6a78cfa6252584fee97b2ec84a9d572ee4a5d3bc1558bb98a4b370fb861",
			},
			{
				pubKey:         "6b0b523ee91ad18a63d63f21e0c40a83ef15963f4260574ca5159fd90a1c5270",
				votingPower:    int64(10000),
				relayerAddress: "6fd1ceb5a48579f322605220d4325bd9ff90d5fa",
				relayerBlsKey:  "b31e74a881fc78681e3dfa440978d2b8be0708a1cbbca2c660866216975fdaf0e9038d9b7ccbf9731f43956dba7f2451",
			},
			{
				pubKey:         "919606ae20bf5d248ee353821754bcdb456fd3950618fda3e32d3d0fb990eeda",
				votingPower:    int64(10000),
				relayerAddress: "97376a436bbf54e0f6949b57aa821a90a749920a",
				relayerBlsKey:  "b32979580ea04984a2be033599c20c7a0c9a8d121b57f94ee05f5eda5b36c38f6e354c89328b92cdd1de33b64d3a0867",
			},
		},
		consensusStateBytes: "636861696e5f393030302d3132310000000000000000000000000000000000000000000000000001a5f1af4874227f1cdbe5240259a365ad86484a4255bfd65e2a0222d733fcdbc320cc466ee9412ddd49e0fff04cdb41bade2b7622f08b6bdacac94d4de03bdb970000000000002710d5e63aeee6e6fa122a6a23a6e0fca87701ba1541aa2d28cbcd1ea3a63479f6fb260a3d755853e6a78cfa6252584fee97b2ec84a9d572ee4a5d3bc1558bb98a4b370fb8616b0b523ee91ad18a63d63f21e0c40a83ef15963f4260574ca5159fd90a1c527000000000000027106fd1ceb5a48579f322605220d4325bd9ff90d5fab31e74a881fc78681e3dfa440978d2b8be0708a1cbbca2c660866216975fdaf0e9038d9b7ccbf9731f43956dba7f2451919606ae20bf5d248ee353821754bcdb456fd3950618fda3e32d3d0fb990eeda000000000000271097376a436bbf54e0f6949b57aa821a90a749920ab32979580ea04984a2be033599c20c7a0c9a8d121b57f94ee05f5eda5b36c38f6e354c89328b92cdd1de33b64d3a0867",
	},
}

func TestEncodeConsensusState(t *testing.T) {
	for i := 0; i < len(testcases); i++ {
		testcase := testcases[i]

		var validatorSet []*types.Validator

		for j := 0; j < len(testcase.vals); j++ {
			valInfo := testcase.vals[j]
			pubKeyBytes, err := hex.DecodeString(valInfo.pubKey)
			if err != nil {
				t.Fatal("decode pub key failed")
			}
			relayerAddress, err := hex.DecodeString(valInfo.relayerAddress)
			if err != nil {
				t.Fatal("decode relayer address failed")
			}
			relayerBlsKey, err := hex.DecodeString(valInfo.relayerBlsKey)
			if err != nil {
				t.Fatal("decode relayer bls key failed")
			}

			pubkey := ed25519.PubKey(make([]byte, ed25519.PubKeySize))
			copy(pubkey[:], pubKeyBytes)
			validator := types.NewValidator(pubkey, valInfo.votingPower)
			validator.SetRelayerAddress(relayerAddress)
			validator.SetRelayerBlsKey(relayerBlsKey)
			validatorSet = append(validatorSet, validator)
		}

		nextValidatorHash, err := hex.DecodeString(testcase.nextValidatorSetHash)
		if err != nil {
			t.Fatal("decode next validator set hash failed")
		}

		consensusState := ConsensusState{
			ChainID:              testcase.chainID,
			Height:               testcase.height,
			NextValidatorSetHash: nextValidatorHash,
			ValidatorSet: &types.ValidatorSet{
				Validators: validatorSet,
			},
		}

		csBytes, err := consensusState.EncodeConsensusState()
		if err != nil {
			t.Fatalf("Encode consensus state failed, err: %s\n", err)
		}

		t.Log("Encode consensus state success:")
		t.Logf("cs length: %d\n", len(csBytes))
		t.Logf("cs bytes: %s\n", hex.EncodeToString(csBytes))
	}
}

func TestDecodeConsensusState(t *testing.T) {
	for i := 0; i < len(testcases); i++ {
		testcase := testcases[i]

		csBytes, err := hex.DecodeString(testcase.consensusStateBytes)
		if err != nil {
			t.Fatal("decode consensus state failed")
		}

		cs, err := DecodeConsensusState(csBytes)
		if err != nil {
			t.Fatalf("Decode consensus state failed, err: %s\n", err)
		}

		t.Log("Decode consensus state success:")
		t.Logf("chainID: %s\n", cs.ChainID)
		t.Logf("height: %d\n", cs.Height)
		t.Logf("next validator set hash: %s\n", hex.EncodeToString(cs.NextValidatorSetHash))
	}
}

func TestConsensusStateApplyLightBlock(t *testing.T) {
	csBytes, err := hex.DecodeString("677265656e6669656c645f393030302d313231000000000000000000000000000000000000000001a5f1af4874227f1cdbe5240259a365ad86484a4255bfd65e2a0222d733fcdbc320cc466ee9412ddd49e0fff04cdb41bade2b7622f08b6bdacac94d4de03bdb970000000000002710d5e63aeee6e6fa122a6a23a6e0fca87701ba1541aa2d28cbcd1ea3a63479f6fb260a3d755853e6a78cfa6252584fee97b2ec84a9d572ee4a5d3bc1558bb98a4b370fb8616b0b523ee91ad18a63d63f21e0c40a83ef15963f4260574ca5159fd90a1c527000000000000027106fd1ceb5a48579f322605220d4325bd9ff90d5fab31e74a881fc78681e3dfa440978d2b8be0708a1cbbca2c660866216975fdaf0e9038d9b7ccbf9731f43956dba7f2451919606ae20bf5d248ee353821754bcdb456fd3950618fda3e32d3d0fb990eeda000000000000271097376a436bbf54e0f6949b57aa821a90a749920ab32979580ea04984a2be033599c20c7a0c9a8d121b57f94ee05f5eda5b36c38f6e354c89328b92cdd1de33b64d3a0867")
	if err != nil {
		t.Fatal("decode consensus state string failed")
	}

	blockBytes, err := hex.DecodeString("0aa6060a99030a02080b1213677265656e6669656c645f393030302d3132311802220c08d2aafd9e0610d8f9e1eb022a480a204015d7d8169ab6769dbf1f45ee16a190ed46bc00bd0660a5fd820677cad4bde71224080112202457fe25a28709a079ad8c108535331db3f64a8bde4fa9f4d17325af196c68db322026205de8b72d0aec55faca9b7ee9f12a70b0aa790223807ce242f483c862cb853a20e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8554220a5f1af4874227f1cdbe5240259a365ad86484a4255bfd65e2a0222d733fcdbc34a20a5f1af4874227f1cdbe5240259a365ad86484a4255bfd65e2a0222d733fcdbc35220048091bc7ddc283f77bfbf91d73c44da58c3df8a9cbc867405d8b7f3daada22f5a2019f1bd914ccd73076d7f267288077557d0073d0332cc8a6dd90c64fb61a0cacb6220e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8556a20e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8557214181b1681f0a2062e0af512b8052e62cd17824e2e12870308021a480a204c7d6aef71e381a55d2b184f250c0b194f21b4be987bac24e3a8efca0adc92041224080112204d8f2e9efbf01e6db4529a0bd095ba8b3c4c11337a53352abd944f0a900ef15122670802121409207f5faa1bd0a74a13f733724267e65b37b69e1a0b08d8aafd9e0610d8fcb52c22407bb3e5146a9cda4f3712945accfbb67a27f04034c145c6e9ead73266187696447bfa0fca8b9167d2ae0ca4c36751319d12093580c2936c1da0e7d34338205e06226708021214181b1681f0a2062e0af512b8052e62cd17824e2e1a0b08d8aafd9e0610c886e62e224073d8c8d728bbfdf609a8153b1cda13c3659df28fb658eb4d8efb66fcdd0b4ea645f19a8360830d3ab7823dffe54887507a1dc8269a851d4572df264bd943aa06226708021214c057394359aa7259e175ac54d10363e70cae78ea1a0b08d8aafd9e0610f086a131224054f9a07868326636a9a38fac00dae514c45c706858978524a374ff6afc7baff597ae26b0503749789b6ab8f14bd2c469ceb5e1ba4b82c0cf908c8e664597d20012bc040a90010a1409207f5faa1bd0a74a13f733724267e65b37b69e12220a2020cc466ee9412ddd49e0fff04cdb41bade2b7622f08b6bdacac94d4de03bdb9718904e20e0e3feffffffffffff012a30aa2d28cbcd1ea3a63479f6fb260a3d755853e6a78cfa6252584fee97b2ec84a9d572ee4a5d3bc1558bb98a4b370fb8613214d5e63aeee6e6fa122a6a23a6e0fca87701ba15410a88010a14181b1681f0a2062e0af512b8052e62cd17824e2e12220a206b0b523ee91ad18a63d63f21e0c40a83ef15963f4260574ca5159fd90a1c527018904e20904e2a30b31e74a881fc78681e3dfa440978d2b8be0708a1cbbca2c660866216975fdaf0e9038d9b7ccbf9731f43956dba7f245132146fd1ceb5a48579f322605220d4325bd9ff90d5fa0a88010a14c057394359aa7259e175ac54d10363e70cae78ea12220a20919606ae20bf5d248ee353821754bcdb456fd3950618fda3e32d3d0fb990eeda18904e20904e2a30b32979580ea04984a2be033599c20c7a0c9a8d121b57f94ee05f5eda5b36c38f6e354c89328b92cdd1de33b64d3a0867321497376a436bbf54e0f6949b57aa821a90a749920a1290010a1409207f5faa1bd0a74a13f733724267e65b37b69e12220a2020cc466ee9412ddd49e0fff04cdb41bade2b7622f08b6bdacac94d4de03bdb9718904e20e0e3feffffffffffff012a30aa2d28cbcd1ea3a63479f6fb260a3d755853e6a78cfa6252584fee97b2ec84a9d572ee4a5d3bc1558bb98a4b370fb8613214d5e63aeee6e6fa122a6a23a6e0fca87701ba1541")
	if err != nil {
		t.Fatal("decode light block string failed")
	}

	cs, err := DecodeConsensusState(csBytes)
	if err != nil {
		t.Fatalf("Decode consensus state failed, err: %s\n", err)
	}

	var lbpb tmproto.LightBlock
	err = lbpb.Unmarshal(blockBytes)
	if err != nil {
		t.Fatalf("Unmarshal block bytes failed, err: %s\n", err)
	}
	block, err := types.LightBlockFromProto(&lbpb)
	if err != nil {
		t.Fatalf("Convert light block from proto failed, err: %s\n", err)
	}

	validatorSetChanged, err := cs.ApplyLightBlock(block)
	if err != nil {
		t.Fatalf("Apply light block failed: %v\n", err)
	}

	if cs.Height != 2 {
		t.Fatalf("Height is unexpected, expected: 2, actual: %d\n", cs.Height)
	}

	if validatorSetChanged {
		t.Fatalf("Validator set has exchanaged which is not expected.\n")
	}
}
