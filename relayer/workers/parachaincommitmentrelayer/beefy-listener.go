package parachaincommitmentrelayer

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	gethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/blake2b"
	"github.com/sirupsen/logrus"
	rpcOffchain "github.com/snowfork/go-substrate-rpc-client/v2/rpc/offchain"
	"github.com/snowfork/go-substrate-rpc-client/v2/types"
	"golang.org/x/sync/errgroup"

	"github.com/snowfork/polkadot-ethereum/relayer/chain/ethereum"
	"github.com/snowfork/polkadot-ethereum/relayer/chain/parachain"
	"github.com/snowfork/polkadot-ethereum/relayer/chain/relaychain"
	"github.com/snowfork/polkadot-ethereum/relayer/contracts/lightclientbridge"
	chainTypes "github.com/snowfork/polkadot-ethereum/relayer/substrate"
	"github.com/snowfork/polkadot-ethereum/relayer/workers/beefyrelayer/store"
)

//TODO - put in config
const OUR_PARACHAIN_ID = 200

// TODO: This file is currently listening to the relay chain for new beefy justifications. This is temporary, as in
// a follow up PR, it will be changed to listen to Ethereum for new justifications.
// This can't be done yet, as we still need to add block numbers to the Ethereum proofs being submitted
// to the relay chain light client, but will be done once that's complete.

type MessagePackage struct {
	channelID      chainTypes.ChannelID
	commitmentHash types.H256
	commitmentData types.StorageDataRaw
	paraHeadProof  string
	mmrProof       types.GenerateMMRProofResponse
}

type BeefyListener struct {
	ethereumConfig      *ethereum.Config
	ethereumConn        *ethereum.Connection
	lightClientBridge   *lightclientbridge.Contract
	relaychainConn      *relaychain.Connection
	parachainConnection *parachain.Connection
	messages            chan<- MessagePackage
	log                 *logrus.Entry
}

func NewBeefyListener(
	ethereumConfig *ethereum.Config,
	ethereumConn *ethereum.Connection,
	relaychainConn *relaychain.Connection,
	parachainConnection *parachain.Connection,
	messages chan<- MessagePackage,
	log *logrus.Entry) *BeefyListener {
	return &BeefyListener{
		ethereumConfig:      ethereumConfig,
		ethereumConn:        ethereumConn,
		relaychainConn:      relaychainConn,
		parachainConnection: parachainConnection,
		messages:            messages,
		log:                 log,
	}
}

func (li *BeefyListener) Start(ctx context.Context, eg *errgroup.Group) error {

	// Set up light client bridge contract
	lightClientBridgeContract, err := lightclientbridge.NewContract(common.HexToAddress(li.ethereumConfig.LightClientBridge), li.ethereumConn.GetClient())
	if err != nil {
		return err
	}
	li.lightClientBridge = lightClientBridgeContract

	eg.Go(func() error {
		err := li.subBeefyJustifications(ctx)
		return err
	})

	return nil
}

func (li *BeefyListener) onDone(ctx context.Context) error {
	li.log.Info("Shutting down listener...")
	if li.messages != nil {
		close(li.messages)
	}
	return ctx.Err()
}

func (li *BeefyListener) subBeefyJustifications(ctx context.Context) error {
	li.log.Info("Subscribing to relay chain light client for new mmr payloads")

	headers := make(chan *gethTypes.Header, 5)

	li.ethereumConn.GetClient().SubscribeNewHead(ctx, headers)

	for {
		select {
		case <-ctx.Done():
			return li.onDone(ctx)
		case gethheader := <-headers:
			// Query LightClientBridge contract's ContractFinalVerificationSuccessful events
			blockNumber := gethheader.Number.Uint64()
			var lightClientBridgeEvents []*lightclientbridge.ContractFinalVerificationSuccessful

			contractEvents, err := li.queryLightClientEvents(ctx, blockNumber, &blockNumber)
			if err != nil {
				li.log.WithError(err).Error("Failure fetching event logs")
				return err
			}
			lightClientBridgeEvents = append(lightClientBridgeEvents, contractEvents...)

			if len(lightClientBridgeEvents) > 0 {
				li.log.Info(fmt.Sprintf("Found %d LightClientBridge contract events on block %d", len(lightClientBridgeEvents), blockNumber))
			}
			li.processLightClientEvents(ctx, lightClientBridgeEvents)
		}
	}
}

// processLightClientEvents matches events to BEEFY commitment info by transaction hash
func (li *EthereumLightClientListener) processLightClientEvents(ctx context.Context, events []*lightclientbridge.ContractFinalVerificationSuccessful) {
	for _, event := range events {

		li.log.WithFields(logrus.Fields{
			"blockHash":   event.Raw.BlockHash.Hex(),
			"blockNumber": event.Raw.BlockNumber,
			"txHash":      event.Raw.TxHash.Hex(),
		}).Info("event information")

		signedCommitment := &store.SignedCommitment{}
		err := types.DecodeFromHexString(msg.(string), signedCommitment)
		if err != nil {
			li.log.WithError(err).Error("Failed to decode BEEFY commitment messages")
		}

		blockNumber := signedCommitment.Commitment.BlockNumber

		li.log.WithFields(logrus.Fields{
			"commitmentBlockNumber": blockNumber,
			"payload":               signedCommitment.Commitment.Payload.Hex(),
			"validatorSetID":        signedCommitment.Commitment.ValidatorSetID,
		}).Info("Witnessed a new BEEFY commitment:")
		if len(signedCommitment.Signatures) == 0 {
			li.log.Info("BEEFY commitment has no signatures, skipping...")
			continue
		} else {
			hash := blake2b.Sum256(signedCommitment.Commitment.Bytes())
			li.log.WithFields(logrus.Fields{
				"commitment":       hex.EncodeToString(signedCommitment.Commitment.Bytes()),
				"hashedCommitment": hex.EncodeToString(hash[:]),
			}).Info("Commitment with signatures:")
		}
		li.log.WithField("blockNumber", blockNumber+1).Info("Getting hash for next block")
		nextBlockHash, err := li.relaychainConn.GetAPI().RPC.Chain.GetBlockHash(uint64(blockNumber + 1))
		if err != nil {
			li.log.WithError(err).Error("Failed to get block hash")
		}
		li.log.WithField("blockHash", nextBlockHash.Hex()).Info("Got blockhash")

		// TODO this just queries the latest MMR leaf in the latest MMR and our latest parahead in that leaf.
		// we should ideally be querying the last few leaves in the latest MMR until we find
		// the first parachain block that has not yet been fully processed on ethereum,
		// and then package and relay all newer heads/commitments
		mmrProof := li.GetMMRLeafForBlock(uint64(blockNumber), nextBlockHash)
		allParaHeads, ourParaHead := li.GetAllParaheads(nextBlockHash, OUR_PARACHAIN_ID)

		ourParaHeadProof := createParachainHeaderProof(allParaHeads, ourParaHead)

		messagePackets, err := li.extractCommitments(ourParaHead, mmrProof, ourParaHeadProof)
		if err != nil {
			li.log.WithError(err).Error("Failed to extract commitment and messages")
		}
		if len(messagePackets) == 0 {
			li.log.Info("Parachain header has no commitment with messages, skipping...")
			continue
		}
		for _, messagePacket := range messagePackets {
			li.log.WithFields(logrus.Fields{
				"channelID":        messagePacket.channelID,
				"commitmentHash":   messagePacket.commitmentHash,
				"commitmentData":   messagePacket.commitmentData,
				"ourParaHeadProof": messagePacket.paraHeadProof,
				"mmrProof":         messagePacket.mmrProof,
			}).Info("Beefy Listener emitted new message packet")

			li.messages <- messagePacket
		}

	}
}

// queryLightClientEvents queries ContractFinalVerificationSuccessful events from the LightClientBridge contract
func (li *EthereumLightClientListener) queryLightClientEvents(ctx context.Context, start uint64,
	end *uint64) ([]*lightclientbridge.ContractFinalVerificationSuccessful, error) {
	var events []*lightclientbridge.ContractFinalVerificationSuccessful
	filterOps := bind.FilterOpts{Start: start, End: end, Context: ctx}

	iter, err := li.lightClientBridge.FilterFinalVerificationSuccessful(&filterOps)
	if err != nil {
		return nil, err
	}

	for {
		more := iter.Next()
		if !more {
			err = iter.Error()
			if err != nil {
				return nil, err
			}
			break
		}

		events = append(events, iter.Event)
	}

	return events, nil
}

func (li *BeefyListener) GetMMRLeafForBlock(
	blockNumber uint64,
	blockHash types.Hash,
) types.GenerateMMRProofResponse {
	li.log.WithFields(logrus.Fields{
		"blockNumber": blockNumber,
		"blockHash":   blockHash.Hex(),
	}).Info("Getting MMR Leaf for block...")
	proofResponse, err := li.relaychainConn.GetAPI().RPC.MMR.GenerateProof(blockNumber, blockHash)
	if err != nil {
		li.log.WithError(err).Error("Failed to generate mmr proof")
	}

	var proofItemsHex = []string{}
	for _, item := range proofResponse.Proof.Items {
		proofItemsHex = append(proofItemsHex, item.Hex())
	}

	li.log.WithFields(logrus.Fields{
		"BlockHash":                       proofResponse.BlockHash.Hex(),
		"Leaf.ParentNumber":               proofResponse.Leaf.ParentNumberAndHash.ParentNumber,
		"Leaf.Hash":                       proofResponse.Leaf.ParentNumberAndHash.Hash.Hex(),
		"Leaf.ParachainHeads":             proofResponse.Leaf.ParachainHeads.Hex(),
		"Leaf.BeefyNextAuthoritySet.ID":   proofResponse.Leaf.BeefyNextAuthoritySet.ID,
		"Leaf.BeefyNextAuthoritySet.Len":  proofResponse.Leaf.BeefyNextAuthoritySet.Len,
		"Leaf.BeefyNextAuthoritySet.Root": proofResponse.Leaf.BeefyNextAuthoritySet.Root.Hex(),
		"Proof.LeafIndex":                 proofResponse.Proof.LeafIndex,
		"Proof.LeafCount":                 proofResponse.Proof.LeafCount,
		"Proof.Items":                     proofItemsHex,
	}).Info("Generated MMR Proof")
	return proofResponse
}

func (li *BeefyListener) GetAllParaheads(blockHash types.Hash, ourParachainId uint32) ([]types.Header, types.Header) {
	none := types.NewOptionU32Empty()
	encoded, err := types.EncodeToBytes(none)
	if err != nil {
		li.log.WithError(err).Error("Error")
	}

	baseParaHeadsStorageKey, err := types.CreateStorageKey(
		li.relaychainConn.GetMetadata(),
		"Paras",
		"Heads", encoded, nil)
	if err != nil {
		li.log.WithError(err).Error("Failed to create parachain header storage key")
	}

	//TODO fix this manual slice.
	// The above types.CreateStorageKey does not give the same base key as polkadotjs needs for getKeys.
	// It has some extra bytes.
	// maybe from the none u32 in golang being wrong, or maybe slightly off CreateStorageKey call? we slice it
	// here as a hack.
	actualBaseParaHeadsStorageKey := baseParaHeadsStorageKey[:32]
	li.log.WithField("actualBaseParaHeadsStorageKey", actualBaseParaHeadsStorageKey.Hex()).Info("actualBaseParaHeadsStorageKey")

	keysResponse, err := li.relaychainConn.GetAPI().RPC.State.GetKeys(actualBaseParaHeadsStorageKey, blockHash)
	if err != nil {
		li.log.WithError(err).Error("Failed to get all parachain keys")
	}

	headersResponse, err := li.relaychainConn.GetAPI().RPC.State.QueryStorage(keysResponse, blockHash, blockHash)
	if err != nil {
		li.log.WithError(err).Error("Failed to get all parachain headers")
	}

	li.log.Info("Got all parachain headers")
	var headers []types.Header
	var ourParachainHeader types.Header
	for _, headerResponse := range headersResponse {
		for _, change := range headerResponse.Changes {

			// TODO fix this manual slice with a proper type decode. only the last few bytes are for the ParaId,
			// not sure what the early ones are for.
			key := change.StorageKey[40:]
			var parachainID types.U32
			if err := types.DecodeFromBytes(key, &parachainID); err != nil {
				li.log.WithError(err).Error("Failed to decode parachain ID")
			}

			li.log.WithField("parachainId", parachainID).Info("Decoding header for parachain")
			var encodableOpaqueHeader types.Bytes
			if err := types.DecodeFromBytes(change.StorageData, &encodableOpaqueHeader); err != nil {
				li.log.WithError(err).Error("Failed to decode MMREncodableOpaqueLeaf")
			}

			var header types.Header
			if err := types.DecodeFromBytes(encodableOpaqueHeader, &header); err != nil {
				li.log.WithError(err).Error("Failed to decode Header")
			}
			li.log.WithFields(logrus.Fields{
				"headerBytes":           fmt.Sprintf("%#x", encodableOpaqueHeader),
				"header.ParentHash":     header.ParentHash.Hex(),
				"header.Number":         header.Number,
				"header.StateRoot":      header.StateRoot.Hex(),
				"header.ExtrinsicsRoot": header.ExtrinsicsRoot.Hex(),
				"header.Digest":         header.Digest,
				"parachainId":           parachainID,
			}).Info("Decoded header for parachain")
			headers = append(headers, header)

			if parachainID == types.U32(ourParachainId) {
				ourParachainHeader = header
			}
		}
	}
	return headers, ourParachainHeader
}

func createParachainHeaderProof(allParaHeads []types.Header, ourParaHead types.Header) string {
	//TODO: implement
	return ""
}

func (li *BeefyListener) extractCommitments(
	header types.Header,
	mmrProof types.GenerateMMRProofResponse,
	ourParaHeadProof string) ([]MessagePackage, error) {

	li.log.WithFields(logrus.Fields{
		"blockNumber": header.Number,
	}).Debug("Extracting commitment from parachain header")

	auxDigestItems, err := getAuxiliaryDigestItems(header.Digest)
	if err != nil {
		return nil, err
	}

	var messagePackages []MessagePackage
	for _, auxDigestItem := range auxDigestItems {
		li.log.WithFields(logrus.Fields{
			"block":          header.Number,
			"channelID":      auxDigestItem.AsCommitment.ChannelID,
			"commitmentHash": auxDigestItem.AsCommitment.Hash.Hex(),
		}).Debug("Found commitment hash in header digest")
		commitmentHash := auxDigestItem.AsCommitment.Hash
		commitmentData, err := li.getDataForDigestItem(&auxDigestItem)
		if err != nil {
			return nil, err
		}
		messagePackage := MessagePackage{
			auxDigestItem.AsCommitment.ChannelID,
			commitmentHash,
			commitmentData,
			ourParaHeadProof,
			mmrProof,
		}
		messagePackages = append(messagePackages, messagePackage)
	}

	return messagePackages, nil
}

func getAuxiliaryDigestItems(digest types.Digest) ([]chainTypes.AuxiliaryDigestItem, error) {
	var auxDigestItems []chainTypes.AuxiliaryDigestItem
	for _, digestItem := range digest {
		if digestItem.IsOther {
			var auxDigestItem chainTypes.AuxiliaryDigestItem
			err := types.DecodeFromBytes(digestItem.AsOther, &auxDigestItem)
			if err != nil {
				return nil, err
			}
			auxDigestItems = append(auxDigestItems, auxDigestItem)
		}
	}
	return auxDigestItems, nil
}

func (li *BeefyListener) getDataForDigestItem(digestItem *chainTypes.AuxiliaryDigestItem) (types.StorageDataRaw, error) {
	storageKey, err := parachain.MakeStorageKey(digestItem.AsCommitment.ChannelID, digestItem.AsCommitment.Hash)
	if err != nil {
		return nil, err
	}

	data, err := li.parachainConnection.GetAPI().RPC.Offchain.LocalStorageGet(rpcOffchain.Persistent, storageKey)
	if err != nil {
		li.log.WithError(err).Error("Failed to read commitment from offchain storage")
		return nil, err
	}

	if data != nil {
		li.log.WithFields(logrus.Fields{
			"commitmentSizeBytes": len(*data),
		}).Debug("Retrieved commitment from offchain storage")
	} else {
		li.log.WithError(err).Error("Commitment not found in offchain storage")
		return nil, err
	}

	return *data, nil
}
