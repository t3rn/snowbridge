package ethereum

import (
	"context"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/snowfork/go-substrate-rpc-client/types"
	"github.com/snowfork/snowbridge/relayer/chain/ethereum"
	"github.com/snowfork/snowbridge/relayer/chain/parachain"
	"github.com/snowfork/snowbridge/relayer/contracts/basic"
	"github.com/snowfork/snowbridge/relayer/relays/ethereum"
)

type Tracker struct {
	config *Config
	ethConn *ethereum.Connection
	paraConn *parachain.Connection
}

func NewTracker(config *Config, ethConn *ethereum.Connection, paraConn *parachain.Connection) (*Tracker, error) {
	return &Tracker{
		config, ethConn, paraConn,
	}, nil
}

func (t *Tracker) Start(ctx context.Context) error {

	var address common.Address

	address = common.HexToAddress(t.config.Source.Contracts.BasicOutboundChannel)
	channel, err := basic.NewBasicOutboundChannel(address, t.ethConn.GetClient())
	if err != nil {
		return err
	}

	options := bind.CallOpts{
		Pending: true,
		Context: ctx,
	}

	ethNonce, err := channel.Nonce(&options)
	if err != nil {
		return err
	}

	paraHash, err := t.paraConn.API().RPC.Chain.GetFinalizedHead()
	if err != nil {
		return err
	}

	paraNonceKey, err := types.CreateStorageKey(t.paraConn.Metadata(), "BasicOutboundModule", "Nonce", nil, nil)
	if err != nil {
		return err
	}

	var paraNonce types.U64
	ok, err := t.paraConn.API().RPC.State.GetStorage(paraNonceKey, &paraNonce, paraHash)
	if err != nil {
		return err
	}
	if !ok {
		paraNonce = 0
	}

	if ethNonce == paraNonce {
		return nil
	}




}
