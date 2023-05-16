package backend

import (
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	rpctypes "github.com/evmos/ethermint/rpc/types"
	evmtypes "github.com/evmos/ethermint/x/evm/types"
	"math/big"
)

// GetRawTransactionReceipt returns the transaction receipt identified by hash.
func (b *Backend) GetRawTransactionReceipt(hash common.Hash) (*ethtypes.Receipt, error) {
	hexTx := hash.Hex()
	b.logger.Debug("eth_getTransactionReceipt", "hash", hexTx)

	res, err := b.GetTxByEthHash(hash)
	if err != nil {
		b.logger.Debug("tx not found", "hash", hexTx, "error", err.Error())
		return nil, nil
	}

	resBlock, err := b.TendermintBlockByNumber(rpctypes.BlockNumber(res.Height))
	if err != nil {
		b.logger.Debug("block not found", "height", res.Height, "error", err.Error())
		return nil, nil
	}
	tx, err := b.clientCtx.TxConfig.TxDecoder()(resBlock.Block.Txs[res.TxIndex])
	if err != nil {
		b.logger.Debug("decoding failed", "error", err.Error())
		return nil, fmt.Errorf("failed to decode tx: %w", err)
	}
	ethMsg := tx.GetMsgs()[res.MsgIndex].(*evmtypes.MsgEthereumTx)

	txData, err := evmtypes.UnpackTxData(ethMsg.Data)
	if err != nil {
		b.logger.Error("failed to unpack tx data", "error", err.Error())
		return nil, err
	}

	cumulativeGasUsed := uint64(0)
	blockRes, err := b.TendermintBlockResultByNumber(&res.Height)
	if err != nil {
		b.logger.Debug("failed to retrieve block results", "height", res.Height, "error", err.Error())
		return nil, nil
	}
	for _, txResult := range blockRes.TxsResults[0:res.TxIndex] {
		cumulativeGasUsed += uint64(txResult.GasUsed)
	}
	cumulativeGasUsed += res.CumulativeGasUsed

	var status hexutil.Uint
	if res.Failed {
		status = hexutil.Uint(ethtypes.ReceiptStatusFailed)
	} else {
		status = hexutil.Uint(ethtypes.ReceiptStatusSuccessful)
	}

	chainID, err := b.ChainID()
	if err != nil {
		return nil, err
	}

	from, err := ethMsg.GetSender(chainID.ToInt())
	if err != nil {
		return nil, err
	}

	// parse tx logs from events
	logs, err := TxLogsFromEvents(blockRes.TxsResults[res.TxIndex].Events, int(res.MsgIndex))
	if err != nil {
		b.logger.Debug("failed to parse logs", "hash", hexTx, "error", err.Error())
	}

	if res.EthTxIndex == -1 {
		// Fallback to find tx index by iterating all valid eth transactions
		msgs := b.EthMsgsFromTendermintBlock(resBlock, blockRes)
		for i := range msgs {
			if msgs[i].Hash == hexTx {
				res.EthTxIndex = int32(i)
				break
			}
		}
	}
	// return error if still unable to find the eth tx index
	if res.EthTxIndex == -1 {
		return nil, errors.New("can't find index of ethereum tx")
	}

	rawReceipt := &ethtypes.Receipt{
		Type:              0,
		PostState:         nil,
		Status:            uint64(status),
		CumulativeGasUsed: cumulativeGasUsed,
		Bloom:             ethtypes.BytesToBloom(ethtypes.LogsBloom(logs)),
		Logs:              logs,
		TxHash:            hash,
		ContractAddress:   common.Address{},
		GasUsed:           res.GasUsed,
		BlockHash:         common.BytesToHash(resBlock.Block.Header.Hash()),
		BlockNumber:       big.NewInt(res.Height),
		TransactionIndex:  uint(res.EthTxIndex),
	}

	if logs == nil {
		rawReceipt.Logs = []*ethtypes.Log{}
	}

	// If the ContractAddress is 20 0x0 bytes, assume it is not a contract creation
	if txData.GetTo() == nil {
		rawReceipt.ContractAddress = crypto.CreateAddress(from, txData.GetNonce())
	}

	return rawReceipt, nil
}

func (b *Backend) BlockReceipts(blockNum uint64) (*ethtypes.Receipts, error) {
	b.logger.Debug("eth_blockReceipts", "height", blockNum)

	block, err := b.TendermintBlockByNumber(rpctypes.BlockNumber(blockNum))
	if err != nil {
		b.logger.Debug("block not found", "height", blockNum, "error", err.Error())
		return nil, nil
	}
	blockNumInt64 := int64(blockNum)
	blockRes, err := b.TendermintBlockResultByNumber(&blockNumInt64)
	if err != nil {
		b.logger.Debug("block res not found", "height", blockNum, "error", err.Error())
		return nil, nil
	}
	chainID, err := b.ChainID()
	if err != nil {
		return nil, err
	}
	var rawReceipts []*ethtypes.Receipt
	for index, rawTx := range block.Block.Txs {
		res, err := b.GetTxByTxIndex(int64(blockNum), uint(index))
		if err != nil {
			b.logger.Debug("tx not found", "blockNum", blockNum, "index", index, "error", err.Error())
			return nil, nil
		}
		otx, err := b.clientCtx.TxConfig.TxDecoder()(rawTx)
		if err != nil {
			b.logger.Debug("decoding failed", "error", err.Error())
			return nil, fmt.Errorf("failed to decode tx: %w", err)
		}
		ethMsg := otx.GetMsgs()[res.MsgIndex].(*evmtypes.MsgEthereumTx)

		txData, err := evmtypes.UnpackTxData(ethMsg.Data)
		if err != nil {
			b.logger.Error("failed to unpack tx data", "error", err.Error())
			return nil, err
		}
		var status hexutil.Uint
		if res.Failed {
			status = hexutil.Uint(ethtypes.ReceiptStatusFailed)
		} else {
			status = hexutil.Uint(ethtypes.ReceiptStatusSuccessful)
		}
		var from common.Address
		if ethMsg.From == "" {
			from, err = ethMsg.GetSender(chainID.ToInt())
			if err != nil {
				return nil, err
			}
		} else {
			from = common.HexToAddress(ethMsg.From)
		}

		// parse tx logs from events
		logs, err := TxLogsFromEvents(blockRes.TxsResults[res.TxIndex].Events, int(res.MsgIndex))
		if err != nil {
			b.logger.Debug("failed to parse logs", "tx index", res.TxIndex, "error", err.Error())
		}

		cumulativeGasUsed := uint64(0)
		for _, txResult := range blockRes.TxsResults[0:res.TxIndex] {
			cumulativeGasUsed += uint64(txResult.GasUsed)
		}
		cumulativeGasUsed += res.CumulativeGasUsed
		rawReceipt := &ethtypes.Receipt{
			Type:              0,
			PostState:         nil,
			Status:            uint64(status),
			CumulativeGasUsed: cumulativeGasUsed,
			Bloom:             ethtypes.BytesToBloom(ethtypes.LogsBloom(logs)),
			Logs:              logs,
			TxHash:            common.HexToHash(ethMsg.Hash),
			ContractAddress:   common.Address{},
			GasUsed:           res.GasUsed,
			BlockHash:         common.BytesToHash(block.Block.Header.Hash()),
			BlockNumber:       big.NewInt(res.Height),
			TransactionIndex:  uint(res.EthTxIndex),
		}
		if logs == nil {
			rawReceipt.Logs = []*ethtypes.Log{}
		}

		// If the ContractAddress is 20 0x0 bytes, assume it is not a contract creation
		if txData.GetTo() == nil {
			rawReceipt.ContractAddress = crypto.CreateAddress(from, txData.GetNonce())
		}
		rawReceipts = append(rawReceipts, rawReceipt)
	}

	receipts := ethtypes.Receipts(rawReceipts)
	return &receipts, nil
}
