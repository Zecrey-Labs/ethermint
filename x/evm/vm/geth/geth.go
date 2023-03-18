// Copyright 2021 Evmos Foundation
// This file is part of Evmos' Ethermint library.
//
// The Ethermint library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The Ethermint library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the Ethermint library. If not, see https://github.com/evmos/ethermint/blob/main/LICENSE
package geth

import (
	"errors"
	"math/big"
	"reflect"
	"time"
	"unsafe"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"

	evm "github.com/evmos/ethermint/x/evm/vm"
)

var (
	_                          evm.EVM         = (*EVM)(nil)
	_                          evm.Constructor = NewEVM
	customPrecompiledContracts map[common.Address]evm.StatefulPrecompiledContract
)

// EVM is the wrapper for the go-ethereum EVM.
type EVM struct {
	*vm.EVM
}

// NewEVM defines the constructor function for the go-ethereum (geth) EVM. It uses
// the default precompiled contracts and the EVM concrete implementation from
// geth.
func NewEVM(
	blockCtx vm.BlockContext,
	txCtx vm.TxContext,
	stateDB vm.StateDB,
	chainConfig *params.ChainConfig,
	config vm.Config,
	_ evm.PrecompiledContracts, // unused
) evm.EVM {
	return &EVM{
		EVM: vm.NewEVM(blockCtx, txCtx, stateDB, chainConfig, config),
	}
}

// Context returns the EVM's Block Context
func (e EVM) Context() vm.BlockContext {
	return e.EVM.Context
}

// TxContext returns the EVM's Tx Context
func (e EVM) TxContext() vm.TxContext {
	return e.EVM.TxContext
}

// Config returns the configuration options for the EVM.
func (e EVM) Config() vm.Config {
	return e.EVM.Config
}

// Precompile returns the precompiled contract associated with the given address
// and the current chain configuration. If the contract cannot be found it returns
// nil.
func (e EVM) Precompile(addr common.Address) (p vm.PrecompiledContract, found bool) {
	precompiles := GetPrecompiles(e.ChainConfig(), e.EVM.Context.BlockNumber)
	p, found = precompiles[addr]
	p, foundOnCustom := customPrecompiledContracts[addr]
	return p, found || foundOnCustom
}

// ActivePrecompiles returns a list of all the active precompiled contract addresses
// for the current chain configuration.
func (EVM) ActivePrecompiles(rules params.Rules) []common.Address {
	return vm.ActivePrecompiles(rules)
}

// RunStatefulPrecompiledContract runs a stateful precompiled contract and ignores the address and
// value arguments. It uses the RunPrecompiledContract function from the geth vm package
func (e *EVM) RunStatefulPrecompiledContract(
	p evm.StatefulPrecompiledContract,
	caller common.Address, // address arg is unused
	input []byte,
	suppliedGas uint64,
	value *big.Int,
) (ret []byte, remainingGas uint64, err error) {
	gasCost := p.RequiredGas(input)
	if suppliedGas < gasCost {
		return nil, 0, vm.ErrOutOfGas
	}
	suppliedGas -= gasCost
	output, err := p.RunStateful(e, caller, input, value)
	return output, suppliedGas, err
}

// Call executes the contract associated with the addr with the given input as
// parameters. It also handles any necessary value transfer required and takes
// the necessary steps to create accounts and reverses the state in case of an
// execution error or failed value transfer.
func (evm *EVM) Call(caller vm.ContractRef, addr common.Address, input []byte, gas uint64, value *big.Int) (ret []byte, leftOverGas uint64, err error) {
	// Fail if we're trying to execute above the call depth limit
	oEVM := reflect.ValueOf(evm.EVM).Elem()
	depthValue := oEVM.FieldByName("depth")
	depth, ok := reflect.NewAt(depthValue.Type(), unsafe.Pointer(depthValue.UnsafeAddr())).Elem().Interface().(int)
	if !ok {
		return nil, gas, vm.ErrDepth
	}
	if depth > int(params.CallCreateDepth) {
		return nil, gas, vm.ErrDepth
	}
	chainRulesValue := oEVM.FieldByName("chainRules")
	chainRules, ok := reflect.NewAt(chainRulesValue.Type(), unsafe.Pointer(chainRulesValue.UnsafeAddr())).Elem().Interface().(params.Rules)
	if !ok {
		return nil, gas, errors.New("unable to get chain rules")
	}
	interpreterValue := oEVM.FieldByName("interpreter")
	interpreter, ok := reflect.NewAt(interpreterValue.Type(), unsafe.Pointer(interpreterValue.UnsafeAddr())).Elem().Interface().(*vm.EVMInterpreter)
	if !ok {
		return nil, gas, errors.New("unable to get interpreter")
	}
	// Fail if we're trying to transfer more than the available balance
	if value.Sign() != 0 && !evm.Context().CanTransfer(evm.StateDB, caller.Address(), value) {
		return nil, gas, vm.ErrInsufficientBalance
	}
	snapshot := evm.StateDB.Snapshot()
	p, isPrecompile := evm.Precompile(addr)

	if !evm.StateDB.Exist(addr) {
		if !isPrecompile && chainRules.IsEIP158 && value.Sign() == 0 {
			// Calling a non existing account, don't do anything, but ping the tracer
			if evm.Config().Debug {
				if depth == 0 {
					evm.Config().Tracer.CaptureStart(evm.EVM, caller.Address(), addr, false, input, gas, value)
					evm.Config().Tracer.CaptureEnd(ret, 0, 0, nil)
				} else {
					evm.Config().Tracer.CaptureEnter(vm.CALL, caller.Address(), addr, input, gas, value)
					evm.Config().Tracer.CaptureExit(ret, 0, nil)
				}
			}
			return nil, gas, nil
		}
		evm.StateDB.CreateAccount(addr)
	}
	evm.Context().Transfer(evm.StateDB, caller.Address(), addr, value)

	// Capture the tracer start/end events in debug mode
	if evm.Config().Debug {
		if depth == 0 {
			evm.Config().Tracer.CaptureStart(evm.EVM, caller.Address(), addr, false, input, gas, value)
			defer func(startGas uint64, startTime time.Time) { // Lazy evaluation of the parameters
				evm.Config().Tracer.CaptureEnd(ret, startGas-gas, time.Since(startTime), err)
			}(gas, time.Now())
		} else {
			// Handle tracer events for entering and exiting a call frame
			evm.Config().Tracer.CaptureEnter(vm.CALL, caller.Address(), addr, input, gas, value)
			defer func(startGas uint64) {
				evm.Config().Tracer.CaptureExit(ret, startGas-gas, err)
			}(gas)
		}
	}

	if isPrecompile {
		if customPrecompiledContracts[addr] != nil {
			ret, gas, err = evm.RunStatefulPrecompiledContract(customPrecompiledContracts[addr], caller.Address(), input, gas, value)
		} else {
			ret, gas, err = vm.RunPrecompiledContract(p, input, gas)
		}
	} else {
		// Initialise a new contract and set the code that is to be used by the EVM.
		// The contract is a scoped environment for this execution context only.
		code := evm.StateDB.GetCode(addr)
		if len(code) == 0 {
			ret, err = nil, nil // gas is unchanged
		} else {
			addrCopy := addr
			// If the account has no code, we can abort here
			// The depth-check is already done, and precompiles handled above
			contract := vm.NewContract(caller, vm.AccountRef(addrCopy), value, gas)
			contract.SetCallCode(&addrCopy, evm.StateDB.GetCodeHash(addrCopy), code)
			ret, err = interpreter.Run(contract, input, false)
			gas = contract.Gas
		}
	}
	// When an error was returned by the EVM or when setting the creation code
	// above we revert to the snapshot and consume any gas remaining. Additionally
	// when we're in homestead this also counts for code storage gas errors.
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != vm.ErrExecutionReverted {
			gas = 0
		}
		// TODO: consider clearing up unused snapshots:
		//} else {
		//	evm.StateDB.DiscardSnapshot(snapshot)
	}
	return ret, gas, err
}

// DelegateCall executes the contract associated with the addr with the given input
// as parameters. It reverses the state in case of an execution error.
//
// DelegateCall differs from CallCode in the sense that it executes the given address'
// code with the caller as context and the caller is set to the caller of the caller.
func (evm *EVM) DelegateCall(caller vm.ContractRef, addr common.Address, input []byte, gas uint64) (ret []byte, leftOverGas uint64, err error) {
	// Fail if we're trying to execute above the call depth limit
	oEVM := reflect.ValueOf(evm.EVM).Elem()
	depthValue := oEVM.FieldByName("depth")
	depth, ok := reflect.NewAt(depthValue.Type(), unsafe.Pointer(depthValue.UnsafeAddr())).Elem().Interface().(int)
	if !ok {
		return nil, gas, vm.ErrDepth
	}
	interpreterValue := oEVM.FieldByName("interpreter")
	interpreter, ok := reflect.NewAt(interpreterValue.Type(), unsafe.Pointer(interpreterValue.UnsafeAddr())).Elem().Interface().(*vm.EVMInterpreter)
	if !ok {
		return nil, gas, errors.New("unable to get interpreter")
	}
	if depth > int(params.CallCreateDepth) {
		return nil, gas, vm.ErrDepth
	}
	var snapshot = evm.StateDB.Snapshot()

	// Invoke tracer hooks that signal entering/exiting a call frame
	if evm.Config().Debug {
		evm.Config().Tracer.CaptureEnter(vm.DELEGATECALL, caller.Address(), addr, input, gas, nil)
		defer func(startGas uint64) {
			evm.Config().Tracer.CaptureExit(ret, startGas-gas, err)
		}(gas)
	}

	// It is allowed to call precompiles, even via delegatecall
	if p, isPrecompile := evm.Precompile(addr); isPrecompile {
		if customPrecompiledContracts[addr] != nil {
			ret, gas, err = evm.RunStatefulPrecompiledContract(customPrecompiledContracts[addr], caller.Address(), input, gas, big.NewInt(0))
		} else {
			ret, gas, err = vm.RunPrecompiledContract(p, input, gas)
		}
	} else {
		addrCopy := addr
		// Initialise a new contract and make initialise the delegate values
		contract := vm.NewContract(caller, vm.AccountRef(caller.Address()), nil, gas).AsDelegate()
		contract.SetCallCode(&addrCopy, evm.StateDB.GetCodeHash(addrCopy), evm.StateDB.GetCode(addrCopy))
		ret, err = interpreter.Run(contract, input, false)
		gas = contract.Gas
	}
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != vm.ErrExecutionReverted {
			gas = 0
		}
	}
	return ret, gas, err
}
