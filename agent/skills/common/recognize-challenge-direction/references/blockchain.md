# Blockchain direction

## Recognize

Strong signals include Solidity, ABI, deployed contract addresses, bytecode,
chain IDs, Ethereum JSON-RPC methods such as `eth_chainId` or
`web3_clientVersion`, Foundry/Hardhat/Anvil, wallet/transaction/signature
semantics, or an explicit smart-contract objective. A `0x` string, port 8545, or
JSON alone is weak.

Common families include access control, reentrancy, delegatecall/proxy and
storage mistakes, signature/replay issues, oracle or price manipulation,
accounting/rounding, randomness, and DeFi/flash-loan logic.

## First information channels

1. Identify the chain, RPC endpoint, instance lifecycle, accounts, and network
   state.
2. Obtain or locate source, ABI, bytecode, deployment metadata, and proxy
   relationships.
3. Map callable state-changing functions and authorization boundaries.
4. Validate one concrete contract invariant or transaction hypothesis.

Do not treat the instance launcher or its TCP port as the vulnerability surface;
follow the chain and contract evidence.
