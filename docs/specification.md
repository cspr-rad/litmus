### Casper Blockchain Light Client Specification

#### Introduction
This document specifies the design and implementation of a blockchain light client for the Casper blockchain. The client is versatile, functioning in both browser environments (via WebAssembly) and server-side Rust environments. Central to this design is a `no_std` kernel, written in Rust and compiled to WebAssembly using `wasm-pack`.

#### Prior Work
The design follows Polkadot's light-client architecture. For more information, see the following references:
- [Polkadot Light Clients](https://wiki.polkadot.network/docs/build-light-clients)
- [Polkadot Light Client Specification](https://spec.polkadot.network/sect-lightclient)
- [Substrate Light Clients](https://docs.substrate.io/learn/light-clients-in-substrate-connect)
- [Substrate Connect Package](https://www.npmjs.com/package/@substrate/connect)

In addition, the Helios Ethereum light client, supported by a16z, represents an innovative development in light client design. It focuses on efficiency and minimal resource usage for Ethereum, providing insights potentially applicable to the Casper blockchain light client. More information can be found at the [Helios Ethereum Light Client GitHub Repository](https://github.com/a16z/helios).

#### Core Data Structure
The kernel's primary data structure in Rust is:

```rust
use alloc::collections::BTreeMap;
use core::option::Option;

#[derive(Clone, Copy)]
struct BlockHash([u8; 32]);

#[derive(Clone, Copy)]
struct PublicKey([u8; 32]);

#[derive(Clone, Copy)]
struct EraId(u64);

struct EraInfo {
    era_id: EraId,
    validator_weights: BTreeMap<PublicKey, u64>,
    total_weight: u64,
}

struct ParentHashAndCurrentHeight {
    parent_hash: BlockHash,
    current_height: u64,
}

struct LightClientKernel {
    latest_block_hash: BlockHash,
    parent_hash_and_current_height: Option<ParentHashAndCurrentHeight>,
    era_info: Option<EraInfo>,
}
```

#### Light Client Kernel Interface
The inherent implementation (`impl`) for `LightClientKernel` introduces an interface for safe state transitions.

##### Relevant Casper Node Data Structures

- `BlockHeader`: Represents the header of a block in the Casper blockchain. This data structure is approximately:

```rust
// see https://github.com/casper-network/casper-node/blob/8ca9001dabba0dae95f92ad8c54eddd163200b5d/node/src/types/block.rs#L813-L828
pub struct BlockHeader {
    parent_hash: BlockHash,
    state_root_hash: Digest,
    body_hash: Digest,
    random_bit: bool,
    accumulated_seed: Digest,
    era_end: Option<EraEnd>,
    timestamp: Timestamp,
    era_id: EraId,
    height: u64,
    protocol_version: ProtocolVersion,
}
```

A key thing to note is that `BlockHeader` exposes a `block_hash(&self) -> BlockHash` method in its inherent implementation. See https://github.com/casper-network/casper-node/blob/8ca9001dabba0dae95f92ad8c54eddd163200b5d/node/src/types/block.rs#L1030-L1036.

- `BlockHeaderWithMetadata`: Combines a `BlockHeader` with associated metadata, including signatures. This data structure is approximately:

```rust
struct Signature([u8; 64]);

// Note that the actual implementation of `BlockSignatures` includes extraneous data that can be derived from the `BlockHeader`...
type BlockSignatures = BTreeMap<PublicKey, Signature>

// see https://github.com/casper-network/casper-node/blob/8ca9001dabba0dae95f92ad8c54eddd163200b5d/node/src/types/block.rs#L1185-L1188

pub struct BlockHeaderWithMetadata {
    pub block_header: BlockHeader,
    pub block_signatures: BlockSignatures,
}
```

#### Addition: Facility for Verifying Deploys in a Block
In addition to the existing architecture, it is essential to include a facility for verifying that deploys are included in a block. This feature will enhance the security and reliability of the light client by ensuring that the transactions (deploys) are indeed part of the confirmed block.

#### `LightClientKernel` Implementation

```rust
enum LightClientUpdateError {
    InvalidBlockHashWhenInitializing,
    InvalidBlockHashWhenWalkingBack,
    BlockInPastWhenProgressing,
    WrongEraId,
    InvalidSignatures,
}

impl LightClientKernel {
    fn new(latest_block_hash: BlockHash) -> Self {
        LightClientKernel {
            latest_block_hash,
            parent_hash_and_current_height: None,
            era_info: None,
        }
    }

    fn update(&mut self, block_header_with_metadata: BlockHeaderWithMetadata) -> Result<(), LightClientUpdateError> {
        let BlockHeaderWithMetadata {
            block_header,
            block_signatures,
        } = block_header_with_metadata;

        match (self.parent_hash_and_current_height, self.era_info) {
            // parent_hash_and_current_height are not set, check the latest block has the correct trusted hash and set them
            (None, _) => {
                if self.latest_block_hash == block_header.block_hash() {
                    let parent_hash = block_header.parent_hash;
                    let current_height = block_header.height;
                    self.parent_hash_and_current_height = Some(ParentHashAndCurrentHeight { parent_hash, current_height });
                    Ok(())
                } else {
                    Err(InvalidBlockHashWhenInitializing)
                }
            },
            // If the parent_hash_and_current_height are set, but there's no `EraInfo`, then the update effectively walks the light-client back in history by a block.
            // If the block_header_with_metadata has an era_end, use that to set `EraInfo`.
            (Some(ParentHashAndCurrentHeight { parent_hash, current_height }), None) => {
                if parent_hash == block_header.block_hash() {
                    self.latest_hash = parent_hash;
                    let parent_hash = block_header.parent_hash;
                    let current_height = block_header.height;
                    if let Some(era_end) = block_header.era_end {
                        self.era_info = Some(era_end.into());
                    }
                    Ok(())
                } else {
                    Err(InvalidBlockHashWhenWalkingBack)
                }
            },
            // If the era_info is set, then the light client progresses by checking if the block is in the current era and has proper finality signatures. If it is and it has a height higher than the kernel, progress the light client.
            (Some(ParentHashAndCurrentHeight { parent_hash, current_height }), Some(EraInfo { era_id, validator_weights, total_weight })) => {
                if block_header.height != current_height + 1 {
                    Err(BlockInPastWhenProgressing)
                } else if block_header.era_id != era_id {
                    Err(WrongEraId)
                } else if !signatures_valid(block_header.block_hash(), block_signatures, validator_weights, total_weight) {
                    Err(InvalidSignatures)
                } else {
                    self.latest_block_hash = block_header.block_hash();
                    self.parent_hash_and_current_height = Some(ParentHashAndCurrentHeight { parent_hash: block_header.parent_hash, current_height: block_header.height });
                    if let Some(era_end) = block_header.era_end {
                        self.era_info = Some(era_end.into());
                    }
                    Ok(())
                }
            }
        }
    }
}
```

This addition will require the `LightClientKernel` to interact with deploy-related data and potentially include additional data structures or methods to support this functionality.

#### WebAssembly Interface
The light client kernel will compile to WebAssembly for browser use. 

##### JavaScript Integration
- Use JavaScript's `fetch` function to retrieve information from a Casper-node RPC.
- Implement state transitions within the kernel using the `update` function.
- In a browser environment, employ a WebWorker alongside persistent storage to track the latest block or latest switch-block (where `block_header.era_end` is not `None`).

#### Rust Backend Implementation
- Utilize the `reqwest` crate for RPC communication in the Rust backend.
- Implement similar state management logic as in the WebAssembly interface.

#### Conclusion
This specification outlines the foundational structure and behavior of the Casper blockchain light client. The design ensures compatibility across browser and server-side environments, leveraging Rust's `no_std` capability for a versatile and efficient implementation. The inclusion of a facility for verifying deploys in a block further strengthens the light client's utility and security, making it an even more robust solution for interacting with the Casper blockchain.