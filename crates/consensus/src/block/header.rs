use crate::{
    constants::{EMPTY_OMMER_ROOT_HASH, EMPTY_ROOT_HASH},
    Block, BlockBody,
};
use alloc::vec::Vec;
use alloy_eips::{
    eip1559::{calc_next_block_base_fee, BaseFeeParams},
    eip1898::BlockWithParent,
    eip7840::BlobParams,
    merge::ALLOWED_FUTURE_BLOCK_TIME_SECONDS,
    BlockNumHash,
};
use alloy_primitives::{
    keccak256, Address, BlockNumber, Bloom, Bytes, Sealable, Sealed, B256, B64, U256,
};
use alloy_rlp::{length_of_length, BufMut, Decodable, Encodable};
use core::mem;

/// Ethereum Block header
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct Header {
    /// The Keccak 256-bit hash of the parent
    /// block’s header, in its entirety; formally Hp.
    pub parent_hash: B256,
    /// The Keccak 256-bit hash of the ommers list portion of this block; formally Ho.
    #[cfg_attr(feature = "serde", serde(rename = "sha3Uncles", alias = "ommersHash"))]
    pub ommers_hash: B256,
    /// The 160-bit address to which all fees collected from the successful mining of this block
    /// be transferred; formally Hc.
    #[cfg_attr(feature = "serde", serde(rename = "miner", alias = "beneficiary"))]
    pub beneficiary: Address,
    /// The Keccak 256-bit hash of the root node of the previous block's state trie, after all
    /// transactions are executed and finalisations applied, per EIP-7886. This is the state root
    /// before executing transactions in the current block.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub pre_state_root: Option<B256>,
    /// The Keccak 256-bit hash of the root node of the previous block's trie structure populated
    /// with each transaction in the transactions list portion of the block, per EIP-7886.
    /// Formerly was `transactions_root` in pre-EIP-7886 headers.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub parent_transactions_root: Option<B256>,
    /// The Keccak 256-bit hash of the root node of the previous block's trie structure populated
    /// with the receipts of each transaction in the transactions list portion of the block, per
    /// EIP-7886. Formerly was `receipts_root` in pre-EIP-7886 headers.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub parent_receipts_root: Option<B256>,
    /// The Bloom filter composed from indexable information (logger address and log topics)
    /// contained in each log entry from the receipt of each transaction in the transactions list
    /// of the previous block, per EIP-7886.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub parent_logs_bloom: Option<Bloom>,
    /// The Keccak 256-bit hash of the an RLP encoded list with each
    /// [EIP-7685] request in the block body of the previous block, per EIP-7886.
    /// [EIP-7685]: https://eips.ethereum.org/EIPS/eip-7685.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub parent_requests_hash: Option<B256>,
    /// Indicates whether the execution of the previous block was reverted, per EIP-7886.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub parent_execution_reverted: Option<bool>,
    /// The Keccak 256-bit hash of the root node of the state trie, after all transactions are
    /// executed and finalisations applied; formally Hr.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub state_root: Option<B256>,
    /// The Keccak 256-bit hash of the root node of the trie structure populated with each
    /// transaction in the transactions list portion of the block; formally Ht.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub transactions_root: Option<B256>,
    /// The Keccak 256-bit hash of the root node of the trie structure populated with the receipts
    /// of each transaction in the transactions list portion of the block; formally He.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub receipts_root: Option<B256>,
    /// The Bloom filter composed from indexable information (logger address and log topics)
    /// contained in each log entry from the receipt of each transaction in the transactions list;
    /// formally Hb.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub logs_bloom: Option<Bloom>,
    /// A scalar value corresponding to the difficulty level of this block. This can be calculated
    /// from the previous block’s difficulty level and the timestamp; formally Hd.
    pub difficulty: U256,
    /// A scalar value equal to the number of ancestor blocks. The genesis block has a number of
    /// zero; formally Hi.
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub number: BlockNumber,
    /// A scalar value equal to the current limit of gas expenditure per block; formally Hl.
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub gas_limit: u64,
    /// A scalar value equal to the total gas used in transactions in this block; formally Hg.
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub gas_used: u64,
    /// A scalar value equal to the reasonable output of Unix’s time() at this block’s inception;
    /// formally Hs.
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub timestamp: u64,
    /// An arbitrary byte array containing data relevant to this block. This must be 32 bytes or
    /// fewer; formally Hx.
    pub extra_data: Bytes,
    /// A 256-bit hash which, combined with the
    /// nonce, proves that a sufficient amount of computation has been carried out on this block;
    /// formally Hm.
    pub mix_hash: B256,
    /// A 64-bit value which, combined with the mixhash, proves that a sufficient amount of
    /// computation has been carried out on this block; formally Hn.
    pub nonce: B64,
    /// A scalar representing EIP1559 base fee which can move up or down each block according
    /// to a formula which is a function of gas used in parent block and gas target
    /// (block gas limit divided by elasticity multiplier) of parent block.
    /// The algorithm results in the base fee per gas increasing when blocks are
    /// above the gas target, and decreasing when blocks are below the gas target. The base fee per
    /// gas is burned.
    #[cfg_attr(
        feature = "serde",
        serde(
            default,
            with = "alloy_serde::quantity::opt",
            skip_serializing_if = "Option::is_none"
        )
    )]
    pub base_fee_per_gas: Option<u64>,
    /// The Keccak 256-bit hash of the withdrawals list portion of this block.
    /// <https://eips.ethereum.org/EIPS/eip-4895>
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub withdrawals_root: Option<B256>,
    /// The total amount of blob gas consumed by the transactions within the block, added in
    /// EIP-4844.
    #[cfg_attr(
        feature = "serde",
        serde(
            default,
            with = "alloy_serde::quantity::opt",
            skip_serializing_if = "Option::is_none"
        )
    )]
    pub blob_gas_used: Option<u64>,
    /// A running total of blob gas consumed in excess of the target, prior to the block. Blocks
    /// with above-target blob gas consumption increase this value, blocks with below-target blob
    /// gas consumption decrease it (bounded at 0). This was added in EIP-4844.
    #[cfg_attr(
        feature = "serde",
        serde(
            default,
            with = "alloy_serde::quantity::opt",
            skip_serializing_if = "Option::is_none"
        )
    )]
    pub excess_blob_gas: Option<u64>,
    /// The hash of the parent beacon block's root is included in execution blocks, as proposed by
    /// EIP-4788.
    ///
    /// This enables trust-minimized access to consensus state, supporting staking pools, bridges,
    /// and more.
    ///
    /// The beacon roots contract handles root storage, enhancing Ethereum's functionalities.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub parent_beacon_block_root: Option<B256>,
    /// The Keccak 256-bit hash of the an RLP encoded list with each
    /// [EIP-7685] request in the block body.
    ///
    /// [EIP-7685]: https://eips.ethereum.org/EIPS/eip-7685
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub requests_hash: Option<B256>,
}

impl AsRef<Self> for Header {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl Default for Header {
    fn default() -> Self {
        Self {
            parent_hash: Default::default(),
            ommers_hash: EMPTY_OMMER_ROOT_HASH,
            beneficiary: Default::default(),

            // ── EIP-7886 additions: all absent in a legacy header ──────────
            pre_state_root: None,
            parent_transactions_root: None,
            parent_receipts_root: None,
            parent_logs_bloom: None,
            parent_requests_hash: None,
            parent_execution_reverted: None,

            // ── legacy roots ───────────────────────────────────────────────
            state_root: Some(EMPTY_ROOT_HASH),
            transactions_root: Some(EMPTY_ROOT_HASH),
            receipts_root: Some(EMPTY_ROOT_HASH),
            logs_bloom: Some(Default::default()),
            difficulty: Default::default(),
            number: 0,
            gas_limit: 0,
            gas_used: 0,
            timestamp: 0,
            extra_data: Default::default(),
            mix_hash: Default::default(),
            nonce: B64::ZERO,
            base_fee_per_gas: None,
            withdrawals_root: None,
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_block_root: None,
            requests_hash: None,
        }
    }
}

impl Sealable for Header {
    fn hash_slow(&self) -> B256 {
        self.hash_slow()
    }
}

impl Header {
    /// Create a [`Block`] from the body and its header.
    pub const fn into_block<T>(self, body: BlockBody<T>) -> Block<T> {
        body.into_block(self)
    }

    /// Heavy function that will calculate hash of data and will *not* save the change to metadata.
    ///
    /// Use [`Header::seal_slow`] and unlock if you need the hash to be persistent.
    pub fn hash_slow(&self) -> B256 {
        let mut out = Vec::<u8>::new();
        self.encode(&mut out);
        keccak256(&out)
    }

    /// Check if the ommers hash equals to empty hash list.
    pub fn ommers_hash_is_empty(&self) -> bool {
        self.ommers_hash == EMPTY_OMMER_ROOT_HASH
    }

    /// Check if the transaction root equals to empty root.
    pub fn transaction_root_is_empty(&self) -> bool {
        self.transactions_root == Some(EMPTY_ROOT_HASH)
    }

    /// Returns the blob fee for _this_ block according to the EIP-4844 spec.
    ///
    /// Returns `None` if `excess_blob_gas` is None
    pub fn blob_fee(&self, blob_params: BlobParams) -> Option<u128> {
        Some(blob_params.calc_blob_fee(self.excess_blob_gas?))
    }

    /// Returns the blob fee for the next block according to the EIP-4844 spec.
    ///
    /// Returns `None` if `excess_blob_gas` is None.
    ///
    /// See also [Self::next_block_excess_blob_gas]
    pub fn next_block_blob_fee(&self, blob_params: BlobParams) -> Option<u128> {
        Some(blob_params.calc_blob_fee(self.next_block_excess_blob_gas(blob_params)?))
    }

    /// Calculate base fee for next block according to the EIP-1559 spec.
    ///
    /// Returns a `None` if no base fee is set, no EIP-1559 support
    pub fn next_block_base_fee(&self, base_fee_params: BaseFeeParams) -> Option<u64> {
        Some(calc_next_block_base_fee(
            self.gas_used,
            self.gas_limit,
            self.base_fee_per_gas?,
            base_fee_params,
        ))
    }

    /// Calculate excess blob gas for the next block according to the EIP-4844
    /// spec.
    ///
    /// Returns a `None` if no excess blob gas is set, no EIP-4844 support
    pub fn next_block_excess_blob_gas(&self, blob_params: BlobParams) -> Option<u64> {
        Some(blob_params.next_block_excess_blob_gas(self.excess_blob_gas?, self.blob_gas_used?))
    }

    /// Calculate a heuristic for the in-memory size of the [Header].
    #[inline]
    pub fn size(&self) -> usize {
        mem::size_of::<B256>() + // parent hash
        mem::size_of::<B256>() + // ommers hash
        mem::size_of::<Address>() + // beneficiary
         mem::size_of::<Option<B256>>() + // state root
         mem::size_of::<Option<B256>>() + // transactions root
         mem::size_of::<Option<B256>>() + // receipts root
        mem::size_of::<Option<B256>>() + // withdrawals root
         mem::size_of::<Option<B256>>() + // logs bloom
        mem::size_of::<U256>() + // difficulty
        mem::size_of::<BlockNumber>() + // number
        mem::size_of::<u128>() + // gas limit
        mem::size_of::<u128>() + // gas used
        mem::size_of::<u64>() + // timestamp
        mem::size_of::<B256>() + // mix hash
        mem::size_of::<u64>() + // nonce
        mem::size_of::<Option<u128>>() + // base fee per gas
        mem::size_of::<Option<u128>>() + // blob gas used
        mem::size_of::<Option<u128>>() + // excess blob gas
        mem::size_of::<Option<B256>>() + // parent beacon block root
        mem::size_of::<Option<B256>>() + // requests root
        // ── new EIP-7886 fields ────────────────────────────────────────────────
        mem::size_of::<Option<B256>>() + // pre_state_root
        mem::size_of::<Option<B256>>() + // parent_transactions_root
        mem::size_of::<Option<B256>>() + // parent_receipts_root
        mem::size_of::<Option<Bloom>>() + // parent_logs_bloom
        mem::size_of::<Option<B256>>() + // parent_requests_hash
        mem::size_of::<Option<bool>>() + // parent_execution_reverted
        self.extra_data.len() // extra data
    }

    fn header_payload_length(&self) -> usize {
        let mut length = 0;
        length += self.parent_hash.length();
        length += self.ommers_hash.length();
        length += self.beneficiary.length();

        // pre-EIP-7886 fields
        if let Some(state_root) = self.state_root {
            length += state_root.length();
        }

        if let Some(transactions_root) = self.transactions_root {
            length += transactions_root.length();
        }

        if let Some(receipts_root) = self.receipts_root {
            length += receipts_root.length();
        }

        if let Some(logs_bloom) = self.logs_bloom {
            length += logs_bloom.length();
        }

        // Encode EIP-7886 fields first (right after ommers_hash)
        if let Some(ref pre_state_root) = self.pre_state_root {
            length += pre_state_root.length();
        }
        if let Some(ref parent_transactions_root) = self.parent_transactions_root {
            length += parent_transactions_root.length();
        }
        if let Some(ref parent_receipts_root) = self.parent_receipts_root {
            length += parent_receipts_root.length();
        }
        if let Some(ref parent_logs_bloom) = self.parent_logs_bloom {
            length += parent_logs_bloom.length();
        }
        if let Some(ref parent_requests_hash) = self.parent_requests_hash {
            length += parent_requests_hash.length();
        }
        if let Some(parent_execution_reverted) = self.parent_execution_reverted {
            // Encode the boolean as 0 / 1 using U256 to stay consistent with the
            // length-calculation.
            length += U256::from(parent_execution_reverted as u8).length();
        }

        length += self.difficulty.length();
        length += U256::from(self.number).length();
        length += U256::from(self.gas_limit).length();
        length += U256::from(self.gas_used).length();
        length += self.timestamp.length();
        length += self.extra_data.length();
        length += self.mix_hash.length();
        length += self.nonce.length();

        if let Some(base_fee) = self.base_fee_per_gas {
            // Adding base fee length if it exists.
            length += U256::from(base_fee).length();
        }

        if let Some(root) = self.withdrawals_root {
            // Adding withdrawals_root length if it exists.
            length += root.length();
        }

        if let Some(blob_gas_used) = self.blob_gas_used {
            // Adding blob_gas_used length if it exists.
            length += U256::from(blob_gas_used).length();
        }

        if let Some(excess_blob_gas) = self.excess_blob_gas {
            // Adding excess_blob_gas length if it exists.
            length += U256::from(excess_blob_gas).length();
        }

        if let Some(parent_beacon_block_root) = self.parent_beacon_block_root {
            length += parent_beacon_block_root.length();
        }

        if let Some(requests_hash) = self.requests_hash {
            length += requests_hash.length();
        }

        length
    }

    /// Returns the parent block's number and hash
    ///
    /// Note: for the genesis block the parent number is 0 and the parent hash is the zero hash.
    pub const fn parent_num_hash(&self) -> BlockNumHash {
        BlockNumHash { number: self.number.saturating_sub(1), hash: self.parent_hash }
    }

    /// Returns the block's number and hash.
    ///
    /// Note: this hashes the header.
    pub fn num_hash_slow(&self) -> BlockNumHash {
        BlockNumHash { number: self.number, hash: self.hash_slow() }
    }

    /// Returns the block's number and hash with the parent hash.
    ///
    /// Note: this hashes the header.
    pub fn num_hash_with_parent_slow(&self) -> BlockWithParent {
        BlockWithParent::new(self.parent_hash, self.num_hash_slow())
    }

    /// Seal the header with a known hash.
    ///
    /// WARNING: This method does not perform validation whether the hash is correct.
    #[inline]
    pub const fn seal(self, hash: B256) -> Sealed<Self> {
        Sealed::new_unchecked(self, hash)
    }

    /// True if the shanghai hardfork is active.
    ///
    /// This function checks that the withdrawals root field is present.
    pub const fn shanghai_active(&self) -> bool {
        self.withdrawals_root.is_some()
    }

    /// True if the Cancun hardfork is active.
    ///
    /// This function checks that the blob gas used field is present.
    pub const fn cancun_active(&self) -> bool {
        self.blob_gas_used.is_some()
    }

    /// True if the Prague hardfork is active.
    ///
    /// This function checks that the requests hash is present.
    pub const fn prague_active(&self) -> bool {
        self.requests_hash.is_some()
    }

    /// True if the EIP-7886 hardfork is active
    ///
    /// This function checks if the pre_state_root field is present.
    pub const fn eip7886_active(&self) -> bool {
        self.pre_state_root.is_some()
    }
}

impl Encodable for Header {
    fn encode(&self, out: &mut dyn BufMut) {
        let list_header =
            alloy_rlp::Header { list: true, payload_length: self.header_payload_length() };
        list_header.encode(out);
        self.parent_hash.encode(out);
        self.ommers_hash.encode(out);
        self.beneficiary.encode(out);

        // Encode all the pre-EIP-7886 fields
        if let Some(ref state_root) = self.state_root {
            state_root.encode(out);
        }
        if let Some(ref transactions_root) = self.transactions_root {
            transactions_root.encode(out);
        }
        if let Some(ref receipts_root) = self.receipts_root {
            receipts_root.encode(out);
        }
        if let Some(ref logs_bloom) = self.logs_bloom {
            logs_bloom.encode(out);
        }

        // Encode EIP-7886 fields first (right after ommers_hash)
        if let Some(ref pre_state_root) = self.pre_state_root {
            pre_state_root.encode(out);
        }
        if let Some(ref parent_transactions_root) = self.parent_transactions_root {
            parent_transactions_root.encode(out);
        }
        if let Some(ref parent_receipts_root) = self.parent_receipts_root {
            parent_receipts_root.encode(out);
        }
        if let Some(ref parent_logs_bloom) = self.parent_logs_bloom {
            parent_logs_bloom.encode(out);
        }
        if let Some(ref parent_requests_hash) = self.parent_requests_hash {
            parent_requests_hash.encode(out);
        }
        if let Some(parent_execution_reverted) = self.parent_execution_reverted {
            // Encode the boolean as 0 / 1 using U256 to stay consistent with the
            // length-calculation.
            U256::from(parent_execution_reverted as u8).encode(out);
        }

        self.difficulty.encode(out);
        U256::from(self.number).encode(out);
        U256::from(self.gas_limit).encode(out);
        U256::from(self.gas_used).encode(out);
        self.timestamp.encode(out);
        self.extra_data.encode(out);
        self.mix_hash.encode(out);
        self.nonce.encode(out);

        // Encode all the fork specific fields
        if let Some(ref base_fee) = self.base_fee_per_gas {
            U256::from(*base_fee).encode(out);
        }

        if let Some(ref root) = self.withdrawals_root {
            root.encode(out);
        }

        if let Some(ref blob_gas_used) = self.blob_gas_used {
            U256::from(*blob_gas_used).encode(out);
        }

        if let Some(ref excess_blob_gas) = self.excess_blob_gas {
            U256::from(*excess_blob_gas).encode(out);
        }

        if let Some(ref parent_beacon_block_root) = self.parent_beacon_block_root {
            parent_beacon_block_root.encode(out);
        }

        if let Some(ref requests_hash) = self.requests_hash {
            requests_hash.encode(out);
        }
    }

    fn length(&self) -> usize {
        let mut length = 0;
        length += self.header_payload_length();
        length += length_of_length(length);
        length
    }
}

impl Decodable for Header {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        // helper that does the actual field-by-field decoding
        fn parse_header(
            buf: &mut &[u8],
            read_legacy: bool,
            read_eip7886: bool,
        ) -> alloy_rlp::Result<Header> {
            let rlp_head = alloy_rlp::Header::decode(buf)?;
            if !rlp_head.list {
                return Err(alloy_rlp::Error::UnexpectedString);
            }
            let started_len = buf.len();

            // fixed prefix
            let parent_hash: B256 = Decodable::decode(buf)?;
            let ommers_hash: B256 = Decodable::decode(buf)?;
            let beneficiary: Address = Decodable::decode(buf)?;

            // optional pre-EIP-7886 legacy fields
            let mut state_root = None;
            let mut transactions_root = None;
            let mut receipts_root = None;
            let mut logs_bloom = None;

            if read_legacy && started_len - buf.len() < rlp_head.payload_length {
                state_root = Some(Decodable::decode(buf)?);
            }
            if read_legacy && started_len - buf.len() < rlp_head.payload_length {
                transactions_root = Some(Decodable::decode(buf)?);
            }
            if read_legacy && started_len - buf.len() < rlp_head.payload_length {
                receipts_root = Some(Decodable::decode(buf)?);
            }
            if read_legacy && started_len - buf.len() < rlp_head.payload_length {
                logs_bloom = Some(Decodable::decode(buf)?);
            }

            // EIP-7886 optional fields
            let mut pre_state_root = None;
            let mut parent_transactions_root = None;
            let mut parent_receipts_root = None;
            let mut parent_logs_bloom = None;
            let mut parent_requests_hash = None;
            let mut parent_execution_reverted = None;

            if read_eip7886 && started_len - buf.len() < rlp_head.payload_length {
                pre_state_root = Some(Decodable::decode(buf)?);
            }
            if read_eip7886 && started_len - buf.len() < rlp_head.payload_length {
                parent_transactions_root = Some(Decodable::decode(buf)?);
            }
            if read_eip7886 && started_len - buf.len() < rlp_head.payload_length {
                parent_receipts_root = Some(Decodable::decode(buf)?);
            }
            if read_eip7886 && started_len - buf.len() < rlp_head.payload_length {
                parent_logs_bloom = Some(Decodable::decode(buf)?);
            }
            if read_eip7886 && started_len - buf.len() < rlp_head.payload_length {
                parent_requests_hash = Some(B256::decode(buf)?);
            }
            if read_eip7886 && started_len - buf.len() < rlp_head.payload_length {
                let flag: U256 = Decodable::decode(buf)?;
                parent_execution_reverted = Some(!flag.is_zero());
            }

            // mandatory core & fork fields
            let difficulty: U256 = Decodable::decode(buf)?;
            let number: u64 = u64::decode(buf)?;
            let gas_limit: u64 = u64::decode(buf)?;
            let gas_used: u64 = u64::decode(buf)?;
            let timestamp: u64 = u64::decode(buf)?;
            let extra_data: Bytes = Decodable::decode(buf)?;
            let mix_hash: B256 = Decodable::decode(buf)?;
            let nonce: B64 = B64::decode(buf)?;

            let mut base_fee_per_gas = None;
            let mut withdrawals_root = None;
            let mut blob_gas_used = None;
            let mut excess_blob_gas = None;
            let mut parent_beacon_block_root = None;
            let mut requests_hash = None;

            if started_len - buf.len() < rlp_head.payload_length {
                base_fee_per_gas = Some(u64::decode(buf)?);
            }
            if started_len - buf.len() < rlp_head.payload_length {
                withdrawals_root = Some(Decodable::decode(buf)?);
            }
            if started_len - buf.len() < rlp_head.payload_length {
                blob_gas_used = Some(u64::decode(buf)?);
            }
            if started_len - buf.len() < rlp_head.payload_length {
                excess_blob_gas = Some(u64::decode(buf)?);
            }
            if started_len - buf.len() < rlp_head.payload_length {
                parent_beacon_block_root = Some(B256::decode(buf)?);
            }
            if started_len - buf.len() < rlp_head.payload_length {
                requests_hash = Some(B256::decode(buf)?);
            }

            // final length check
            if started_len - buf.len() != rlp_head.payload_length {
                return Err(alloy_rlp::Error::UnexpectedLength);
            }

            Ok(Header {
                parent_hash,
                ommers_hash,
                beneficiary,
                // legacy
                state_root,
                transactions_root,
                receipts_root,
                logs_bloom,
                // EIP-7886
                pre_state_root,
                parent_transactions_root,
                parent_receipts_root,
                parent_logs_bloom,
                parent_requests_hash,
                parent_execution_reverted,
                // core
                difficulty,
                number,
                gas_limit,
                gas_used,
                timestamp,
                extra_data,
                mix_hash,
                nonce,
                // fork extras
                base_fee_per_gas,
                withdrawals_root,
                blob_gas_used,
                excess_blob_gas,
                parent_beacon_block_root,
                requests_hash,
            })
        }

        let original_buf = *buf;

        // Attempt to parse as a post-EIP-7886 header first.
        let mut eip7886_buf = original_buf;
        parse_header(&mut eip7886_buf, /* read_legacy */ false, /* read_eip7886 */ true)
            .and_then(|header| {
                // If successful, commit the buffer advancement.
                *buf = eip7886_buf;
                Ok(header)
            })
            .or_else(|_err| {
                // If it failed, rewind and try parsing as a legacy header.
                let mut legacy_buf = original_buf;
                let header = parse_header(
                    &mut legacy_buf,
                    /* read_legacy */ true,
                    /* read_eip7886 */ false,
                )?;
                // If successful, commit the buffer advancement.
                *buf = legacy_buf;
                Ok(header)
            })
    }
}

/// Generates a header which is valid __with respect to past and future forks__. This means, for
/// example, that if the withdrawals root is present, the base fee per gas is also present.
///
/// If blob gas used were present, then the excess blob gas and parent beacon block root are also
/// present. In this example, the withdrawals root would also be present.
///
/// This __does not, and should not guarantee__ that the header is valid with respect to __anything
/// else__.
#[cfg(any(test, feature = "arbitrary"))]
pub(crate) const fn generate_valid_header(
    mut header: Header,
    eip_4844_active: bool,
    blob_gas_used: u64,
    excess_blob_gas: u64,
    parent_beacon_block_root: B256,
) -> Header {
    // Clear all related fields if EIP-1559 is inactive
    if header.base_fee_per_gas.is_none() {
        header.withdrawals_root = None;
    }

    // Set fields based on EIP-4844 being active
    if eip_4844_active {
        header.blob_gas_used = Some(blob_gas_used);
        header.excess_blob_gas = Some(excess_blob_gas);
        header.parent_beacon_block_root = Some(parent_beacon_block_root);
    } else {
        header.blob_gas_used = None;
        header.excess_blob_gas = None;
        header.parent_beacon_block_root = None;
    }

    // Placeholder for future EIP adjustments
    header.requests_hash = None;

    header
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for Header {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // Generate an arbitrary header, passing it to the generate_valid_header function to make
        // sure it is valid _with respect to hardforks only_.
        let base = Self {
            parent_hash: u.arbitrary()?,
            ommers_hash: u.arbitrary()?,
            beneficiary: u.arbitrary()?,

            // pre-EIP-7886 fields
            state_root: u.arbitrary()?,
            transactions_root: u.arbitrary()?,
            receipts_root: u.arbitrary()?,
            logs_bloom: u.arbitrary()?,

            // EIP-7886 fields
            pre_state_root: u.arbitrary()?,
            parent_transactions_root: u.arbitrary()?,
            parent_receipts_root: u.arbitrary()?,
            parent_logs_bloom: u.arbitrary()?,
            parent_requests_hash: u.arbitrary()?,
            parent_execution_reverted: u.arbitrary()?,

            difficulty: u.arbitrary()?,
            number: u.arbitrary()?,
            gas_limit: u.arbitrary()?,
            gas_used: u.arbitrary()?,
            timestamp: u.arbitrary()?,
            extra_data: u.arbitrary()?,
            mix_hash: u.arbitrary()?,
            nonce: u.arbitrary()?,
            base_fee_per_gas: u.arbitrary()?,
            blob_gas_used: u.arbitrary()?,
            excess_blob_gas: u.arbitrary()?,
            parent_beacon_block_root: u.arbitrary()?,
            requests_hash: u.arbitrary()?,
            withdrawals_root: u.arbitrary()?,
        };

        Ok(generate_valid_header(
            base,
            u.arbitrary()?,
            u.arbitrary()?,
            u.arbitrary()?,
            u.arbitrary()?,
        ))
    }
}

/// Trait for extracting specific Ethereum block data from a header
#[auto_impl::auto_impl(&, Arc)]
pub trait BlockHeader {
    /// Retrieves the parent hash of the block
    fn parent_hash(&self) -> B256;

    /// Retrieves the ommers hash of the block
    fn ommers_hash(&self) -> B256;

    /// Retrieves the beneficiary (miner) of the block
    fn beneficiary(&self) -> Address;

    /// Retrieves the state root hash of the block, if available
    fn state_root(&self) -> Option<B256>;

    /// Retrieves the transactions root hash of the block, if available
    fn transactions_root(&self) -> Option<B256>;

    /// Retrieves the receipts root hash of the block, if available
    fn receipts_root(&self) -> Option<B256>;

    /// Retrieves the withdrawals root hash of the block, if available
    fn withdrawals_root(&self) -> Option<B256>;

    /// Retrieves the logs bloom filter of the block, if available
    fn logs_bloom(&self) -> Option<Bloom>;

    /// Retrieves the pre-state root of the block, if available
    fn pre_state_root(&self) -> Option<B256>;

    /// Retrieves the parent transactions root of the block, if available
    fn parent_transactions_root(&self) -> Option<B256>;

    /// Retrieves the parent receipts root of the block, if available
    fn parent_receipts_root(&self) -> Option<B256>;

    /// Retrieves the parent logs bloom of the block, if available
    fn parent_logs_bloom(&self) -> Option<Bloom>;

    /// Retrieves the parent requests hash of the block, if available
    fn parent_requests_hash(&self) -> Option<B256>;

    /// Retrieves whether the parent execution was reverted, if available
    fn parent_execution_reverted(&self) -> Option<bool>;

    /// Retrieves the difficulty of the block
    fn difficulty(&self) -> U256;

    /// Retrieves the block number
    fn number(&self) -> BlockNumber;

    /// Retrieves the gas limit of the block
    fn gas_limit(&self) -> u64;

    /// Retrieves the gas used by the block
    fn gas_used(&self) -> u64;

    /// Retrieves the timestamp of the block
    fn timestamp(&self) -> u64;

    /// Retrieves the mix hash of the block, if available
    fn mix_hash(&self) -> Option<B256>;

    /// Retrieves the nonce of the block, if available
    fn nonce(&self) -> Option<B64>;

    /// Retrieves the base fee per gas of the block, if available
    fn base_fee_per_gas(&self) -> Option<u64>;

    /// Retrieves the blob gas used by the block, if available
    fn blob_gas_used(&self) -> Option<u64>;

    /// Retrieves the excess blob gas of the block, if available
    fn excess_blob_gas(&self) -> Option<u64>;

    /// Retrieves the parent beacon block root of the block, if available
    fn parent_beacon_block_root(&self) -> Option<B256>;

    /// Retrieves the requests hash of the block, if available
    fn requests_hash(&self) -> Option<B256>;

    /// Retrieves the block's extra data field
    fn extra_data(&self) -> &Bytes;

    /// Returns the blob fee for _this_ block according to the EIP-4844 spec.
    ///
    /// Returns `None` if `excess_blob_gas` is None
    fn blob_fee(&self, blob_params: BlobParams) -> Option<u128> {
        Some(blob_params.calc_blob_fee(self.excess_blob_gas()?))
    }

    /// Calculate excess blob gas for the next block according to the EIP-4844
    /// spec.
    ///
    /// Returns a `None` if no excess blob gas is set, no EIP-4844 support
    fn next_block_excess_blob_gas(&self, blob_params: BlobParams) -> Option<u64> {
        Some(blob_params.next_block_excess_blob_gas(self.excess_blob_gas()?, self.blob_gas_used()?))
    }

    /// Convenience function for [`Self::next_block_excess_blob_gas`] with an optional
    /// [`BlobParams`] argument.
    ///
    /// Returns `None` if the `blob_params` are `None`.
    fn maybe_next_block_excess_blob_gas(&self, blob_params: Option<BlobParams>) -> Option<u64> {
        self.next_block_excess_blob_gas(blob_params?)
    }

    /// Returns the blob fee for the next block according to the EIP-4844 spec.
    ///
    /// Returns `None` if `excess_blob_gas` is None.
    ///
    /// See also [BlockHeader::next_block_excess_blob_gas]
    fn next_block_blob_fee(&self, blob_params: BlobParams) -> Option<u128> {
        Some(blob_params.calc_blob_fee(self.next_block_excess_blob_gas(blob_params)?))
    }

    /// Convenience function for [`Self::next_block_blob_fee`] with an optional [`BlobParams`]
    /// argument.
    ///
    /// Returns `None` if the `blob_params` are `None`.
    fn maybe_next_block_blob_fee(&self, blob_params: Option<BlobParams>) -> Option<u128> {
        self.next_block_blob_fee(blob_params?)
    }

    /// Calculate base fee for next block according to the EIP-1559 spec.
    ///
    /// Returns a `None` if no base fee is set, no EIP-1559 support
    fn next_block_base_fee(&self, base_fee_params: BaseFeeParams) -> Option<u64> {
        Some(calc_next_block_base_fee(
            self.gas_used(),
            self.gas_limit(),
            self.base_fee_per_gas()?,
            base_fee_params,
        ))
    }

    /// Returns the parent block's number and hash
    ///
    /// Note: for the genesis block the parent number is 0 and the parent hash is the zero hash.
    fn parent_num_hash(&self) -> BlockNumHash {
        BlockNumHash { number: self.number().saturating_sub(1), hash: self.parent_hash() }
    }

    /// Checks if the header is considered empty - has no transactions, no ommers or withdrawals
    fn is_empty(&self) -> bool {
        let txs_and_ommers_empty = self.transactions_root() == Some(EMPTY_ROOT_HASH)
            && self.ommers_hash() == EMPTY_OMMER_ROOT_HASH;
        self.withdrawals_root().map_or(txs_and_ommers_empty, |withdrawals_root| {
            txs_and_ommers_empty && withdrawals_root == EMPTY_ROOT_HASH
        })
    }

    /// Checks if the block's difficulty is set to zero, indicating a Proof-of-Stake header.
    ///
    /// This function is linked to EIP-3675, proposing the consensus upgrade to Proof-of-Stake:
    /// [EIP-3675](https://eips.ethereum.org/EIPS/eip-3675#replacing-difficulty-with-0)
    ///
    /// Verifies whether, as per the EIP, the block's difficulty is updated to zero,
    /// signifying the transition to a Proof-of-Stake mechanism.
    ///
    /// Returns `true` if the block's difficulty matches the constant zero set by the EIP.
    fn is_zero_difficulty(&self) -> bool {
        self.difficulty().is_zero()
    }

    /// Checks if the block's timestamp is in the future based on the present timestamp.
    ///
    /// Clock can drift but this can be consensus issue.
    ///
    /// Note: This check is relevant only pre-merge.
    fn exceeds_allowed_future_timestamp(&self, present_timestamp: u64) -> bool {
        self.timestamp() > present_timestamp + ALLOWED_FUTURE_BLOCK_TIME_SECONDS
    }

    /// Checks if the nonce exists, and if it exists, if it's zero.
    ///
    /// If the nonce is `None`, then this returns `false`.
    fn is_nonce_zero(&self) -> bool {
        self.nonce().is_some_and(|nonce| nonce.is_zero())
    }
}

impl BlockHeader for Header {
    fn parent_hash(&self) -> B256 {
        self.parent_hash
    }

    fn ommers_hash(&self) -> B256 {
        self.ommers_hash
    }

    fn beneficiary(&self) -> Address {
        self.beneficiary
    }

    fn state_root(&self) -> Option<B256> {
        self.state_root
    }

    fn transactions_root(&self) -> Option<B256> {
        self.transactions_root
    }

    fn receipts_root(&self) -> Option<B256> {
        self.receipts_root
    }

    fn withdrawals_root(&self) -> Option<B256> {
        self.withdrawals_root
    }

    fn logs_bloom(&self) -> Option<Bloom> {
        self.logs_bloom
    }

    fn pre_state_root(&self) -> Option<B256> {
        self.pre_state_root
    }

    fn parent_transactions_root(&self) -> Option<B256> {
        self.parent_transactions_root
    }

    fn parent_receipts_root(&self) -> Option<B256> {
        self.parent_receipts_root
    }

    fn parent_logs_bloom(&self) -> Option<Bloom> {
        self.parent_logs_bloom
    }

    fn parent_requests_hash(&self) -> Option<B256> {
        self.parent_requests_hash
    }

    fn parent_execution_reverted(&self) -> Option<bool> {
        self.parent_execution_reverted
    }

    fn difficulty(&self) -> U256 {
        self.difficulty
    }

    fn number(&self) -> BlockNumber {
        self.number
    }

    fn gas_limit(&self) -> u64 {
        self.gas_limit
    }

    fn gas_used(&self) -> u64 {
        self.gas_used
    }

    fn timestamp(&self) -> u64 {
        self.timestamp
    }

    fn mix_hash(&self) -> Option<B256> {
        Some(self.mix_hash)
    }

    fn nonce(&self) -> Option<B64> {
        Some(self.nonce)
    }

    fn base_fee_per_gas(&self) -> Option<u64> {
        self.base_fee_per_gas
    }

    fn blob_gas_used(&self) -> Option<u64> {
        self.blob_gas_used
    }

    fn excess_blob_gas(&self) -> Option<u64> {
        self.excess_blob_gas
    }

    fn parent_beacon_block_root(&self) -> Option<B256> {
        self.parent_beacon_block_root
    }

    fn requests_hash(&self) -> Option<B256> {
        self.requests_hash
    }

    fn extra_data(&self) -> &Bytes {
        &self.extra_data
    }
}

#[cfg(feature = "serde")]
impl<T: BlockHeader> BlockHeader for alloy_serde::WithOtherFields<T> {
    fn parent_hash(&self) -> B256 {
        self.inner.parent_hash()
    }

    fn ommers_hash(&self) -> B256 {
        self.inner.ommers_hash()
    }

    fn beneficiary(&self) -> Address {
        self.inner.beneficiary()
    }

    fn state_root(&self) -> Option<B256> {
        self.inner.state_root()
    }

    fn transactions_root(&self) -> Option<B256> {
        self.inner.transactions_root()
    }

    fn receipts_root(&self) -> Option<B256> {
        self.inner.receipts_root()
    }

    fn withdrawals_root(&self) -> Option<B256> {
        self.inner.withdrawals_root()
    }

    fn logs_bloom(&self) -> Option<Bloom> {
        self.inner.logs_bloom()
    }

    fn difficulty(&self) -> U256 {
        self.inner.difficulty()
    }

    fn number(&self) -> u64 {
        self.inner.number()
    }

    fn gas_limit(&self) -> u64 {
        self.inner.gas_limit()
    }

    fn gas_used(&self) -> u64 {
        self.inner.gas_used()
    }

    fn timestamp(&self) -> u64 {
        self.inner.timestamp()
    }

    fn mix_hash(&self) -> Option<B256> {
        self.inner.mix_hash()
    }

    fn nonce(&self) -> Option<B64> {
        self.inner.nonce()
    }

    fn base_fee_per_gas(&self) -> Option<u64> {
        self.inner.base_fee_per_gas()
    }

    fn blob_gas_used(&self) -> Option<u64> {
        self.inner.blob_gas_used()
    }

    fn excess_blob_gas(&self) -> Option<u64> {
        self.inner.excess_blob_gas()
    }

    fn parent_beacon_block_root(&self) -> Option<B256> {
        self.inner.parent_beacon_block_root()
    }

    fn requests_hash(&self) -> Option<B256> {
        self.inner.requests_hash()
    }

    fn extra_data(&self) -> &Bytes {
        self.inner.extra_data()
    }

    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    fn pre_state_root(&self) -> Option<B256> {
        self.inner.pre_state_root()
    }

    fn parent_transactions_root(&self) -> Option<B256> {
        self.inner.parent_transactions_root()
    }

    fn parent_receipts_root(&self) -> Option<B256> {
        self.inner.parent_receipts_root()
    }

    fn parent_logs_bloom(&self) -> Option<Bloom> {
        self.inner.parent_logs_bloom()
    }

    fn parent_requests_hash(&self) -> Option<B256> {
        self.inner.parent_requests_hash()
    }

    fn parent_execution_reverted(&self) -> Option<bool> {
        self.inner.parent_execution_reverted()
    }
}

/// Bincode-compatible [`Header`] serde implementation.
#[cfg(all(feature = "serde", feature = "serde-bincode-compat"))]
pub(crate) mod serde_bincode_compat {
    use alloc::borrow::Cow;
    use alloy_primitives::{Address, BlockNumber, Bloom, Bytes, B256, B64, U256};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_with::{DeserializeAs, SerializeAs};

    /// Bincode-compatible [`super::Header`] serde implementation.
    ///
    /// Intended to use with the [`serde_with::serde_as`] macro in the following way:
    /// ```rust
    /// use alloy_consensus::{serde_bincode_compat, Header};
    /// use serde::{Deserialize, Serialize};
    /// use serde_with::serde_as;
    ///
    /// #[serde_as]
    /// #[derive(Serialize, Deserialize)]
    /// struct Data {
    ///     #[serde_as(as = "serde_bincode_compat::Header")]
    ///     header: Header,
    /// }
    /// ```
    #[derive(Debug, Serialize, Deserialize)]
    pub struct Header<'a> {
        parent_hash: B256,
        ommers_hash: B256,
        beneficiary: Address,
        #[serde(default)]
        state_root: Option<B256>,
        #[serde(default)]
        transactions_root: Option<B256>,
        #[serde(default)]
        receipts_root: Option<B256>,
        #[serde(default)]
        withdrawals_root: Option<B256>,
        #[serde(default)]
        logs_bloom: Option<Bloom>,
        #[serde(default)]
        pre_state_root: Option<B256>,
        #[serde(default)]
        parent_transactions_root: Option<B256>,
        #[serde(default)]
        parent_receipts_root: Option<B256>,
        #[serde(default)]
        parent_logs_bloom: Option<Bloom>,
        #[serde(default)]
        parent_requests_hash: Option<B256>,
        #[serde(default)]
        parent_execution_reverted: Option<bool>,
        difficulty: U256,
        number: BlockNumber,
        gas_limit: u64,
        gas_used: u64,
        timestamp: u64,
        mix_hash: B256,
        nonce: B64,
        #[serde(default)]
        base_fee_per_gas: Option<u64>,
        #[serde(default)]
        blob_gas_used: Option<u64>,
        #[serde(default)]
        excess_blob_gas: Option<u64>,
        #[serde(default)]
        parent_beacon_block_root: Option<B256>,
        #[serde(default)]
        requests_hash: Option<B256>,
        extra_data: Cow<'a, Bytes>,
    }

    impl<'a> From<&'a super::Header> for Header<'a> {
        fn from(value: &'a super::Header) -> Self {
            Self {
                parent_hash: value.parent_hash,
                ommers_hash: value.ommers_hash,
                beneficiary: value.beneficiary,

                // pre-EIP-7886 fields
                state_root: value.state_root,
                transactions_root: value.transactions_root,
                receipts_root: value.receipts_root,
                withdrawals_root: value.withdrawals_root,
                logs_bloom: value.logs_bloom,

                // EIP-7886 fields
                pre_state_root: value.pre_state_root,
                parent_transactions_root: value.parent_transactions_root,
                parent_receipts_root: value.parent_receipts_root,
                parent_logs_bloom: value.parent_logs_bloom,
                parent_requests_hash: value.parent_requests_hash,
                parent_execution_reverted: value.parent_execution_reverted,

                difficulty: value.difficulty,
                number: value.number,
                gas_limit: value.gas_limit,
                gas_used: value.gas_used,
                timestamp: value.timestamp,
                mix_hash: value.mix_hash,
                nonce: value.nonce,
                base_fee_per_gas: value.base_fee_per_gas,
                blob_gas_used: value.blob_gas_used,
                excess_blob_gas: value.excess_blob_gas,
                parent_beacon_block_root: value.parent_beacon_block_root,
                requests_hash: value.requests_hash,
                extra_data: Cow::Borrowed(&value.extra_data),
            }
        }
    }

    impl<'a> From<Header<'a>> for super::Header {
        fn from(value: Header<'a>) -> Self {
            Self {
                parent_hash: value.parent_hash,
                ommers_hash: value.ommers_hash,
                beneficiary: value.beneficiary,

                // pre-EIP-7886 fields
                state_root: value.state_root,
                transactions_root: value.transactions_root,
                receipts_root: value.receipts_root,
                withdrawals_root: value.withdrawals_root,
                logs_bloom: value.logs_bloom,

                // EIP-7886 fields
                pre_state_root: value.pre_state_root,
                parent_transactions_root: value.parent_transactions_root,
                parent_receipts_root: value.parent_receipts_root,
                parent_logs_bloom: value.parent_logs_bloom,
                parent_requests_hash: value.parent_requests_hash,
                parent_execution_reverted: value.parent_execution_reverted,
                difficulty: value.difficulty,
                number: value.number,
                gas_limit: value.gas_limit,
                gas_used: value.gas_used,
                timestamp: value.timestamp,
                mix_hash: value.mix_hash,
                nonce: value.nonce,
                base_fee_per_gas: value.base_fee_per_gas,
                blob_gas_used: value.blob_gas_used,
                excess_blob_gas: value.excess_blob_gas,
                parent_beacon_block_root: value.parent_beacon_block_root,
                requests_hash: value.requests_hash,
                extra_data: value.extra_data.into_owned(),
            }
        }
    }

    impl SerializeAs<super::Header> for Header<'_> {
        fn serialize_as<S>(source: &super::Header, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            Header::from(source).serialize(serializer)
        }
    }

    impl<'de> DeserializeAs<'de, super::Header> for Header<'de> {
        fn deserialize_as<D>(deserializer: D) -> Result<super::Header, D::Error>
        where
            D: Deserializer<'de>,
        {
            Header::deserialize(deserializer).map(Into::into)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::super::{serde_bincode_compat, Header};
        use arbitrary::Arbitrary;
        use bincode::config;
        use rand::Rng;
        use serde::{Deserialize, Serialize};
        use serde_with::serde_as;

        #[test]
        fn test_header_bincode_roundtrip() {
            #[serde_as]
            #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
            struct Data {
                #[serde_as(as = "serde_bincode_compat::Header")]
                header: Header,
            }

            let mut bytes = [0u8; 1024];
            rand::thread_rng().fill(bytes.as_mut_slice());
            let data = Data {
                header: Header::arbitrary(&mut arbitrary::Unstructured::new(&bytes)).unwrap(),
            };

            let encoded = bincode::serde::encode_to_vec(&data, config::legacy()).unwrap();
            let (decoded, _) =
                bincode::serde::decode_from_slice::<Data, _>(&encoded, config::legacy()).unwrap();
            assert_eq!(decoded, data);
        }
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;
    use alloy_primitives::{b256, hex};

    #[test]
    fn test_header_serde_json_roundtrip() {
        let raw = "{\"parentHash\":\"0x0000000000000000000000000000000000000000000000000000000000000000\",\"sha3Uncles\":\"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347\",\"miner\":\"0x0000000000000000000000000000000000000000\",\"stateRoot\":\"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421\",\"transactionsRoot\":\"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421\",\"receiptsRoot\":\"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421\",\"logsBloom\":\"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"difficulty\":\"0x0\",\"number\":\"0x0\",\"gasLimit\":\"0x0\",\"gasUsed\":\"0x0\",\"timestamp\":\"0x0\",\"extraData\":\"0x\",\"mixHash\":\"0x0000000000000000000000000000000000000000000000000000000000000000\",\"nonce\":\"0x0000000000000000\",\"baseFeePerGas\":\"0x1\",\"withdrawalsRoot\":\"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421\"}";

        let header = Header {
            base_fee_per_gas: Some(1),
            withdrawals_root: Some(EMPTY_ROOT_HASH),
            ..Default::default()
        };

        let encoded = serde_json::to_string(&header).unwrap();
        assert_eq!(encoded, raw);
        println!("encoded-json len      = {}", encoded.len());

        let bloom_hex = &raw[raw.find("\"logsBloom\":").unwrap() + 13..] // after 0x
            .split('"')
            .next()
            .unwrap();
        println!("hard-coded bloom hex-digits = {}", bloom_hex.len()); // expect 1024

        // ...existing code...
        let decoded: Header = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, header);

        // Create a vector to store the encoded RLP
        let mut encoded_rlp = Vec::new();

        // Encode the header data
        decoded.encode(&mut encoded_rlp);
        println!("encoded-rlp bytes len = {}", encoded_rlp.len());

        let decoded_rlp = match Header::decode(&mut encoded_rlp.as_slice()) {
            Ok(h) => h,
            Err(e) => {
                println!("RLP decode error: {:?}", e);
                panic!("failed to decode RLP");
            }
        };

        // Check that the decoded RLP data matches the original header data
        assert_eq!(decoded_rlp, decoded);
    }

    #[test]
    fn serde_rlp_prague() {
        // Note: Some fields are renamed from eth_getHeaderByHash
        let raw = r#"{"baseFeePerGas":"0x7","blobGasUsed":"0x20000","difficulty":"0x0","excessBlobGas":"0x40000","extraData":"0xd883010e0c846765746888676f312e32332e32856c696e7578","gasLimit":"0x1c9c380","gasUsed":"0x5208","hash":"0x661da523f3e44725f3a1cee38183d35424155a05674609a9f6ed81243adf9e26","logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","miner":"0xf97e180c050e5ab072211ad2c213eb5aee4df134","mixHash":"0xe6d9c084dd36560520d5776a5387a82fb44793c9cd1b69afb61d53af29ee64b0","nonce":"0x0000000000000000","number":"0x315","parentBeaconBlockRoot":"0xd0bdb48ab45028568e66c8ddd600ac4c2a52522714bbfbf00ea6d20ba40f3ae2","parentHash":"0x60f1563d2c572116091a4b91421d8d972118e39604d23455d841f9431cea4b6a","receiptsRoot":"0xeaa8c40899a61ae59615cf9985f5e2194f8fd2b57d273be63bde6733e89b12ab","requestsHash":"0x6036c41849da9c076ed79654d434017387a88fb833c2856b32e18218b3341c5f","sha3Uncles":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","stateRoot":"0x8101d88f2761eb9849634740f92fe09735551ad5a4d5e9da9bcae1ef4726a475","timestamp":"0x6712ba6e","transactionsRoot":"0xf543eb3d405d2d6320344d348b06703ff1abeef71288181a24061e53f89bb5ef","withdrawalsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"}
"#;

        // helper: should print 1024
        println!(
            "{}",
            &raw[raw.find("\"logsBloom\":").unwrap() + 13..] // jump after `"logsBloom":"0x`
                .split('"')
                .next()
                .unwrap() // take only the hex
                .len()
        );
        println!("hi");

        let header = serde_json::from_str::<Header>(raw).unwrap();

        println!("{:#?}", header);
        let hash = header.hash_slow();
        assert_eq!(hash, b256!("661da523f3e44725f3a1cee38183d35424155a05674609a9f6ed81243adf9e26"));
    }

    /// Round-trip JSON + RLP for a “pure” post-EIP-7886 header.
    #[test]
    fn serde_rlp_eip7886_roundtrip() {
        // build a minimal post-EIP-7886 header
        let header = Header {
            state_root: None,
            transactions_root: None,
            receipts_root: None,
            logs_bloom: None,
            pre_state_root: Some(EMPTY_ROOT_HASH),
            parent_transactions_root: Some(EMPTY_ROOT_HASH),
            parent_receipts_root: Some(EMPTY_ROOT_HASH),
            parent_logs_bloom: Some(Default::default()),
            parent_requests_hash: Some(EMPTY_ROOT_HASH),
            parent_execution_reverted: Some(true),
            // everything else default
            ..Header::default()
        };
        assert!(header.eip7886_active());
        println!("{:#?}", header);
        println!("EIP-7886 active: {}", header.eip7886_active());

        // JSON
        let json = serde_json::to_string(&header).unwrap();
        let de: Header = serde_json::from_str(&json).unwrap();
        assert_eq!(de, header);
        println!("JSON: {}", json);

        // RLP
        let mut v = Vec::new();
        header.encode(&mut v);
        let decoded = Header::decode(&mut v.as_slice()).unwrap();
        assert_eq!(decoded, header);
    }

    /// The `parent_execution_reverted` flag must be encoded as 0 / 1.
    #[test]
    fn parent_execution_reverted_rlp_encoding() {
        let roundtrip = |flag: bool| {
            let h = Header {
                // EIP-7886 fields - all present in a proper EIP-7886 header
                pre_state_root: Some(EMPTY_ROOT_HASH),
                parent_transactions_root: Some(EMPTY_ROOT_HASH),
                parent_receipts_root: Some(EMPTY_ROOT_HASH),
                parent_logs_bloom: Some(Default::default()),
                parent_requests_hash: Some(EMPTY_ROOT_HASH),
                parent_execution_reverted: Some(flag),
                // Legacy fields should be None in EIP-7886
                state_root: None,
                transactions_root: None,
                receipts_root: None,
                logs_bloom: None,
                ..Header::default()
            };
            let mut bytes = Vec::new();
            h.encode(&mut bytes);
            let decoded = Header::decode(&mut bytes.as_slice()).unwrap();
            assert_eq!(decoded.parent_execution_reverted, Some(flag));
        };

        roundtrip(true);
        roundtrip(false);
    }
}
