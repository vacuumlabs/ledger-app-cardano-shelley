#include "common.h"
#include "txHashBuilder.h"
#include "hash.h"
#include "cbor.h"
#include "cardano.h"
#include "crc32.h"
#include "bufView.h"

// this tracing is rarely needed
// so we want to keep it turned off to avoid polluting the trace log

//#define TRACE_TX_HASH_BUILDER

#ifdef TRACE_TX_HASH_BUILDER
#define _TRACE(...) TRACE(__VA_ARGS__)
#else
#define _TRACE(...)
#endif // DEVEL


/*
The following macros and functions have dual purpose:
1. syntactic sugar for neat recording of hash computations;
2. tracing of hash computations (allows to reconstruct bytestrings we are hashing via usbtool).
*/

#define BUILDER_APPEND_CBOR(type, value) \
	blake2b_256_append_cbor_tx_body(&builder->txHash, type, value)

#define BUILDER_APPEND_DATA(buffer, bufferSize) \
	blake2b_256_append_buffer_tx_body(&builder->txHash, buffer, bufferSize)


static void blake2b_256_append_buffer_tx_body(
        blake2b_256_context_t* hashCtx,
        const uint8_t* buffer,
        size_t bufferSize
)
{
	TRACE_BUFFER(buffer, bufferSize);
	blake2b_256_append(hashCtx, buffer, bufferSize);
}

__noinline_due_to_stack__
static void blake2b_256_append_cbor_tx_body(
        blake2b_256_context_t* hashCtx,
        uint8_t type, uint64_t value
)
{
	uint8_t buffer[10];
	size_t size = cbor_writeToken(type, value, buffer, SIZEOF(buffer));
	TRACE_BUFFER(buffer, size);
	blake2b_256_append(hashCtx, buffer, size);
}

/* End of hash computation utilities. */

void txHashBuilder_init(
        tx_hash_builder_t* builder,
        uint16_t numInputs,
        uint16_t numOutputs,
        bool includeTtl,
        uint16_t numCertificates,
        uint16_t numWithdrawals,
        bool includeAuxData,
        bool includeValidityIntervalStart,
        bool includeMint
)
{
	TRACE("numInputs = %u", numInputs);
	TRACE("numOutputs = %u", numOutputs);
	TRACE("includeTtl = %u", includeTtl);
	TRACE("numCertificates = %u", numCertificates);
	TRACE("numWithdrawals  = %u", numWithdrawals);
	TRACE("includeAuxData = %u", includeAuxData);
	TRACE("includeValidityIntervalStart = %u", includeValidityIntervalStart);
	TRACE("includeMint = %u", includeMint);

	blake2b_256_init(&builder->txHash);

	{
		size_t numItems = 0;

		builder->remainingInputs = numInputs;
		numItems++; // an array that is always included (even if empty)

		builder->remainingOutputs = numOutputs;
		numItems++; // an array that is always included (even if empty)

		// fee always included
		numItems++;

		builder->includeTtl = includeTtl;
		if (includeTtl) numItems++;

		builder->remainingCertificates = numCertificates;
		if (numCertificates > 0) numItems++;

		builder->remainingWithdrawals = numWithdrawals;
		if (numWithdrawals > 0) numItems++;

		builder->includeAuxData = includeAuxData;
		if (includeAuxData) numItems++;

		builder->includeValidityIntervalStart = includeValidityIntervalStart;
		if (includeValidityIntervalStart) numItems++;

		builder->includeMint = includeMint;
		if (includeMint) numItems++;

		ASSERT((3 <= numItems) && (numItems <= 9));

		_TRACE("Serializing tx body with %u items", numItems);
		BUILDER_APPEND_CBOR(CBOR_TYPE_MAP, numItems);
	}
	builder->state = TX_HASH_BUILDER_INIT;
}

static void txHashBuilder_assertCanLeaveInit(tx_hash_builder_t* builder)
{
	_TRACE("state = %d", builder->state);

	ASSERT(builder->state == TX_HASH_BUILDER_INIT);
}

void txHashBuilder_enterInputs(tx_hash_builder_t* builder)
{
	_TRACE("state = %d", builder->state);

	txHashBuilder_assertCanLeaveInit(builder);
	{
		// Enter inputs
		BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_INPUTS);
		BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, builder->remainingInputs);
	}
	builder->state = TX_HASH_BUILDER_IN_INPUTS;
}

void txHashBuilder_addInput(
        tx_hash_builder_t* builder,
        const uint8_t* utxoHashBuffer, size_t utxoHashSize,
        uint32_t utxoIndex
)
{
	_TRACE("state = %d, remainingInputs = %u", builder->state, builder->remainingInputs);

	ASSERT(builder->state == TX_HASH_BUILDER_IN_INPUTS);
	ASSERT(builder->remainingInputs > 0);
	builder->remainingInputs--;
	// Array(2)[
	//    Bytes[hash],
	//    Unsigned[index]
	// ]
	{
		BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2);
		{
			ASSERT(utxoHashSize == 32);
			BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, utxoHashSize);
			BUILDER_APPEND_DATA(utxoHashBuffer, utxoHashSize);
		}
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, utxoIndex);
		}
	}
}

static void txHashBuilder_assertCanLeaveInputs(tx_hash_builder_t* builder)
{
	_TRACE("state = %d, remainingInputs = %u", builder->state, builder->remainingInputs);

	ASSERT(builder->state == TX_HASH_BUILDER_IN_INPUTS);
	ASSERT(builder->remainingInputs == 0);
}

void txHashBuilder_enterOutputs(tx_hash_builder_t* builder)
{
	_TRACE("state = %d", builder->state);

	txHashBuilder_assertCanLeaveInputs(builder);
	{
		// Enter outputs
		BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_OUTPUTS);
		BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, builder->remainingOutputs);
	}
	builder->state = TX_HASH_BUILDER_IN_OUTPUTS;
}

void txHashBuilder_addOutput_topLevelData(
        tx_hash_builder_t* builder,
        const uint8_t* addressBuffer, size_t addressSize,
        uint64_t amount,
        uint16_t numAssetGroups
)
{
	_TRACE("state = %d, remainingOutputs = %u", builder->state, builder->remainingOutputs);

	ASSERT(builder->state == TX_HASH_BUILDER_IN_OUTPUTS);
	ASSERT(builder->remainingOutputs > 0);
	builder->remainingOutputs--;

	if (numAssetGroups == 0) {
		// Array(2)[
		//   Bytes[address]
		//   Unsigned[amount]
		// ]
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2);
			{
				BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, addressSize);
				BUILDER_APPEND_DATA(addressBuffer, addressSize);
			}
			{
				BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, amount);
			}
		}
		builder->state = TX_HASH_BUILDER_IN_OUTPUTS;
	} else {
		builder->multiassetData.remainingAssetGroups = numAssetGroups;
		// Array(2)[
		//   Bytes[address]
		//   Array(2)[]
		//     Unsigned[amount]
		//     Map(numAssetGroups)[
		//       // entries added later, { * policy_id => { * asset_name => uint } }
		//     ]
		//   ]
		// ]
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2);
			{
				BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, addressSize);
				BUILDER_APPEND_DATA(addressBuffer, addressSize);
			}
			{
				BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2);
				{
					BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, amount);
					BUILDER_APPEND_CBOR(CBOR_TYPE_MAP, numAssetGroups);
				}
			}
		}
		builder->state = TX_HASH_BUILDER_IN_OUTPUTS_ASSET_GROUP;
	}
}

__noinline_due_to_stack__
static void addTokenGroup(tx_hash_builder_t* builder,
                          const uint8_t* policyIdBuffer, size_t policyIdSize,
                          uint16_t numTokens,
                          tx_hash_builder_state_t mandatoryState,
                          tx_hash_builder_state_t nextState)
{
	_TRACE("state = %d, remainingAssetGroups = %u", builder->state, builder->multiassetData.remainingAssetGroups);

	ASSERT(builder->state == mandatoryState);
	ASSERT(builder->multiassetData.remainingAssetGroups > 0);
	builder->multiassetData.remainingAssetGroups--;

	ASSERT(numTokens > 0);
	builder->multiassetData.remainingTokens = numTokens;

	ASSERT(policyIdSize == MINTING_POLICY_ID_SIZE);

	// Bytes[policyId]
	// Map(numTokens)[
	//   // entried added later { * asset_name => auint }
	// ]
	{
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, policyIdSize);
			BUILDER_APPEND_DATA(policyIdBuffer, policyIdSize);
		}
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_MAP, numTokens);
		}
		builder->state = nextState;
	}
}

__noinline_due_to_stack__
static void addToken(tx_hash_builder_t* builder,
                     const uint8_t* assetNameBuffer, size_t assetNameSize,
                     uint64_t amount,
                     tx_hash_builder_state_t mandatoryState,
                     tx_hash_builder_state_t nextGroupState,
                     tx_hash_builder_state_t leaveState)
{
	_TRACE("state = %d, remainingTokens = %u", builder->state, builder->multiassetData.remainingTokens);

	ASSERT(builder->state == mandatoryState);
	ASSERT(builder->multiassetData.remainingTokens > 0);
	builder->multiassetData.remainingTokens--;

	ASSERT(assetNameSize <= ASSET_NAME_SIZE_MAX);

	// add a map entry:
	// Bytes[assetname]
	// Unsigned[Amount]
	{
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, assetNameSize);
			BUILDER_APPEND_DATA(assetNameBuffer, assetNameSize);
		}
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, amount);
		}
	}

	if (builder->multiassetData.remainingTokens == 0) {
		if (builder->multiassetData.remainingAssetGroups == 0)
			builder->state = leaveState;
		else
			builder->state = nextGroupState;
	} else {
		// we remain in current state
		// because we are expecting more token amounts
	}
}

void txHashBuilder_addOutput_tokenGroup(
        tx_hash_builder_t* builder,
        const uint8_t* policyIdBuffer, size_t policyIdSize,
        uint16_t numTokens
)
{
	addTokenGroup(builder, policyIdBuffer, policyIdSize, numTokens,
	              TX_HASH_BUILDER_IN_OUTPUTS_ASSET_GROUP, TX_HASH_BUILDER_IN_OUTPUTS_TOKEN);
}

void txHashBuilder_addOutput_token(
        tx_hash_builder_t* builder,
        const uint8_t* assetNameBuffer, size_t assetNameSize,
        uint64_t amount
)
{
	addToken(builder, assetNameBuffer, assetNameSize, amount,
	         TX_HASH_BUILDER_IN_OUTPUTS_TOKEN,
	         TX_HASH_BUILDER_IN_OUTPUTS_ASSET_GROUP,
	         TX_HASH_BUILDER_IN_OUTPUTS);
}

static void txHashBuilder_assertCanLeaveOutputs(tx_hash_builder_t* builder)
{
	_TRACE("state = %d, remainingOutputs = %u", builder->state, builder->remainingOutputs);

	ASSERT(builder->state == TX_HASH_BUILDER_IN_OUTPUTS);
	ASSERT(builder->remainingOutputs == 0);
}

void txHashBuilder_addFee(tx_hash_builder_t* builder, uint64_t fee)
{
	_TRACE("state = %d", builder->state);

	txHashBuilder_assertCanLeaveOutputs(builder);

	// add fee item into the main tx body map
	BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_FEE);
	BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, fee);

	builder->state = TX_HASH_BUILDER_IN_FEE;
}

static void txHashBuilder_assertCanLeaveFee(tx_hash_builder_t* builder)
{
	_TRACE("state = %d", builder->state);

	ASSERT(builder->state == TX_HASH_BUILDER_IN_FEE);
}

void txHashBuilder_addTtl(tx_hash_builder_t* builder, uint64_t ttl)
{
	_TRACE("state = %d", builder->state);

	txHashBuilder_assertCanLeaveFee(builder);

	BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_TTL);
	BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, ttl);

	builder->state = TX_HASH_BUILDER_IN_TTL;
}

static void txHashBuilder_assertCanLeaveTtl(tx_hash_builder_t* builder)
{
	_TRACE("state = %d", builder->state);

	switch (builder->state) {
	case TX_HASH_BUILDER_IN_TTL:
		break;

	case TX_HASH_BUILDER_IN_FEE:
		txHashBuilder_assertCanLeaveFee(builder);
		ASSERT(!builder->includeTtl);
		break;

	default:
		ASSERT(false);
	}
}

void txHashBuilder_enterCertificates(tx_hash_builder_t* builder)
{
	_TRACE("state = %d, remaining certificates = %u", builder->state, builder->remainingCertificates);

	txHashBuilder_assertCanLeaveTtl(builder);
	ASSERT(builder->remainingCertificates > 0);

	{
		// Enter certificates
		BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_CERTIFICATES);
		BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, builder->remainingCertificates);
	}

	builder->poolCertificateData.remainingOwners = 0;
	builder->poolCertificateData.remainingRelays = 0;

	builder->state = TX_HASH_BUILDER_IN_CERTIFICATES;
}

// staking key certificate registration or deregistration
void txHashBuilder_addCertificate_stakingKey(
        tx_hash_builder_t* builder,
        const certificate_type_t certificateType,
        const uint8_t* stakingKeyHash, size_t stakingKeyHashSize
)
{
	_TRACE("state = %d, remainingCertificates = %u", builder->state, builder->remainingCertificates);

	ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES);
	ASSERT(builder->remainingCertificates > 0);
	builder->remainingCertificates--;

	ASSERT((certificateType == CERTIFICATE_TYPE_STAKE_REGISTRATION)
	       || (certificateType == CERTIFICATE_TYPE_STAKE_DEREGISTRATION));

	// Array(2)[
	//   Unsigned[certificateType]
	//   Array(2)[
	//     Unsigned[0]
	//     Bytes[stakingKeyHash]
	//   ]
	// ]
	{
		BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2);
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, certificateType);
		}
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2);
			{
				BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, 0);
			}
			{
				BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, stakingKeyHashSize);
				BUILDER_APPEND_DATA(stakingKeyHash, stakingKeyHashSize);
			}
		}
	}
}

void txHashBuilder_addCertificate_delegation(
        tx_hash_builder_t* builder,
        const uint8_t* stakingKeyHash, size_t stakingKeyHashSize,
        const uint8_t* poolKeyHash, size_t poolKeyHashSize
)
{
	_TRACE("state = %d, remainingCertificates = %u", builder->state, builder->remainingCertificates);

	ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES);
	ASSERT(builder->remainingCertificates > 0);
	builder->remainingCertificates--;

	// Array(3)[
	//   Unsigned[2]
	//   Array(2)[
	//     Unsigned[0]
	//     Bytes[stakingKeyHash]
	//   ]
	//   Bytes[poolKeyHash]
	// ]
	{
		BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 3);
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, 2);
		}
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2);
			{
				BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, 0);
			}
			{
				BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, stakingKeyHashSize);
				BUILDER_APPEND_DATA(stakingKeyHash, stakingKeyHashSize);
			}
		}
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, poolKeyHashSize);
			BUILDER_APPEND_DATA(poolKeyHash, poolKeyHashSize);
		}
	}
}

void txHashBuilder_addCertificate_poolRetirement(
        tx_hash_builder_t* builder,
        uint8_t* poolKeyHash, size_t poolKeyHashSize,
        uint64_t epoch
)
{
	_TRACE("state = %d", builder->state);

	ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES);
	ASSERT(builder->remainingCertificates > 0);
	builder->remainingCertificates--;

	// Array(3)[
	//   Unsigned[4]
	//   Bytes[poolKeyHash]
	//   Unsigned[epoch]
	// ]
	{
		BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 3);
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, 4);
		}
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, poolKeyHashSize);
			BUILDER_APPEND_DATA(poolKeyHash, poolKeyHashSize);
		}
		BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, epoch);
	}
}

void txHashBuilder_poolRegistrationCertificate_enter(
        tx_hash_builder_t* builder,
        uint16_t numOwners, uint16_t numRelays
)
{
	_TRACE("state = %d, remainingCertificates = %u", builder->state, builder->remainingCertificates);

	ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES);
	ASSERT(builder->remainingCertificates > 0);
	builder->remainingCertificates--;

	ASSERT(builder->poolCertificateData.remainingOwners == 0);
	builder->poolCertificateData.remainingOwners = numOwners;
	ASSERT(builder->poolCertificateData.remainingRelays == 0);
	builder->poolCertificateData.remainingRelays = numRelays;

	// Array(10)[
	//   Unsigned[3]

	{
		BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 10);
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, 3);
		}
	}

	builder->state = TX_HASH_BUILDER_IN_CERTIFICATES_POOL_INIT;
}

void txHashBuilder_poolRegistrationCertificate_poolKeyHash(
        tx_hash_builder_t* builder,
        uint8_t* poolKeyHash, size_t poolKeyHashSize
)
{
	_TRACE("state = %d", builder->state);

	ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES_POOL_INIT);

	ASSERT(poolKeyHashSize == POOL_KEY_HASH_LENGTH);

	//   Bytes[pool_keyhash]          // also called operator in CDDL specs and pool id in user interfaces
	{
		BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, poolKeyHashSize);
		BUILDER_APPEND_DATA(poolKeyHash, poolKeyHashSize);
	}

	builder->state = TX_HASH_BUILDER_IN_CERTIFICATES_POOL_KEY_HASH;
}

void txHashBuilder_poolRegistrationCertificate_vrfKeyHash(
        tx_hash_builder_t* builder,
        uint8_t* vrfKeyHash, size_t vrfKeyHashSize
)
{
	_TRACE("state = %d", builder->state);

	ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES_POOL_KEY_HASH);

	ASSERT(vrfKeyHashSize == VRF_KEY_HASH_LENGTH);

	//   Bytes[vrf_keyhash]
	{
		BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, vrfKeyHashSize);
		BUILDER_APPEND_DATA(vrfKeyHash, vrfKeyHashSize);
	}

	builder->state = TX_HASH_BUILDER_IN_CERTIFICATES_POOL_VRF;
}

void txHashBuilder_poolRegistrationCertificate_financials(
        tx_hash_builder_t* builder,
        uint64_t pledge, uint64_t cost,
        uint64_t marginNumerator, uint64_t marginDenominator
)
{
	_TRACE("state = %d", builder->state);

	ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES_POOL_VRF);

	//   Unsigned[pledge]
	//   Unsigned[cost]
	//   Tag(30) Array(2)[
	//     Unsigned[marginDenominator]
	//     Unsigned[marginNumerator]
	//   ]
	{
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, pledge);
		}
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, cost);
		}
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_TAG, 30);
			BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2);
			{
				BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, marginNumerator);
			}
			{
				BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, marginDenominator);
			}
		}
	}

	builder->state = TX_HASH_BUILDER_IN_CERTIFICATES_POOL_FINANCIALS;
}

void txHashBuilder_poolRegistrationCertificate_rewardAccount(
        tx_hash_builder_t* builder,
        uint8_t* rewardAccount, size_t rewardAccountSize
)
{
	_TRACE("state = %d", builder->state);

	ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES_POOL_FINANCIALS);

	ASSERT(rewardAccountSize == REWARD_ACCOUNT_SIZE);

	//   Bytes[rewardAccount]
	{
		BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, rewardAccountSize);
		BUILDER_APPEND_DATA(rewardAccount, rewardAccountSize);
	}

	builder->state = TX_HASH_BUILDER_IN_CERTIFICATES_POOL_REWARD_ACCOUNT;
}

void txHashBuilder_addPoolRegistrationCertificate_enterOwners(tx_hash_builder_t* builder)
{
	_TRACE("state = %d", builder->state);

	ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES_POOL_REWARD_ACCOUNT);

	{
		BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, builder->poolCertificateData.remainingOwners);
	}

	builder->state = TX_HASH_BUILDER_IN_CERTIFICATES_POOL_OWNERS;
}

void txHashBuilder_addPoolRegistrationCertificate_addOwner(
        tx_hash_builder_t* builder,
        const uint8_t* stakingKeyHash, size_t stakingKeyHashSize
)
{
	_TRACE("state = %d, remainingOwners = %u", builder->state, builder->poolCertificateData.remainingOwners);

	ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES_POOL_OWNERS);
	ASSERT(builder->poolCertificateData.remainingOwners > 0);
	builder->poolCertificateData.remainingOwners--;

	// Bytes[poolKeyHash]
	{
		BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, stakingKeyHashSize);
		BUILDER_APPEND_DATA(stakingKeyHash, stakingKeyHashSize);
	}
}

void txHashBuilder_addPoolRegistrationCertificate_enterRelays(tx_hash_builder_t* builder)
{
	_TRACE("state = %d, remainingOwners = %u", builder->state, builder->poolCertificateData.remainingOwners);

	// enter empty owners if none were received (and none were expected)
	if (builder->state == TX_HASH_BUILDER_IN_CERTIFICATES_POOL_REWARD_ACCOUNT) {
		ASSERT(builder->poolCertificateData.remainingOwners == 0);
		txHashBuilder_addPoolRegistrationCertificate_enterOwners(builder);
	}

	ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES_POOL_OWNERS);
	ASSERT(builder->poolCertificateData.remainingOwners == 0);

	{
		BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, builder->poolCertificateData.remainingRelays);
	}

	builder->state = TX_HASH_BUILDER_IN_CERTIFICATES_POOL_RELAYS;
}

static void _relay_addPort(tx_hash_builder_t* builder, ipport_t* port)
{
	_TRACE("state = %d, remainingRelays = %u", builder->state, builder->poolCertificateData.remainingRelays);

	ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES_POOL_RELAYS);

	//   Unsigned[port] / Null
	if (port->isNull) {
		BUILDER_APPEND_CBOR(CBOR_TYPE_NULL, 0);
	} else {
		BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, port->number);
	}
}

static void _relay_addIpv4(tx_hash_builder_t* builder, ipv4_t* ipv4)
{
	_TRACE("state = %d, remainingRelays = %u", builder->state, builder->poolCertificateData.remainingRelays);

	ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES_POOL_RELAYS);

	//   Bytes[ipv4] / Null
	if (ipv4->isNull) {
		BUILDER_APPEND_CBOR(CBOR_TYPE_NULL, 0);
	} else {
		STATIC_ASSERT(sizeof(ipv4->ip) == IPV4_SIZE, "wrong ipv4 size"); // SIZEOF does not work for 4-byte buffers
		BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, IPV4_SIZE);
		BUILDER_APPEND_DATA(ipv4->ip, IPV4_SIZE);
	}
}

static void _relay_addIpv6(tx_hash_builder_t* builder, const ipv6_t* ipv6)
{
	_TRACE("state = %d, remainingRelays = %u", builder->state, builder->poolCertificateData.remainingRelays);

	ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES_POOL_RELAYS);

	//   Bytes[ipv6] / Null
	if (ipv6->isNull) {
		BUILDER_APPEND_CBOR(CBOR_TYPE_NULL, 0);
	} else {
		STATIC_ASSERT(SIZEOF(ipv6->ip) == IPV6_SIZE, "wrong ipv6 size");
		BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, IPV6_SIZE);

		// serialized as 4 big-endian uint32
		// we need a local copy of the data to make the following pointer tricks work
		// the copy is created by memcpy instead of struct assignment to avoid compiler optimizing it away
		uint8_t ipBuffer[IPV6_SIZE];
		memcpy(ipBuffer, ipv6->ip, SIZEOF(ipBuffer));
		STATIC_ASSERT(SIZEOF(ipBuffer) == 16, "wrong ipv6 size");

		uint32_t* as_uint32 = (uint32_t*) ipBuffer;
		for (size_t i = 0; i < 4; i++) {
			uint8_t chunk[4];
			u4be_write(chunk, as_uint32[i]);
			BUILDER_APPEND_DATA(chunk, 4);
		}
	}
}

static void _relay_addDnsName(tx_hash_builder_t* builder, pool_relay_t* relay)
{
	_TRACE("state = %d, remainingRelays = %u", builder->state, builder->poolCertificateData.remainingRelays);

	ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES_POOL_RELAYS);

	ASSERT(relay->dnsNameSize <= DNS_NAME_SIZE_MAX);

	//   Text[dnsName]
	{
		BUILDER_APPEND_CBOR(CBOR_TYPE_TEXT, relay->dnsNameSize);
		BUILDER_APPEND_DATA(relay->dnsName, relay->dnsNameSize);
	}
}

void txHashBuilder_addPoolRegistrationCertificate_addRelay(
        tx_hash_builder_t* builder,
        pool_relay_t* relay
)
{
	_TRACE("state = %d, remainingRelays = %u", builder->state, builder->poolCertificateData.remainingRelays);

	ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES_POOL_RELAYS);
	ASSERT(builder->poolCertificateData.remainingRelays > 0);
	builder->poolCertificateData.remainingRelays--;

	switch(relay->format) {
	case RELAY_SINGLE_HOST_IP: {
		// Array(4)[
		//   Unsigned[0]
		//   Unsigned[port] / Null
		//   Bytes[ipv4] / Null
		//   Bytes[ipv6] / Null
		// ]
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 4);
			{
				BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, 0);
			}
			_relay_addPort(builder, &relay->port);
			_relay_addIpv4(builder, &relay->ipv4);
			_relay_addIpv6(builder, &relay->ipv6);
		}
		break;
	}
	case RELAY_SINGLE_HOST_NAME: {
		// Array(3)[
		//   Unsigned[1]
		//   Unsigned[port] / Null
		//   Text[dnsName]
		// ]
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 3);
			{
				BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, 1);
			}
			_relay_addPort(builder, &relay->port);
			_relay_addDnsName(builder, relay);
		}
		break;
	}
	case RELAY_MULTIPLE_HOST_NAME: {
		// Array(2)[
		//   Unsigned[2]
		//   Text[dnsName]
		// ]
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2);
			{
				BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, 2);
			}
			_relay_addDnsName(builder, relay);
		}
		break;
	}
	default:
		ASSERT(false);
	}
}

// enter empty owners or relays if none were received
static void addPoolMetadata_updateState(tx_hash_builder_t* builder)
{
	switch (builder->state) {
	case TX_HASH_BUILDER_IN_CERTIFICATES_POOL_REWARD_ACCOUNT:
		// skipping owners is only possible if none were expected
		ASSERT(builder->poolCertificateData.remainingOwners == 0);
		txHashBuilder_addPoolRegistrationCertificate_enterOwners(builder);

	// intentional fallthrough

	case TX_HASH_BUILDER_IN_CERTIFICATES_POOL_OWNERS:
		// skipping relays is only possible if none were expected
		ASSERT(builder->poolCertificateData.remainingRelays == 0);
		txHashBuilder_addPoolRegistrationCertificate_enterRelays(builder);

	// intentional fallthrough

	case TX_HASH_BUILDER_IN_CERTIFICATES_POOL_RELAYS:
		// all relays should have been received
		ASSERT(builder->poolCertificateData.remainingRelays == 0);
		break; // we want to be here

	default:
		ASSERT(false);
	}

	builder->state = TX_HASH_BUILDER_IN_CERTIFICATES_POOL_METADATA;
}

void txHashBuilder_addPoolRegistrationCertificate_addPoolMetadata(
        tx_hash_builder_t* builder,
        const uint8_t* url, size_t urlSize,
        const uint8_t* metadataHash, size_t metadataHashSize
)
{
	_TRACE("state = %d", builder->state);

	// we allow this to be called immediately after pool params have been added
	// if there are no owners or relays in the tx
	addPoolMetadata_updateState(builder);
	ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES_POOL_METADATA);

	// Array(2)[
	//   Tstr[url]
	//   Bytes[metadataHash]
	// ]
	{
		BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2);
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_TEXT, urlSize);
			BUILDER_APPEND_DATA(url, urlSize);
		}
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, metadataHashSize);
			BUILDER_APPEND_DATA(metadataHash, metadataHashSize);
		}
	}
	builder->state = TX_HASH_BUILDER_IN_CERTIFICATES;
}

void txHashBuilder_addPoolRegistrationCertificate_addPoolMetadata_null(
        tx_hash_builder_t* builder
)
{
	_TRACE("state = %d", builder->state);

	addPoolMetadata_updateState(builder);
	ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES_POOL_METADATA);
	{
		BUILDER_APPEND_CBOR(CBOR_TYPE_NULL, 0);
	}
	builder->state = TX_HASH_BUILDER_IN_CERTIFICATES;
}

static void txHashBuilder_assertCanLeaveCertificates(tx_hash_builder_t* builder)
{
	_TRACE("state = %d, remainingCertificates = %u", builder->state, builder->remainingCertificates);

	switch (builder->state) {
	case TX_HASH_BUILDER_IN_CERTIFICATES:
		break;

	case TX_HASH_BUILDER_IN_TTL:
	case TX_HASH_BUILDER_IN_FEE:
		txHashBuilder_assertCanLeaveTtl(builder);
		break;

	default:
		ASSERT(false);
	}

	ASSERT(builder->remainingCertificates == 0);
}

void txHashBuilder_enterWithdrawals(tx_hash_builder_t* builder)
{
	_TRACE("state = %d, remainingWithdrawals = %u", builder->state, builder->remainingWithdrawals);

	txHashBuilder_assertCanLeaveCertificates(builder);
	ASSERT(builder->remainingWithdrawals > 0);

	{
		// enter withdrawals
		BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_WITHDRAWALS);
		BUILDER_APPEND_CBOR(CBOR_TYPE_MAP, builder->remainingWithdrawals);
	}

	builder->state = TX_HASH_BUILDER_IN_WITHDRAWALS;
}

void txHashBuilder_addWithdrawal(
        tx_hash_builder_t* builder,
        const uint8_t* rewardAddressBuffer, size_t rewardAddressSize,
        uint64_t amount
)
{
	// should call cbor_mapKeyFulfillsCanonicalOrdering for withdrawals,
	// but storing the previous withdrawal would increase the memory footprint of tx_hash_builder_t too much
	_TRACE("state = %d, remainingWithdrawals = %u", builder->state, builder->remainingWithdrawals);

	ASSERT(builder->state == TX_HASH_BUILDER_IN_WITHDRAWALS);
	ASSERT(builder->remainingWithdrawals > 0);
	builder->remainingWithdrawals--;

	ASSERT(rewardAddressSize == 1 + ADDRESS_KEY_HASH_LENGTH);

	// map entry
	//   Bytes[address]
	//   Unsigned[amount]
	{
		BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, rewardAddressSize);
		BUILDER_APPEND_DATA(rewardAddressBuffer, rewardAddressSize);
	}
	{
		BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, amount);
	}
}

static void txHashBuilder_assertCanLeaveWithdrawals(tx_hash_builder_t* builder)
{
	_TRACE("state = %d, remainingWithdrawals = %u", builder->state, builder->remainingWithdrawals);

	switch (builder->state) {
	case TX_HASH_BUILDER_IN_WITHDRAWALS:
		break;

	case TX_HASH_BUILDER_IN_CERTIFICATES:
	case TX_HASH_BUILDER_IN_TTL:
	case TX_HASH_BUILDER_IN_FEE:
		txHashBuilder_assertCanLeaveCertificates(builder);
		break;

	default:
		ASSERT(false);
	}

	ASSERT(builder->remainingWithdrawals == 0);
}

void txHashBuilder_addAuxData(tx_hash_builder_t* builder, const uint8_t* auxDataHashBuffer, size_t auxDataHashBufferSize)
{
	_TRACE("state = %d, remainingWithdrawals = %u", builder->state, builder->remainingWithdrawals);

	txHashBuilder_assertCanLeaveWithdrawals(builder);
	ASSERT(builder->includeAuxData);

	{
		BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_AUX_DATA);
		BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, auxDataHashBufferSize);
		BUILDER_APPEND_DATA(auxDataHashBuffer, auxDataHashBufferSize);
	}
	builder->state = TX_HASH_BUILDER_IN_AUX_DATA;
}

static void txHashBuilder_assertCanLeaveAuxData(tx_hash_builder_t* builder)
{
	_TRACE("state = %d", builder->state);

	switch (builder->state) {
	case TX_HASH_BUILDER_IN_AUX_DATA:
		break;

	case TX_HASH_BUILDER_IN_WITHDRAWALS:
	case TX_HASH_BUILDER_IN_CERTIFICATES:
	case TX_HASH_BUILDER_IN_TTL:
	case TX_HASH_BUILDER_IN_FEE:
		txHashBuilder_assertCanLeaveWithdrawals(builder);
		ASSERT(!builder->includeAuxData);
		break;

	default:
		ASSERT(false);
	}
}

void txHashBuilder_addValidityIntervalStart(tx_hash_builder_t* builder, uint64_t validityIntervalStart)
{
	_TRACE("state = %d", builder->state);

	txHashBuilder_assertCanLeaveAuxData(builder);

	// add validity interval start item into the main tx body map
	BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_VALIDITY_INTERVAL_START);
	BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, validityIntervalStart);

	builder->state = TX_HASH_BUILDER_IN_VALIDITY_INTERVAL_START;
}

static void txHashBuilder_assertCanLeaveValidityIntervalStart(tx_hash_builder_t* builder)
{
	_TRACE("state = %d", builder->state);

	switch (builder->state) {
	case TX_HASH_BUILDER_IN_VALIDITY_INTERVAL_START:
		break;

	case TX_HASH_BUILDER_IN_AUX_DATA:
	case TX_HASH_BUILDER_IN_WITHDRAWALS:
	case TX_HASH_BUILDER_IN_CERTIFICATES:
	case TX_HASH_BUILDER_IN_TTL:
	case TX_HASH_BUILDER_IN_FEE:
		txHashBuilder_assertCanLeaveAuxData(builder);
		ASSERT(!builder->includeValidityIntervalStart);
		break;

	default:
		ASSERT(false);
	}
}

void txHashBuilder_enterMint(tx_hash_builder_t* builder)
{
	_TRACE("state = %d", builder->state);

	txHashBuilder_assertCanLeaveValidityIntervalStart(builder);
	{
		// Enter mint
		BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_MINT);
	}
	builder->state = TX_HASH_BUILDER_IN_MINT;
}

void txHashBuilder_addMint_topLevelData(
        tx_hash_builder_t* builder, uint16_t numAssetGroups
)
{
	_TRACE("state = %u", builder->state);

	ASSERT(builder->state == TX_HASH_BUILDER_IN_MINT);

	builder->multiassetData.remainingAssetGroups = numAssetGroups;
	// Map(numAssetGroups)[
	//   { * policy_id => { * asset_name => uint } }
	// ]
	BUILDER_APPEND_CBOR(CBOR_TYPE_MAP, numAssetGroups);
	if (0 != numAssetGroups) {
		builder->state = TX_HASH_BUILDER_IN_MINT_ASSET_GROUP;
	} else {
		// TODO is this an error case?
	}
}

void txHashBuilder_addMint_tokenGroup(
        tx_hash_builder_t* builder,
        const uint8_t* policyIdBuffer, size_t policyIdSize,
        uint16_t numTokens
)
{
	addTokenGroup(builder, policyIdBuffer, policyIdSize, numTokens,
	              TX_HASH_BUILDER_IN_MINT_ASSET_GROUP, TX_HASH_BUILDER_IN_MINT_TOKEN);
}

void txHashBuilder_addMint_token(
        tx_hash_builder_t* builder,
        const uint8_t* assetNameBuffer, size_t assetNameSize,
        int64_t amount
)
{
	//  TODO int64 -> uint64 conversion should work fine ?
	// 	  BUILDER_APPEND_CBOR
	addToken(builder, assetNameBuffer, assetNameSize, amount,
	         TX_HASH_BUILDER_IN_MINT_TOKEN,
	         TX_HASH_BUILDER_IN_MINT_ASSET_GROUP,
	         TX_HASH_BUILDER_IN_MINT);
}

static void txHashBuilder_assertCanLeaveMint(tx_hash_builder_t* builder)
{
	_TRACE("state = %u, remainingMintAssetGroups = %u, remainingMintTokens = %u",
	       builder->state, builder->multiassetData.remainingAssetGroups, builder->multiassetData.remainingTokens);

	switch (builder->state) {
	case TX_HASH_BUILDER_IN_MINT:
		break;

	case TX_HASH_BUILDER_IN_VALIDITY_INTERVAL_START:
	case TX_HASH_BUILDER_IN_AUX_DATA:
	case TX_HASH_BUILDER_IN_WITHDRAWALS:
	case TX_HASH_BUILDER_IN_CERTIFICATES:
	case TX_HASH_BUILDER_IN_TTL:
	case TX_HASH_BUILDER_IN_FEE:
		txHashBuilder_assertCanLeaveValidityIntervalStart(builder);
		ASSERT(!builder->includeMint);
		break;

	default:
		ASSERT(false);
	}

	ASSERT(builder->multiassetData.remainingAssetGroups == 0);
	ASSERT(builder->multiassetData.remainingTokens == 0);
}


void txHashBuilder_finalize(tx_hash_builder_t* builder, uint8_t* outBuffer, size_t outSize)
{
	txHashBuilder_assertCanLeaveMint(builder);

	ASSERT(outSize == 32);
	{
		blake2b_256_finalize(&builder->txHash, outBuffer, outSize);
	}

	builder->state = TX_HASH_BUILDER_FINISHED;
}
