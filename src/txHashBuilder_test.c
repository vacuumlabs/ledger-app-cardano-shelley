#ifdef DEVEL

#include "txHashBuilder.h"
#include "cardano.h"
#include "hexUtils.h"
#include "textUtils.h"
#include "testUtils.h"


static struct {
	const char* txHashHex;
	int index;
} inputs[] = {
	{
		"0B40265111D8BB3C3C608D95B3A0BF83461ACE32D79336579A1939B3AAD1C0B7",
		0
	},
	{
		"1B40265111D8BB3C3C608D95B3A0BF83461ACE32D79336579A1939B3AAD1C0B7",
		1
	},
	{
		"2B40265111D8BB3C3C608D95B3A0BF83461ACE32D79336579A1939B3AAD1C0B7",
		2
	},
	{
		"3B40265111D8BB3C3C608D95B3A0BF83461ACE32D79336579A1939B3AAD1C0B7",
		3
	},
};

static struct {
	const char* rawAddressHex;
	uint64_t amount;
} outputs[] = {
	{
		"82D818582183581C6EE5BB111C8771CE03278E624056A12C9CFB353EB112E8ABF21FA4FEA0001A74EEE408",
		100
	},
	{
		"009493315CD92EB5D8C4304E67B7E16AE36D61D34502694657811A2C8E32C728D3861E164CAB28CB8F006448139C8F1740FFB8E7AA9E5232DC",
		200
	},
	{
		"409493315CD92EB5D8C4304E67B7E16AE36D61D34502694657811A2C8E87688F509738",
		300
	},
	{
		"609493315CD92EB5D8C4304E67B7E16AE36D61D34502694657811A2C8E",
		400
	},
	{
		"609493315CD92EB5D8C4304E67B7E16AE36D61D34502694657811A2C8E",
		500
	},
};

static struct {
	const char* stakingKeyHash;
} registrationCertificates[] = {
	{
		"32C728D3861E164CAB28CB8F006448139C8F1740FFB8E7AA9E5232DC"
	},
};

static struct {
	const char* stakingKeyHash;
} deregistrationCertificates[] = {
	{
		"32C728D3861E164CAB28CB8F006448139C8F1740FFB8E7AA9E5232DC"
	},
	{
		"337B62CFFF6403A06A3ACBC34F8C46003C69FE79A3628CEFA9C47251"
	},
};

static struct {
	const char* stakingKeyHash;
	const char* poolKeyHash;
} delegationCertificates[] = {
	{
		"32C728D3861E164CAB28CB8F006448139C8F1740FFB8E7AA9E5232DC",
		"0D13015CDBCDBD0889CE276192A1601F2D4D20B8392D4EF4F9A754E2"
	},
	{
		"32C728D3861E164CAB28CB8F006448139C8F1740FFB8E7AA9E5232DC",
		"1D13015CDBCDBD0889CE276192A1601F2D4D20B8392D4EF4F9A754E2"
	},
	{
		"32C728D3861E164CAB28CB8F006448139C8F1740FFB8E7AA9E5232DC",
		"2D13015CDBCDBD0889CE276192A1601F2D4D20B8392D4EF4F9A754E2"
	},
};

static struct {
	const char* rewardAddress;
	uint64_t amount;
} withdrawals[] = {
	{
		"E032C728D3861E164CAB28CB8F006448139C8F1740FFB8E7AA9E5232DC",
		666
	}
};

static const char* expectedHex = "a185a8ec05862e17cae482c1d5407f3f3dae472212e8b7fb06e7ae8322e9529e";

typedef void(*addTokenGroupFun)(tx_hash_builder_t* builder,
                                const uint8_t* policyIdBuffer, size_t policyIdSize,
                                uint16_t numTokens);
typedef void(*addTokenFun)(tx_hash_builder_t* builder,
                           const uint8_t* assetNameBuffer, size_t assetNameSize,
                           uint64_t amount);

static void addTwoMultiassetTokenGroups(tx_hash_builder_t* builder,
                                        addTokenGroupFun tokenGroupAdder, addTokenFun tokenAdder)
{
	// we reuse the buffers to avoid wasting stack
	uint8_t policy[MINTING_POLICY_ID_SIZE] = {0};
	explicit_bzero(policy, SIZEOF(policy));

	uint8_t assetNameBuffer[ASSET_NAME_SIZE_MAX] = {0};
	explicit_bzero(assetNameBuffer, SIZEOF(assetNameBuffer));

	policy[0] = 1;
	tokenGroupAdder(builder, policy, SIZEOF(policy), 2);

	assetNameBuffer[0] = 11;
	tokenAdder(builder, assetNameBuffer, SIZEOF(assetNameBuffer), 110);
	assetNameBuffer[0] = 12;
	tokenAdder(builder, assetNameBuffer, SIZEOF(assetNameBuffer), 120);

	policy[0] = 2;
	tokenGroupAdder(builder, policy, SIZEOF(policy), 2);

	assetNameBuffer[0] = 21;
	tokenAdder(builder, assetNameBuffer, SIZEOF(assetNameBuffer), 210);
	assetNameBuffer[0] = 22;
	// use a short buffer on purpose
	tokenAdder(builder, assetNameBuffer, 1, 220);
}

static void addMintTokenProxy(tx_hash_builder_t* builder,
                              const uint8_t* assetNameBuffer, size_t assetNameSize,
                              uint64_t amount)
{
	txHashBuilder_addMint_token(builder, assetNameBuffer, assetNameSize, (int64_t)amount);
}

static void addMultiassetMint(tx_hash_builder_t* builder)
{
	txHashBuilder_addMint_topLevelData(builder, 2);
	addTwoMultiassetTokenGroups(builder, &txHashBuilder_addMint_tokenGroup, &addMintTokenProxy);
}

static void outputTokenHandler(
        tx_hash_builder_t* builder,
        const uint8_t* assetNameBuffer, size_t assetNameSize,
        uint64_t amount
)
{
	txHashBuilder_addOutput_token(builder, assetNameBuffer, assetNameSize, amount, false);
}


static void addMultiassetOutput(tx_hash_builder_t* builder)
{
	uint8_t tmp[70] = {0};
	size_t tmpSize = decode_hex(PTR_PIC(outputs[1].rawAddressHex), tmp, SIZEOF(tmp));
	txHashBuilder_addOutput_topLevelData(
	        builder,
	        tmp, tmpSize,
	        outputs[1].amount,
	        2,
	        false
	);

	addTwoMultiassetTokenGroups(builder, &txHashBuilder_addOutput_tokenGroup, &outputTokenHandler);
}

static void addOutputs(tx_hash_builder_t* builder)
{
	txHashBuilder_enterOutputs(builder);

	addMultiassetOutput(builder);

	ITERATE(it, outputs) {
		uint8_t tmp[70] = {0};
		size_t tmpSize = decode_hex(PTR_PIC(it->rawAddressHex), tmp, SIZEOF(tmp));
		txHashBuilder_addOutput_topLevelData(
		        builder,
		        tmp, tmpSize,
		        it->amount,
		        0, false
		);
	}

	// added for the second time to more thoroughly check the state machine
	addMultiassetOutput(builder);
}

static void addPoolRegistrationCertificate(tx_hash_builder_t* builder)
{
	uint8_t poolKeyHash[POOL_KEY_HASH_LENGTH] = {0};
	uint8_t vrfKeyHash[VRF_KEY_HASH_LENGTH] = {0};
	uint64_t pledge = 500000000;
	uint64_t cost = 340000000;
	uint64_t marginNumerator = 1;
	uint64_t marginDenominator = 1;
	uint8_t rewardAccount[REWARD_ACCOUNT_SIZE] = {0};

	size_t poolKeyHashSize = decode_hex(
	                                 "5631EDE662CFB10FD5FD69B4667101DD289568E12BCF5F64D1C406FC",
	                                 poolKeyHash, SIZEOF(poolKeyHash)
	                         );
	ASSERT(poolKeyHashSize == SIZEOF(poolKeyHash));

	size_t vrfKeyHashSize = decode_hex(
	                                "198890AD6C92E80FBDAB554DDA02DA9FB49D001BBD96181F3E07F7A6AB0D0640",
	                                vrfKeyHash, SIZEOF(vrfKeyHash)
	                        );
	ASSERT(vrfKeyHashSize == SIZEOF(vrfKeyHash));

	size_t rewardAccountSize = decode_hex(
	                                   "E03A7F09D3DF4CF66A7399C2B05BFA234D5A29560C311FC5DB4C490711",
	                                   rewardAccount, SIZEOF(rewardAccount)
	                           );
	ASSERT(rewardAccountSize == SIZEOF(rewardAccount));

	txHashBuilder_poolRegistrationCertificate_enter(builder, 1, 3);
	txHashBuilder_poolRegistrationCertificate_poolKeyHash(builder, poolKeyHash, SIZEOF(poolKeyHash));
	txHashBuilder_poolRegistrationCertificate_vrfKeyHash(builder, vrfKeyHash, SIZEOF(vrfKeyHash));
	txHashBuilder_poolRegistrationCertificate_financials(builder, pledge, cost, marginNumerator, marginDenominator);
	txHashBuilder_poolRegistrationCertificate_rewardAccount(builder, rewardAccount, SIZEOF(rewardAccount));

	txHashBuilder_addPoolRegistrationCertificate_enterOwners(builder);

	uint8_t owner1[28] = {0};
	size_t owner1Size = decode_hex("3A7F09D3DF4CF66A7399C2B05BFA234D5A29560C311FC5DB4C490711", owner1, SIZEOF(owner1));
	ASSERT(owner1Size == SIZEOF(owner1));

	txHashBuilder_addPoolRegistrationCertificate_addOwner(builder, owner1, owner1Size);

	txHashBuilder_addPoolRegistrationCertificate_enterRelays(builder);

	{
		pool_relay_t relay0;
		relay0.format = 0;
		relay0.port.isNull = false;
		relay0.port.number = 1234;
		relay0.ipv4.isNull = false;
		decode_hex("08080808", relay0.ipv4.ip, IPV4_SIZE);
		relay0.ipv6.isNull = true;
		txHashBuilder_addPoolRegistrationCertificate_addRelay(builder, &relay0);
	}
	{
		pool_relay_t relay1;
		relay1.format = 1;
		relay1.port.isNull = true;
		// a valid DNS AAAA record, since dnsName actually is suppposed to be an A or AAAA record
		const char* dnsName = "AAAA 2400:cb00:2049:1::a29f:1804";
		relay1.dnsNameSize = str_textToBuffer(dnsName, relay1.dnsName, SIZEOF(relay1.dnsName));
		txHashBuilder_addPoolRegistrationCertificate_addRelay(builder, &relay1);
	}
	{
		pool_relay_t relay2;
		relay2.format = 2;
		// dnsName is not a valid DNS SRV record, but we don't validate it
		const char* dnsName = "AAAA 2400:cb00:2049:1::a29f:1804";
		relay2.dnsNameSize = str_textToBuffer(dnsName, relay2.dnsName, SIZEOF(relay2.dnsName));
		txHashBuilder_addPoolRegistrationCertificate_addRelay(builder, &relay2);
	}

	uint8_t metadataHash[32] = {0};
	size_t metadataHashSize = decode_hex("914C57C1F12BBF4A82B12D977D4F274674856A11ED4B9B95BD70F5D41C5064A6", metadataHash, SIZEOF(metadataHash));
	ASSERT(metadataHashSize == SIZEOF(metadataHash));

	const char* metadataUrl = "https://teststakepool.com";
	uint8_t urlBuffer[DNS_NAME_SIZE_MAX] = {0};
	size_t urlSize = str_textToBuffer(metadataUrl, urlBuffer, SIZEOF(urlBuffer));
	ASSERT(urlSize <= DNS_NAME_SIZE_MAX);

	txHashBuilder_addPoolRegistrationCertificate_addPoolMetadata(builder, urlBuffer, urlSize, metadataHash, metadataHashSize);
}

static void addPoolRetirementCertificate(tx_hash_builder_t* builder)
{
	uint8_t poolKeyHash[POOL_KEY_HASH_LENGTH] = {0};
	uint64_t epoch = 1000;

	size_t poolKeyHashSize = decode_hex(
	                                 "5631EDE662CFB10FD5FD69B4667101DD289568E12BCF5F64D1C406FC",
	                                 poolKeyHash, SIZEOF(poolKeyHash)
	                         );
	ASSERT(poolKeyHashSize == SIZEOF(poolKeyHash));

	txHashBuilder_addCertificate_poolRetirement(
	        builder,
	        poolKeyHash, SIZEOF(poolKeyHash),
	        epoch
	);
}

static void addCertificates(tx_hash_builder_t* builder)
{
	txHashBuilder_enterCertificates(builder);

	ITERATE(it, registrationCertificates) {
		uint8_t tmp[70] = {0};
		size_t tmpSize = decode_hex(PTR_PIC(it->stakingKeyHash), tmp, SIZEOF(tmp));
		txHashBuilder_addCertificate_stakingHash(
		        builder,
		        CERTIFICATE_TYPE_STAKE_REGISTRATION,
		        STAKE_CREDENTIAL_KEY_PATH,
		        tmp, tmpSize
		);
	}

	ITERATE(it, deregistrationCertificates) {
		uint8_t tmp[70] = {0};
		size_t tmpSize = decode_hex(PTR_PIC(it->stakingKeyHash), tmp, SIZEOF(tmp));
		txHashBuilder_addCertificate_stakingHash(
		        builder,
		        CERTIFICATE_TYPE_STAKE_DEREGISTRATION,
		        STAKE_CREDENTIAL_KEY_PATH,
		        tmp, tmpSize
		);
	}

	addPoolRegistrationCertificate(builder);

	addPoolRetirementCertificate(builder);

	ITERATE(it, delegationCertificates) {
		uint8_t tmp_credential[70] = {0};
		size_t tmpSize_credential = decode_hex(
		                                    PTR_PIC(it->stakingKeyHash),
		                                    tmp_credential, SIZEOF(tmp_credential)
		                            );
		uint8_t tmp_pool[70] = {0};
		size_t tmpSize_pool = decode_hex(PTR_PIC(it->poolKeyHash), tmp_pool, SIZEOF(tmp_pool));
		txHashBuilder_addCertificate_delegation(
		        builder, STAKE_CREDENTIAL_KEY_PATH,
		        tmp_credential, tmpSize_credential,
		        tmp_pool, tmpSize_pool
		);
	}
}

static void addMint(tx_hash_builder_t* builder)
{
	txHashBuilder_enterMint(builder);

	addMultiassetMint(builder);
}

void run_txHashBuilder_test()
{
	PRINTF("txHashBuilder test\n");
	tx_hash_builder_t builder;

	const size_t numCertificates = ARRAY_LEN(registrationCertificates) +
	                               ARRAY_LEN(deregistrationCertificates) +
	                               ARRAY_LEN(delegationCertificates) +
	                               1 + // stake pool retirement certificate
	                               1;  // stake pool registration certificate

	txHashBuilder_init(&builder,
	                   ARRAY_LEN(inputs), ARRAY_LEN(outputs) + 2, // +2 for multiasset outputs
	                   true, // ttl
	                   numCertificates, ARRAY_LEN(withdrawals),
	                   true, // metadata
	                   true, // validity interval start
	                   true, // mint
	                   false, // script hash data
	                   0,	// collaterals not tested yet
	                   0,	// required signers not tested yet
	                   false // network id
	                  );

	txHashBuilder_enterInputs(&builder);
	ITERATE(it, inputs) {
		uint8_t tmp[TX_HASH_LENGTH] = {0};
		size_t tmpSize = decode_hex(PTR_PIC(it->txHashHex), tmp, SIZEOF(tmp));
		tx_input_t input;
		memmove(input.txHashBuffer, tmp, tmpSize);
		input.index = it->index;
		txHashBuilder_addInput(&builder, &input);
	}

	addOutputs(&builder);

	txHashBuilder_addFee(&builder, 42);

	txHashBuilder_addTtl(&builder, 235000);

	addCertificates(&builder);

	txHashBuilder_enterWithdrawals(&builder);

	ITERATE(it, withdrawals) {
		uint8_t tmp[70] = {0};
		size_t tmpSize = decode_hex(PTR_PIC(it->rewardAddress), tmp, SIZEOF(tmp));
		txHashBuilder_addWithdrawal(
		        &builder,
		        tmp, tmpSize,
		        it->amount
		);
	}

	{
		const char auxDataHashHex[] = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
		uint8_t tmp[AUX_DATA_HASH_LENGTH] = {0};
		size_t tmpSize = decode_hex(auxDataHashHex, tmp, SIZEOF(tmp));
		ASSERT(tmpSize == AUX_DATA_HASH_LENGTH);
		txHashBuilder_addAuxData(&builder, tmp, tmpSize);
	}

	txHashBuilder_addValidityIntervalStart(&builder, 33);

	addMint(&builder);

	uint8_t result[TX_HASH_LENGTH] = {0};
	txHashBuilder_finalize(&builder, result, SIZEOF(result));

	uint8_t expected[TX_HASH_LENGTH] = {0};
	decode_hex(expectedHex, expected, SIZEOF(expected));

	PRINTF("result\n");
	PRINTF("%.*h\n", 32, result);

	EXPECT_EQ_BYTES(result, expected, 32);
}

#endif // DEVEL
