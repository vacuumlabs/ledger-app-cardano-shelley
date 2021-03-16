#ifdef DEVEL

#include "txHashBuilder.h"
#include "cardano.h"
#include "cardanoCertificates.h"
#include "hexUtils.h"
#include "textUtils.h"
#include "test_utils.h"


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

static const char* expectedHex = "58dc0efc7a2d654795ae3b7c85518065bb123f17056406732c18d1553cc2510f";


static void addMultiassetOutput(tx_hash_builder_t* builder)
{
	uint8_t tmp[70];
	size_t tmpSize = decode_hex(PTR_PIC(outputs[1].rawAddressHex), tmp, SIZEOF(tmp));
	txHashBuilder_addOutput_topLevelData(
	        builder,
	        tmp, tmpSize,
	        outputs[1].amount,
	        2
	);

	// we reuse the buffers to avoid wasting stack
	uint8_t policy[MINTING_POLICY_ID_SIZE];
	explicit_bzero(policy, SIZEOF(policy));

	uint8_t assetNameBuffer[ASSET_NAME_SIZE_MAX];
	explicit_bzero(assetNameBuffer, SIZEOF(assetNameBuffer));

	policy[0] = 1;
	txHashBuilder_addOutput_tokenGroup(builder, policy, SIZEOF(policy), 2);

	assetNameBuffer[0] = 11;
	txHashBuilder_addOutput_token(builder, assetNameBuffer, SIZEOF(assetNameBuffer), 110);
	assetNameBuffer[0] = 12;
	txHashBuilder_addOutput_token(builder, assetNameBuffer, SIZEOF(assetNameBuffer), 120);

	policy[0] = 2;
	txHashBuilder_addOutput_tokenGroup(builder, policy, SIZEOF(policy), 2);

	assetNameBuffer[0] = 21;
	txHashBuilder_addOutput_token(builder, assetNameBuffer, SIZEOF(assetNameBuffer), 210);
	assetNameBuffer[0] = 22;
	// use a short buffer on purpose
	txHashBuilder_addOutput_token(builder, assetNameBuffer, 1, 220);
}

static void addOutputs(tx_hash_builder_t* builder)
{
	txHashBuilder_enterOutputs(builder);

	addMultiassetOutput(builder);

	ITERATE(it, outputs) {
		uint8_t tmp[70];
		size_t tmpSize = decode_hex(PTR_PIC(it->rawAddressHex), tmp, SIZEOF(tmp));
		txHashBuilder_addOutput_topLevelData(
		        builder,
		        tmp, tmpSize,
		        it->amount,
		        0
		);
	}

	// added for the second time to more thoroughly check the state machine
	addMultiassetOutput(builder);
}

static void addPoolRegistrationCertificate(tx_hash_builder_t* builder)
{
	pool_registration_params_t poolParams = {};

	size_t poolKeyHashSize = decode_hex(
	                                 "5631EDE662CFB10FD5FD69B4667101DD289568E12BCF5F64D1C406FC",
	                                 poolParams.poolKeyHash, SIZEOF(poolParams.poolKeyHash)
	                         );
	ASSERT(poolKeyHashSize == SIZEOF(poolParams.poolKeyHash));

	size_t vrfKeyHashSize = decode_hex(
	                                "198890AD6C92E80FBDAB554DDA02DA9FB49D001BBD96181F3E07F7A6AB0D0640",
	                                poolParams.vrfKeyHash, SIZEOF(poolParams.vrfKeyHash)
	                        );
	ASSERT(vrfKeyHashSize == SIZEOF(poolParams.vrfKeyHash));

	size_t rewardAccountSize = decode_hex(
	                                   "E03A7F09D3DF4CF66A7399C2B05BFA234D5A29560C311FC5DB4C490711",
	                                   poolParams.rewardAccount, SIZEOF(poolParams.rewardAccount)
	                           );
	ASSERT(rewardAccountSize == SIZEOF(poolParams.rewardAccount));

	poolParams.pledge = 500000000;
	poolParams.cost = 340000000;
	poolParams.marginNumerator = 1;
	poolParams.marginDenominator = 1;

	txHashBuilder_addPoolRegistrationCertificate(
	        builder,
	        &poolParams,
	        1, 3
	);

	txHashBuilder_addPoolRegistrationCertificate_enterOwners(builder);

	uint8_t owner1[28];
	size_t owner1Size = decode_hex("3A7F09D3DF4CF66A7399C2B05BFA234D5A29560C311FC5DB4C490711", owner1, SIZEOF(owner1));
	ASSERT(owner1Size == SIZEOF(owner1));

	txHashBuilder_addPoolRegistrationCertificate_addOwner(builder, owner1, owner1Size);

	txHashBuilder_addPoolRegistrationCertificate_enterRelays(builder);

	ipv4_t ipv4;
	decode_hex("08080808", ipv4.ip, IPV4_SIZE);

	uint16_t port = 1234;

	txHashBuilder_addPoolRegistrationCertificate_addRelay0(builder, &port, &ipv4, NULL);

	// a valid DNS AAAA record, since dnsName actually is suppposed to be an A or AAAA record
	const char* dnsName = "AAAA 2400:cb00:2049:1::a29f:1804";
	uint8_t dnsNameBuffer[DNS_NAME_MAX_LENGTH];
	size_t dnsNameBufferSize = str_textToBuffer(dnsName, dnsNameBuffer, SIZEOF(dnsNameBuffer));
	ASSERT(dnsNameBufferSize <= DNS_NAME_MAX_LENGTH);

	txHashBuilder_addPoolRegistrationCertificate_addRelay1(builder, NULL, dnsNameBuffer, dnsNameBufferSize);

	// dnsName is not a valid DNS SRV record, but we don't validate it
	txHashBuilder_addPoolRegistrationCertificate_addRelay2(builder, dnsNameBuffer, dnsNameBufferSize);

	uint8_t metadataHash[32];
	size_t metadataHashSize = decode_hex("914C57C1F12BBF4A82B12D977D4F274674856A11ED4B9B95BD70F5D41C5064A6", metadataHash, SIZEOF(metadataHash));
	ASSERT(metadataHashSize == SIZEOF(metadataHash));

	const char* metadataUrl = "https://teststakepool.com";
	uint8_t urlBuffer[DNS_NAME_MAX_LENGTH];
	size_t urlSize = str_textToBuffer(metadataUrl, urlBuffer, SIZEOF(urlBuffer));
	ASSERT(urlSize <= DNS_NAME_MAX_LENGTH);

	txHashBuilder_addPoolRegistrationCertificate_addPoolMetadata(builder, urlBuffer, urlSize, metadataHash, metadataHashSize);
}

static void addCertificates(tx_hash_builder_t* builder)
{
	txHashBuilder_enterCertificates(builder);

	ITERATE(it, registrationCertificates) {
		uint8_t tmp[70];
		size_t tmpSize = decode_hex(PTR_PIC(it->stakingKeyHash), tmp, SIZEOF(tmp));
		txHashBuilder_addCertificate_stakingKey(
		        builder,
		        CERTIFICATE_TYPE_STAKE_REGISTRATION,
		        tmp, tmpSize
		);
	}

	ITERATE(it, deregistrationCertificates) {
		uint8_t tmp[70];
		size_t tmpSize = decode_hex(PTR_PIC(it->stakingKeyHash), tmp, SIZEOF(tmp));
		txHashBuilder_addCertificate_stakingKey(
		        builder,
		        CERTIFICATE_TYPE_STAKE_DEREGISTRATION,
		        tmp, tmpSize
		);
	}

	addPoolRegistrationCertificate(builder);

	ITERATE(it, delegationCertificates) {
		uint8_t tmp_credential[70];
		size_t tmpSize_credential = decode_hex(
		                                    PTR_PIC(it->stakingKeyHash),
		                                    tmp_credential, SIZEOF(tmp_credential)
		                            );
		uint8_t tmp_pool[70];
		size_t tmpSize_pool = decode_hex(PTR_PIC(it->poolKeyHash), tmp_pool, SIZEOF(tmp_pool));
		txHashBuilder_addCertificate_delegation(
		        builder,
		        tmp_credential, tmpSize_credential,
		        tmp_pool, tmpSize_pool
		);
	}
}

void run_txHashBuilder_test()
{
	PRINTF("txHashBuilder test\n");
	tx_hash_builder_t builder;

	const size_t numCertificates = ARRAY_LEN(registrationCertificates) +
	                               ARRAY_LEN(deregistrationCertificates) +
	                               ARRAY_LEN(delegationCertificates) +
	                               1; // stake pool registration certificate

	txHashBuilder_init(&builder,
	                   ARRAY_LEN(inputs), ARRAY_LEN(outputs) + 2, // +2 for multiasset outputs
	                   true, // ttl
	                   numCertificates, ARRAY_LEN(withdrawals),
	                   true, // metadata
	                   true // validity interval start
	                  );

	txHashBuilder_enterInputs(&builder);
	ITERATE(it, inputs) {
		uint8_t tmp[TX_HASH_LENGTH];
		size_t tmpSize = decode_hex(PTR_PIC(it->txHashHex), tmp, SIZEOF(tmp));
		txHashBuilder_addInput(
		        &builder,
		        tmp, tmpSize,
		        it->index
		);
	}

	addOutputs(&builder);

	txHashBuilder_addFee(&builder, 42);

	txHashBuilder_addTtl(&builder, 235000);

	addCertificates(&builder);

	txHashBuilder_enterWithdrawals(&builder);

	ITERATE(it, withdrawals) {
		uint8_t tmp[70];
		size_t tmpSize = decode_hex(PTR_PIC(it->rewardAddress), tmp, SIZEOF(tmp));
		txHashBuilder_addWithdrawal(
		        &builder,
		        tmp, tmpSize,
		        it->amount
		);
	}

	{
		const char auxDataHashHex[] = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
		uint8_t tmp[AUX_DATA_HASH_LENGTH];
		size_t tmpSize = decode_hex(auxDataHashHex, tmp, SIZEOF(tmp));
		ASSERT(tmpSize == AUX_DATA_HASH_LENGTH);
		txHashBuilder_addAuxData(&builder, tmp, tmpSize);
	}

	txHashBuilder_addValidityIntervalStart(&builder, 33);

	uint8_t result[TX_HASH_LENGTH];
	txHashBuilder_finalize(&builder, result, SIZEOF(result));

	uint8_t expected[TX_HASH_LENGTH];
	decode_hex(expectedHex, expected, SIZEOF(expected));

	PRINTF("result\n");
	PRINTF("%.*h\n", 32, result);

	EXPECT_EQ_BYTES(result, expected, 32);
}

#endif // DEVEL
