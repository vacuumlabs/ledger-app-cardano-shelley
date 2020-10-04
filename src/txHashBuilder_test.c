#ifdef DEVEL

#include "txHashBuilder.h"
#include "cardano.h"
#include "cardanoCertificates.h"
#include "hexUtils.h"
#include "textUtils.h"
#include "test_utils.h"

/* original data from trezor; we added one stake pool registration certificate

{
  "inputs": [
    {
        "path": "m/1852'/1815'/0'/0/0",
        "prev_hash": "0b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7",
        "prev_index": 0
    },
    {
        "path": "m/1852'/1815'/0'/0/0",
        "prev_hash": "1b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7",
        "prev_index": 1
    },
    {
        "path": "m/1852'/1815'/0'/0/0",
        "prev_hash": "2b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7",
        "prev_index": 2
    },
    {
        "path": "m/1852'/1815'/0'/0/0",
        "prev_hash": "3b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7",
        "prev_index": 3
    }
  ],
  "outputs": [
    {
        "addressType": 3,
        "path": "m/44'/1815'/0'/0/0",
        "amount": "100"
    },
    {
        "addressType": 0,
        "path": "m/1852'/1815'/0'/0/0",
        "stakingKeyPath": "m/1852'/1815'/0'/2/0",
        "amount": "200"
    },
    {
        "addressType": 1,
        "path": "m/1852'/1815'/0'/0/0",
        "pointer":{
          "block_index": 1000,
          "tx_index": 2000,
          "certificate_index": 3000
        },
        "amount": "300"
    },
    {
        "addressType": 2,
        "path": "m/1852'/1815'/0'/0/0",
        "amount": "400"
    },
    {
        "addressType": 2,
        "path": "m/1852'/1815'/0'/0/0",
        "amount": "500"
    }
  ],
  "certificates": [
    {
      "type": 0,
      "path": "m/1852'/1815'/0'/2/0"
    },
    {
      "type": 1,
      "path": "m/1852'/1815'/0'/2/0"
    },
    {
      "type": 1,
      "path": "m/1852'/1815'/1'/2/0"
    },
    {
      "type": 2,
      "path": "m/1852'/1815'/0'/2/0",
      "pool": "0d13015cdbcdbd0889ce276192a1601f2d4d20b8392d4ef4f9a754e2"
    },
    {
      "type": 2,
      "path": "m/1852'/1815'/0'/2/0",
      "pool": "1d13015cdbcdbd0889ce276192a1601f2d4d20b8392d4ef4f9a754e2"
    },
    {
      "type": 2,
      "path": "m/1852'/1815'/0'/2/0",
      "pool": "2d13015cdbcdbd0889ce276192a1601f2d4d20b8392d4ef4f9a754e2"
    }
  ],
  "withdrawals": [
    {
      "path": "m/1852'/1815'/0'/2/0",
      "amount": 111
    },
    {
      "path": "m/1852'/1815'/0'/2/0",
      "amount": 222
    },
    {
      "path": "m/1852'/1815'/0'/2/0",
      "amount": 333
    },
    {
      "path": "m/1852'/1815'/0'/2/0",
      "amount": 444
    },
    {
      "path": "m/1852'/1815'/0'/2/0",
      "amount": 555
    },
    {
      "path": "m/1852'/1815'/0'/2/0",
      "amount": 666
    }
  ],
  "fee": 42,
  "ttl": 235000
}

tx_body:
A700848258200B40265111D8BB3C3C608D95B3A0BF83461ACE32D79336579A1939B3AAD1C0B7008258201B40265111D8BB3C3C608D95B3A0BF83461ACE32D79336579A1939B3AAD1C0B7018258202B40265111D8BB3C3C608D95B3A0BF83461ACE32D79336579A1939B3AAD1C0B7028258203B40265111D8BB3C3C608D95B3A0BF83461ACE32D79336579A1939B3AAD1C0B703018582582B82D818582183581C6EE5BB111C8771CE03278E624056A12C9CFB353EB112E8ABF21FA4FEA0001A74EEE4081864825839009493315CD92EB5D8C4304E67B7E16AE36D61D34502694657811A2C8E32C728D3861E164CAB28CB8F006448139C8F1740FFB8E7AA9E5232DC18C8825823409493315CD92EB5D8C4304E67B7E16AE36D61D34502694657811A2C8E87688F50973819012C82581D609493315CD92EB5D8C4304E67B7E16AE36D61D34502694657811A2C8E19019082581D609493315CD92EB5D8C4304E67B7E16AE36D61D34502694657811A2C8E1901F402182A031A000395F8048782008200581C32C728D3861E164CAB28CB8F006448139C8F1740FFB8E7AA9E5232DC82018200581C32C728D3861E164CAB28CB8F006448139C8F1740FFB8E7AA9E5232DC82018200581C337B62CFFF6403A06A3ACBC34F8C46003C69FE79A3628CEFA9C472518A03581C5631EDE662CFB10FD5FD69B4667101DD289568E12BCF5F64D1C406FC5820198890AD6C92E80FBDAB554DDA02DA9FB49D001BBD96181F3E07F7A6AB0D06401A1DCD65001A1443FD00D81E820101581DE03A7F09D3DF4CF66A7399C2B05BFA234D5A29560C311FC5DB4C49071181581C3A7F09D3DF4CF66A7399C2B05BFA234D5A29560C311FC5DB4C4907118384001904D24408080808F68301F678204141414120323430303A636230303A323034393A313A3A613239663A31383034820278204141414120323430303A636230303A323034393A313A3A613239663A3138303482781968747470733A2F2F746573747374616B65706F6F6C2E636F6D5820914C57C1F12BBF4A82B12D977D4F274674856A11ED4B9B95BD70F5D41C5064A683028200581C32C728D3861E164CAB28CB8F006448139C8F1740FFB8E7AA9E5232DC581C0D13015CDBCDBD0889CE276192A1601F2D4D20B8392D4EF4F9A754E283028200581C32C728D3861E164CAB28CB8F006448139C8F1740FFB8E7AA9E5232DC581C1D13015CDBCDBD0889CE276192A1601F2D4D20B8392D4EF4F9A754E283028200581C32C728D3861E164CAB28CB8F006448139C8F1740FFB8E7AA9E5232DC581C2D13015CDBCDBD0889CE276192A1601F2D4D20B8392D4EF4F9A754E205A1581DE032C728D3861E164CAB28CB8F006448139C8F1740FFB8E7AA9E5232DC19029A075820DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF

tx_hash:
378B60224E51EB566F3BF5FF62EDB18BFCD89B5F3E3B848A7820B26536C4B5D3
*/



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

static const char* expectedHex = "378B60224E51EB566F3BF5FF62EDB18BFCD89B5F3E3B848A7820B26536C4B5D3";

void addPoolRegistrationCertificate(tx_hash_builder_t* builder)
{
	pool_registration_params_t poolParams = {};

	size_t poolKeyHashSize = decode_hex(
	                                 "5631EDE662CFB10FD5FD69B4667101DD289568E12BCF5F64D1C406FC",
	                                 poolParams.operatorHash, SIZEOF(poolParams.operatorHash)
	                         );
	ASSERT(poolKeyHashSize == SIZEOF(poolParams.operatorHash));

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

	uint8_t ipv4[4];
	size_t ipv4Size = decode_hex("08080808", ipv4, 4);
	ASSERT(ipv4Size == 4);
	uint16_t port = 1234;

	txHashBuilder_addPoolRegistrationCertificate_addRelay0(builder, &port, ipv4, ipv4Size, NULL, 0);

	const char* dnsName = "AAAA 2400:cb00:2049:1::a29f:1804";
	uint8_t dnsNameBuffer[64];
	size_t dnsNameBufferSize = dnsNameToBuffer(dnsName, dnsNameBuffer, SIZEOF(dnsNameBuffer));
	ASSERT(dnsNameBufferSize <= SIZEOF(dnsNameBuffer));

	txHashBuilder_addPoolRegistrationCertificate_addRelay1(builder, NULL, dnsNameBuffer, dnsNameBufferSize);

	// dnsName is not a valid DNS SRV record, but we don't validate it
	txHashBuilder_addPoolRegistrationCertificate_addRelay2(builder, dnsNameBuffer, dnsNameBufferSize);

	uint8_t metadataHash[32];
	size_t metadataHashSize = decode_hex("914C57C1F12BBF4A82B12D977D4F274674856A11ED4B9B95BD70F5D41C5064A6", metadataHash, SIZEOF(metadataHash));
	ASSERT(metadataHashSize == SIZEOF(metadataHash));

	const char* metadataUrl = "https://teststakepool.com";
	uint8_t urlBuffer[64];
	size_t urlSize = urlToBuffer(metadataUrl, urlBuffer, SIZEOF(urlBuffer));
	ASSERT(urlSize <= SIZEOF(urlBuffer));

	txHashBuilder_addPoolRegistrationCertificate_addPoolMetadata(builder, urlBuffer, urlSize, metadataHash, metadataHashSize);
}

void run_txHashBuilder_test()
{
	PRINTF("txHashBuilder test\n");
	tx_hash_builder_t builder;

	const size_t numCertificates = ARRAY_LEN(registrationCertificates) +
	                               ARRAY_LEN(deregistrationCertificates) +
	                               ARRAY_LEN(delegationCertificates) +
	                               1; // stake pool registration certificate

	txHashBuilder_init(&builder, ARRAY_LEN(inputs), ARRAY_LEN(outputs), numCertificates, ARRAY_LEN(withdrawals), true);

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

	txHashBuilder_enterOutputs(&builder);
	ITERATE(it, outputs) {
		uint8_t tmp[70];
		size_t tmpSize = decode_hex(PTR_PIC(it->rawAddressHex), tmp, SIZEOF(tmp));
		txHashBuilder_addOutput(
		        &builder,
		        tmp, tmpSize,
		        it->amount
		);
	}

	txHashBuilder_addFee(&builder, 42);

	txHashBuilder_addTtl(&builder, 235000);

	txHashBuilder_enterCertificates(&builder);

	ITERATE(it, registrationCertificates) {
		uint8_t tmp[70];
		size_t tmpSize = decode_hex(PTR_PIC(it->stakingKeyHash), tmp, SIZEOF(tmp));
		txHashBuilder_addCertificate_stakingKey(
		        &builder,
		        CERTIFICATE_TYPE_STAKE_REGISTRATION,
		        tmp, tmpSize
		);
	}

	ITERATE(it, deregistrationCertificates) {
		uint8_t tmp[70];
		size_t tmpSize = decode_hex(PTR_PIC(it->stakingKeyHash), tmp, SIZEOF(tmp));
		txHashBuilder_addCertificate_stakingKey(
		        &builder,
		        CERTIFICATE_TYPE_STAKE_DEREGISTRATION,
		        tmp, tmpSize
		);
	}

	addPoolRegistrationCertificate(&builder);

	ITERATE(it, delegationCertificates) {
		uint8_t tmp_credential[70];
		size_t tmpSize_credential = decode_hex(
		                                    PTR_PIC(it->stakingKeyHash),
		                                    tmp_credential, SIZEOF(tmp_credential)
		                            );
		uint8_t tmp_pool[70];
		size_t tmpSize_pool = decode_hex(PTR_PIC(it->poolKeyHash), tmp_pool, SIZEOF(tmp_pool));
		txHashBuilder_addCertificate_delegation(
		        &builder,
		        tmp_credential, tmpSize_credential,
		        tmp_pool, tmpSize_pool
		);
	}

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
		const char metadataHashHex[] = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
		uint8_t tmp[METADATA_HASH_LENGTH];
		size_t tmpSize = decode_hex(metadataHashHex, tmp, SIZEOF(tmp));
		ASSERT(tmpSize == METADATA_HASH_LENGTH);
		txHashBuilder_addMetadata(&builder, tmp, tmpSize);
	}

	uint8_t result[TX_HASH_LENGTH];
	txHashBuilder_finalize(&builder, result, SIZEOF(result));

	uint8_t expected[TX_HASH_LENGTH];
	decode_hex(expectedHex, expected, SIZEOF(expected));

	PRINTF("result\n");
	PRINTF("%.*H\n", 32, result);

	EXPECT_EQ_BYTES(result, expected, 32);
}

#endif
