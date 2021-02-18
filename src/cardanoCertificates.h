#ifndef H_CARDANO_APP_CARDANO_CERTIFICATES
#define H_CARDANO_APP_CARDANO_CERTIFICATES

#include "cardano.h"

// see the calculation in ui_displayMarginScreen() in uiScreens.c
#define MARGIN_DENOMINATOR_MAX 1000000000000000ul // 10^15

#define POOL_METADATA_URL_LENGTH_MAX 64
#define DNS_NAME_SIZE_MAX 64

#define IPV4_SIZE 4
#define IPV6_SIZE 16

// there may be other types we do not support
typedef enum {
	CERTIFICATE_TYPE_STAKE_REGISTRATION = 0,
	CERTIFICATE_TYPE_STAKE_DEREGISTRATION = 1,
	CERTIFICATE_TYPE_STAKE_DELEGATION = 2,
	CERTIFICATE_TYPE_STAKE_POOL_REGISTRATION = 3,

	#ifdef POOL_OPERATOR_APP
	CERTIFICATE_TYPE_STAKE_POOL_RETIREMENT = 4,
	#endif // POOL_OPERATOR_APP
} certificate_type_t;

typedef enum {
	RELAY_SINGLE_HOST_IP = 0,
	RELAY_SINGLE_HOST_NAME = 1,
	RELAY_MULTIPLE_HOST_NAME = 2
} relay_format_t;

typedef struct {
	bool isNull;
	uint8_t ip[IPV4_SIZE];
} ipv4_t;

typedef struct {
	uint8_t ip[IPV6_SIZE];
} ipv6_t;

typedef struct {
	bool isNull;
	uint16_t number;
} ipport_t;

// see the calculation in ui_displayPoolMarginScreen() in uiScreens.c
#define MARGIN_DENOMINATOR_MAX 1000000000000000ul // 10^15

typedef struct {
	relay_format_t format;

	ipport_t port;

	ipv4_t ipv4;

	bool hasIpv6;
	ipv6_t ipv6;

	size_t dnsNameSize;
	uint8_t dnsName[DNS_NAME_SIZE_MAX];
} pool_relay_t;


#endif // H_CARDANO_APP_CARDANO_CERTIFICATES
