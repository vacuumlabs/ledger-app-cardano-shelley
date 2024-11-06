#ifndef H_CARDANO_APP_SIGN_TX
#define H_CARDANO_APP_SIGN_TX

#include "cardano.h"
#include "common.h"
#include "hash.h"
#include "handlers.h"
#include "txHashBuilder.h"
#include "bip44.h"
#include "addressUtilsShelley.h"
#include "signTxMint.h"
#include "signTxOutput.h"
#include "signTxPoolRegistration.h"
#include "signTxCVoteRegistration.h"
#include "signTxAuxData.h"

// the signing mode significantly affects restrictions on tx being signed
typedef enum {
    SIGN_TX_SIGNINGMODE_ORDINARY_TX = 3,  // enum value 3 is needed for backwards compatibility
    SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER = 4,
    SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR = 5,
    SIGN_TX_SIGNINGMODE_MULTISIG_TX = 6,
    SIGN_TX_SIGNINGMODE_PLUTUS_TX = 7,
} sign_tx_signingmode_t;

typedef enum {
    SIGN_STAGE_NONE = 0,
    SIGN_STAGE_INIT = 23,
    SIGN_STAGE_AUX_DATA = 24,
    SIGN_STAGE_AUX_DATA_CVOTE_REGISTRATION_SUBMACHINE = 25,
    SIGN_STAGE_BODY_INPUTS = 26,
    SIGN_STAGE_BODY_OUTPUTS = 27,
    SIGN_STAGE_BODY_OUTPUTS_SUBMACHINE = 28,
    SIGN_STAGE_BODY_FEE = 29,
    SIGN_STAGE_BODY_TTL = 30,
    SIGN_STAGE_BODY_CERTIFICATES = 31,
#ifdef APP_FEATURE_POOL_REGISTRATION
    SIGN_STAGE_BODY_CERTIFICATES_POOL_SUBMACHINE = 32,  // pool registration certificate sub-machine
#endif                                                  // APP_FEATURE_POOL_REGISTRATION
    SIGN_STAGE_BODY_WITHDRAWALS = 33,
    SIGN_STAGE_BODY_VALIDITY_INTERVAL = 34,
    SIGN_STAGE_BODY_MINT = 35,
    SIGN_STAGE_BODY_MINT_SUBMACHINE = 36,
    SIGN_STAGE_BODY_SCRIPT_DATA_HASH = 37,
    SIGN_STAGE_BODY_COLLATERAL_INPUTS = 38,
    SIGN_STAGE_BODY_REQUIRED_SIGNERS = 39,
    SIGN_STAGE_BODY_COLLATERAL_OUTPUT = 40,
    SIGN_STAGE_BODY_COLLATERAL_OUTPUT_SUBMACHINE = 41,
    SIGN_STAGE_BODY_TOTAL_COLLATERAL = 42,
    SIGN_STAGE_BODY_REFERENCE_INPUTS = 43,
    SIGN_STAGE_BODY_VOTING_PROCEDURES = 44,
    SIGN_STAGE_BODY_TREASURY = 45,
    SIGN_STAGE_BODY_DONATION = 46,
    SIGN_STAGE_CONFIRM = 47,
    SIGN_STAGE_WITNESSES = 48,
} sign_tx_stage_t;

enum {
    SIGN_MAX_INPUTS = UINT16_MAX,
    SIGN_MAX_OUTPUTS = UINT16_MAX,
    SIGN_MAX_CERTIFICATES = UINT16_MAX,
    SIGN_MAX_REWARD_WITHDRAWALS = UINT16_MAX,
    SIGN_MAX_COLLATERAL_INPUTS = UINT16_MAX,
    SIGN_MAX_REQUIRED_SIGNERS = UINT16_MAX,
    SIGN_MAX_REFERENCE_INPUTS = UINT16_MAX,
    SIGN_MAX_VOTING_PROCEDURES = 1,  // we only support a single vote per tx
};

#define UI_INPUT_LABEL_SIZE 20

typedef struct {
    bool isStored;
    bool isByron;
    uint32_t accountNumber;
} single_account_data_t;

enum {
    TX_OPTIONS_TAG_CBOR_SETS = 1,
};

typedef struct {
    // significantly affects restrictions on the tx
    sign_tx_signingmode_t txSigningMode;

    uint8_t networkId;       // part of Shelley address
    uint32_t protocolMagic;  // part of Byron address

    single_account_data_t singleAccountData;

    // there is only one flag and no more flags planned for the future
    // but if there were many, it might be necessary to keep them
    // packed in a single uint variable
    bool tagCborSets;
} common_tx_data_t;

// credentials are extended to allow key derivation paths
typedef enum {
    // enum values are affected by backwards-compatibility
    EXT_CREDENTIAL_KEY_PATH = 0,
    EXT_CREDENTIAL_KEY_HASH = 2,
    EXT_CREDENTIAL_SCRIPT_HASH = 1,
} ext_credential_type_t;

typedef struct {
    ext_credential_type_t type;
    union {
        bip44_path_t keyPath;
        uint8_t keyHash[ADDRESS_KEY_HASH_LENGTH];
        uint8_t scriptHash[SCRIPT_HASH_LENGTH];
    };
} ext_credential_t;

// DReps are extended to allow key derivation paths
typedef enum {
    EXT_DREP_KEY_HASH = 0,
    EXT_DREP_KEY_PATH = 0 + 100,
    EXT_DREP_SCRIPT_HASH = 1,
    EXT_DREP_ABSTAIN = 2,
    EXT_DREP_NO_CONFIDENCE = 3,
} ext_drep_type_t;

typedef struct {
    ext_drep_type_t type;
    union {
        bip44_path_t keyPath;
        uint8_t keyHash[ADDRESS_KEY_HASH_LENGTH];
        uint8_t scriptHash[SCRIPT_HASH_LENGTH];
    };
} ext_drep_t;

typedef struct {
    certificate_type_t type;

    union {
        ext_credential_t stakeCredential;
        ext_credential_t committeeColdCredential;
        ext_credential_t dRepCredential;
    };
    union {
        ext_credential_t poolCredential;
        ext_credential_t committeeHotCredential;
        ext_drep_t drep;
        anchor_t anchor;
    };
    union {
        uint64_t epoch;    // in pool retirement
        uint64_t deposit;  // not in pool retirement
    };
} sign_tx_certificate_data_t;

typedef struct {
    tx_input_t input_data;
    char label[UI_INPUT_LABEL_SIZE];
} sign_tx_transaction_input_t;

typedef struct {
    bip44_path_t path;
    uint8_t signature[ED25519_SIGNATURE_LENGTH];
} sign_tx_witness_data_t;

typedef struct {
    ext_credential_t stakeCredential;
    uint64_t amount;
    uint8_t previousRewardAccount[REWARD_ACCOUNT_SIZE];
} sign_tx_withdrawal_data_t;

typedef struct {
    bool auxDataReceived;
    aux_data_type_t auxDataType;
    aux_data_hash_builder_t auxDataHashBuilder;

    struct {
        cvote_registration_context_t cvote_registration_subctx;
    } stageContext;
} ins_sign_tx_aux_data_context_t;

typedef enum {
    REQUIRED_SIGNER_WITH_PATH = 0,
    REQUIRED_SIGNER_WITH_HASH = 1
} sign_tx_required_signer_mode_t;

typedef struct {
    sign_tx_required_signer_mode_t type;
    union {
        uint8_t keyHash[ADDRESS_KEY_HASH_LENGTH];
        bip44_path_t keyPath;
    };
} sign_tx_required_signer_t;

// voters are extended to allow key derivation paths
typedef enum {
    EXT_VOTER_COMMITTEE_HOT_KEY_HASH = 0,
    EXT_VOTER_COMMITTEE_HOT_KEY_PATH = 0 + 100,
    EXT_VOTER_COMMITTEE_HOT_SCRIPT_HASH = 1,
    EXT_VOTER_DREP_KEY_HASH = 2,
    EXT_VOTER_DREP_KEY_PATH = 2 + 100,
    EXT_VOTER_DREP_SCRIPT_HASH = 3,
    EXT_VOTER_STAKE_POOL_KEY_HASH = 4,
    EXT_VOTER_STAKE_POOL_KEY_PATH = 4 + 100,
} ext_voter_type_t;

typedef struct {
    ext_voter_type_t type;
    union {
        bip44_path_t keyPath;
        uint8_t keyHash[ADDRESS_KEY_HASH_LENGTH];
        uint8_t scriptHash[SCRIPT_HASH_LENGTH];
    };
} ext_voter_t;

typedef struct {
    ext_voter_t voter;
    gov_action_id_t govActionId;
    voting_procedure_t votingProcedure;
} sign_tx_voting_procedure_t;

typedef struct {
    tx_hash_builder_t txHashBuilder;

    uint16_t currentInput;
    uint16_t currentOutput;
    uint16_t currentCertificate;
    uint16_t currentWithdrawal;
    uint16_t currentCollateral;
    uint16_t currentRequiredSigner;
    uint16_t currentReferenceInput;
    uint16_t currentVotingProcedure;

    bool feeReceived;
    bool ttlReceived;
    bool validityIntervalStartReceived;
    bool mintReceived;
    bool scriptDataHashReceived;
    bool collateralOutputReceived;
    bool totalCollateralReceived;
    bool treasuryReceived;
    bool donationReceived;

    union {
        sign_tx_transaction_input_t input;
        uint64_t fee;
        uint64_t ttl;
        sign_tx_certificate_data_t certificate;
        sign_tx_withdrawal_data_t withdrawal;
        uint64_t validityIntervalStart;
        uint8_t scriptDataHash[SCRIPT_DATA_HASH_LENGTH];
        sign_tx_required_signer_t requiredSigner;
        uint64_t totalCollateral;
        sign_tx_voting_procedure_t votingProcedure;
        uint64_t treasury;
        uint64_t donation;
    } stageData;

    union {
#ifdef APP_FEATURE_POOL_REGISTRATION
        pool_registration_context_t pool_registration_subctx;
#endif  // APP_FEATURE_POOL_REGISTRATION
        output_context_t output_subctx;
        mint_context_t mint_subctx;
    } stageContext;
} ins_sign_tx_body_context_t;

typedef struct {
    uint16_t currentWitness;
    struct {
        sign_tx_witness_data_t witness;
    } stageData;
} ins_sign_tx_witness_context_t;

typedef struct {
    sign_tx_stage_t stage;

    common_tx_data_t commonTxData;

    bool includeAuxData;
    uint16_t numInputs;
    uint16_t numOutputs;
    bool includeTtl;
    uint16_t numCertificates;
    uint16_t numWithdrawals;  // reward withdrawals
    bool includeValidityIntervalStart;
    bool includeMint;
    bool includeScriptDataHash;
    uint16_t numCollateralInputs;
    uint16_t numRequiredSigners;
    bool includeNetworkId;
    bool includeCollateralOutput;
    bool includeTotalCollateral;
    uint64_t totalCollateral;
    uint16_t numReferenceInputs;
    uint16_t numVotingProcedures;
    bool includeTreasury;
    bool includeDonation;

    uint16_t numWitnesses;

    uint8_t auxDataHash[AUX_DATA_HASH_LENGTH];
    uint8_t txHash[TX_HASH_LENGTH];

    union {
        ins_sign_tx_aux_data_context_t aux_data_ctx;
        ins_sign_tx_body_context_t body_ctx;
        ins_sign_tx_witness_context_t witnesses_ctx;
    } txPartCtx;

    bool poolOwnerByPath;
    bip44_path_t poolOwnerPath;

    bool shouldDisplayTxid;  // long bytestrings (e.g. datums in outputs) are better verified
                             // indirectly

    int ui_step;
    void (*ui_advanceState)();
} ins_sign_tx_context_t;

ins_sign_tx_aux_data_context_t* accessAuxDataContext();
ins_sign_tx_body_context_t* accessBodyContext();
ins_sign_tx_witness_context_t* accessWitnessContext();

#define AUX_DATA_CTX (accessAuxDataContext())
#define BODY_CTX     (accessBodyContext())
#define WITNESS_CTX  (accessWitnessContext())

uint16_t signTx_handleAPDU(uint8_t p1,
                           uint8_t p2,
                           const uint8_t* wireDataBuffer,
                           size_t wireDataSize,
                           bool isNewCall);

static inline bool signTx_parseIncluded(uint8_t value) {
    switch (value) {
        case ITEM_INCLUDED_YES:
            return true;

        case ITEM_INCLUDED_NO:
            return false;

        default:
            THROW(ERR_INVALID_DATA);
    }
}

// advances the stage of the main state machine
void tx_advanceStage(void);

void tx_advanceCertificatesStateIfAppropriate();

#endif  // H_CARDANO_APP_SIGN_TX
