#include "signTxOutput.h"
#include "state.h"
#include "uiHelpers.h"
#include "signTxUtils.h"
#include "uiScreens.h"
#include "txHashBuilder.h"
#include "textUtils.h"
#include "bufView.h"
#include "securityPolicy.h"
#include "tokens.h"

static common_tx_data_t* commonTxData = &(instructionState.signTxContext.commonTxData);
static ins_sign_tx_context_t* ctx = &(instructionState.signTxContext);

static output_context_t* accessSubcontext()
{
	return &BODY_CTX->stageContext.output_subctx;
}

bool isCurrentOutputFinished()
{
	output_context_t* subctx = accessSubcontext();
	TRACE("Output submachine state: %d", subctx->state);
	// we are also asserting that the state is valid
	switch (subctx->state) {
	case STATE_OUTPUT_FINISHED:
		return true;

	case STATE_OUTPUT_TOP_LEVEL_DATA:
	case STATE_OUTPUT_ASSET_GROUP:
	case STATE_OUTPUT_TOKEN:
	case STATE_OUTPUT_DATUM:
	case STATE_OUTPUT_DATUM_INLINE_CHUNKS:
	case STATE_OUTPUT_REFERENCE_SCRIPT:
	case STATE_OUTPUT_REFERENCE_SCRIPT_CHUNKS:
	case STATE_OUTPUT_CONFIRM:
		return false;

	default:
		ASSERT(false);
		return false;
	}
}

void initializeOutputSubmachine()
{
	explicit_bzero(&BODY_CTX->stageContext, SIZEOF(BODY_CTX->stageContext));

	accessSubcontext()->state = STATE_OUTPUT_TOP_LEVEL_DATA;
}

static inline void CHECK_STATE(sign_tx_output_state_t expected)
{
	output_context_t* subctx = accessSubcontext();
	TRACE("Output submachine state: current %d, expected %d", subctx->state, expected);
	VALIDATE(subctx->state == expected, ERR_INVALID_STATE);
}

static inline void advanceState()
{
	output_context_t* subctx = accessSubcontext();
	TRACE("Advancing output state from: %d", subctx->state);

	switch (subctx->state) {

	case STATE_OUTPUT_TOP_LEVEL_DATA:
		if (subctx->numAssetGroups > 0) {
			ASSERT(subctx->stateData.currentAssetGroup == 0);
			subctx->state = STATE_OUTPUT_ASSET_GROUP;
		} else if (subctx->includeDatum) {
			subctx->state = STATE_OUTPUT_DATUM;
		} else if (subctx->includeRefScript) {
			subctx->state = STATE_OUTPUT_REFERENCE_SCRIPT;
		} else {
			subctx->state = STATE_OUTPUT_CONFIRM;
		}
		break;

	case STATE_OUTPUT_ASSET_GROUP:
		ASSERT(subctx->stateData.currentAssetGroup < subctx->numAssetGroups);

		// we are going to receive token amounts for this group
		ASSERT(subctx->stateData.numTokens > 0);
		ASSERT(subctx->stateData.currentToken == 0);

		subctx->state = STATE_OUTPUT_TOKEN;
		break;

	case STATE_OUTPUT_TOKEN:
		// we are done with the current token group
		ASSERT(subctx->stateData.currentToken == subctx->stateData.numTokens);
		subctx->stateData.currentToken = 0;
		ASSERT(subctx->stateData.currentAssetGroup < subctx->numAssetGroups);
		subctx->stateData.currentAssetGroup++;

		if (subctx->stateData.currentAssetGroup == subctx->numAssetGroups) {
			// the whole token bundle has been received
			if (subctx->includeDatum) {
				subctx->state = STATE_OUTPUT_DATUM;
			} else if (subctx->includeRefScript) {
				subctx->state = STATE_OUTPUT_REFERENCE_SCRIPT;
			} else {
				subctx->state = STATE_OUTPUT_CONFIRM;
			}
		} else {
			subctx->state = STATE_OUTPUT_ASSET_GROUP;
		}
		break;

	case STATE_OUTPUT_DATUM:
		ASSERT(subctx->includeDatum);
		if (subctx->stateData.datumType == DATUM_HASH) {
			ASSERT(subctx->datumHashReceived);
			if (subctx->includeRefScript) {
				subctx->state = STATE_OUTPUT_REFERENCE_SCRIPT;
			} else {
				subctx->state = STATE_OUTPUT_CONFIRM;
			}
		} else {
			if (subctx->stateData.datumRemainingBytes > 0) {
				// there are more chunks to receive
				subctx->state = STATE_OUTPUT_DATUM_INLINE_CHUNKS;
			} else if (subctx->includeRefScript) {
				subctx->state = STATE_OUTPUT_REFERENCE_SCRIPT;
			} else {
				subctx->state = STATE_OUTPUT_CONFIRM;
			}
		}
		break;

	case STATE_OUTPUT_DATUM_INLINE_CHUNKS:
		ASSERT(subctx->includeDatum);
		// should be called when all chunks have been received
		ASSERT(subctx->stateData.datumRemainingBytes == 0);
		if (subctx->includeRefScript) {
			subctx->state = STATE_OUTPUT_REFERENCE_SCRIPT;
		} else {
			subctx->state = STATE_OUTPUT_CONFIRM;
		}
		break;

	case STATE_OUTPUT_REFERENCE_SCRIPT:
		ASSERT(subctx->includeRefScript);
		if (subctx->stateData.refScriptRemainingBytes > 0) {
			// there are more chunks to receive
			subctx->state = STATE_OUTPUT_REFERENCE_SCRIPT_CHUNKS;
		} else {
			// the first chunk was enough, no more are coming
			subctx->state = STATE_OUTPUT_CONFIRM;
		}
		break;

	case STATE_OUTPUT_REFERENCE_SCRIPT_CHUNKS:
		// should be called when all chunks have been received
		ASSERT(subctx->stateData.refScriptRemainingBytes == 0);
		subctx->state = STATE_OUTPUT_CONFIRM;
		break;

	case STATE_OUTPUT_CONFIRM:
		subctx->state = STATE_OUTPUT_FINISHED;
		break;

	default:
		ASSERT(false);
	}

	TRACE("Advancing output state to: %d", subctx->state);
}

// ============================== TOP LEVEL DATA ==============================

enum {
	HANDLE_OUTPUT_ADDRESS_BYTES_STEP_WARNING_DATUM = 3100,
	HANDLE_OUTPUT_ADDRESS_BYTES_STEP_DISPLAY_ADDRESS,
	HANDLE_OUTPUT_ADDRESS_BYTES_STEP_DISPLAY_ADA_AMOUNT,
	HANDLE_OUTPUT_ADDRESS_BYTES_STEP_RESPOND,
	HANDLE_OUTPUT_ADDRESS_BYTES_STEP_INVALID,
};

static void signTx_handleOutput_address_bytes_ui_runStep()
{
	output_context_t* subctx = accessSubcontext();
	TRACE("UI step %d", subctx->ui_step);
	ui_callback_fn_t* this_fn = signTx_handleOutput_address_bytes_ui_runStep;

	ASSERT(subctx->stateData.destination.type == DESTINATION_THIRD_PARTY);

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_OUTPUT_ADDRESS_BYTES_STEP_WARNING_DATUM) {
		// TODO why is this warning not shown for address params? can't address params address be script address, I guess?
		ui_displayPaginatedText(
		        "WARNING: output",
		        "could be unspendable due to missing datum",
		        this_fn
		);
	}
	UI_STEP(HANDLE_OUTPUT_ADDRESS_BYTES_STEP_DISPLAY_ADDRESS) {
		ASSERT(subctx->stateData.destination.address.size <= SIZEOF(subctx->stateData.destination.address.buffer));
		ui_displayAddressScreen(
		        "Send to address",
		        subctx->stateData.destination.address.buffer,
		        subctx->stateData.destination.address.size,
		        this_fn
		);
	}
	UI_STEP(HANDLE_OUTPUT_ADDRESS_BYTES_STEP_DISPLAY_ADA_AMOUNT) {
		ui_displayAdaAmountScreen("Send", subctx->stateData.adaAmount, this_fn);
	}
	UI_STEP(HANDLE_OUTPUT_ADDRESS_BYTES_STEP_RESPOND) {
		respondSuccessEmptyMsg();

		advanceState();
	}
	UI_STEP_END(HANDLE_OUTPUT_ADDRESS_BYTES_STEP_INVALID);
}

static void handleOutput_addressBytes()
{
	output_context_t* subctx = accessSubcontext();
	ASSERT(subctx->stateData.destination.type == DESTINATION_THIRD_PARTY);

	tx_output_description_t output = {
		.format = subctx->serializationFormat,
		.destination = {
			.type = DESTINATION_THIRD_PARTY,
			.address = {
				.buffer = subctx->stateData.destination.address.buffer,
				.size = subctx->stateData.destination.address.size
			}
		},
		.amount = subctx->stateData.adaAmount,
		.numAssetGroups = subctx->numAssetGroups,
		.includeDatum = subctx->includeDatum,
		.includeRefScript = subctx->includeRefScript,
	};

	security_policy_t policy = policyForSignTxOutputAddressBytes(
									   &output,
	                                   commonTxData->txSigningMode,
	                                   commonTxData->networkId, commonTxData->protocolMagic
	                           );
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);
	subctx->outputSecurityPolicy = policy;
	{
		// add to tx
		txHashBuilder_addOutput_topLevelData(&BODY_CTX->txHashBuilder, &output);
	}
	{
		// select UI steps
		switch (policy) {
#define  CASE(POLICY, UI_STEP) case POLICY: {subctx->ui_step=UI_STEP; break;}
			CASE(POLICY_PROMPT_WARN_UNUSUAL,  HANDLE_OUTPUT_ADDRESS_BYTES_STEP_WARNING_DATUM);
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_OUTPUT_ADDRESS_BYTES_STEP_DISPLAY_ADDRESS);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_OUTPUT_ADDRESS_BYTES_STEP_RESPOND);
#undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}

		signTx_handleOutput_address_bytes_ui_runStep();
	}
}


enum {
	HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_DISPLAY_BEGIN = 3200,
	HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_DISPLAY_SPENDING_PATH,
	HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_DISPLAY_STAKING_INFO,
	HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_DISPLAY_ADDRESS,
	HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_DISPLAY_AMOUNT,
	HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_RESPOND,
	HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_INVALID,
};

__noinline_due_to_stack__
static void signTx_handleOutput_addressParams_ui_runStep()
{
	output_context_t* subctx = accessSubcontext();
	TRACE("UI step %d", subctx->ui_step);
	ui_callback_fn_t* this_fn = signTx_handleOutput_addressParams_ui_runStep;

	ASSERT(subctx->stateData.destination.type == DESTINATION_DEVICE_OWNED);

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_DISPLAY_BEGIN) {
		ui_displayPaginatedText(subctx->ui_text1, subctx->ui_text2, this_fn);
	}
	UI_STEP(HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_DISPLAY_SPENDING_PATH) {
		if (determineSpendingChoice(subctx->stateData.destination.params.type) == SPENDING_NONE) {
			// reward address
			// TODO reward address is not allowed in outputs, why is this here?
			UI_STEP_JUMP(HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_DISPLAY_STAKING_INFO);
		}
		ui_displaySpendingInfoScreen(&subctx->stateData.destination.params, this_fn);
	}
	UI_STEP(HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_DISPLAY_STAKING_INFO) {
		ui_displayStakingInfoScreen(&subctx->stateData.destination.params, this_fn);
	}
	UI_STEP(HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_DISPLAY_ADDRESS) {
		uint8_t addressBuffer[MAX_ADDRESS_SIZE] = {0};
		size_t addressSize = deriveAddress(&subctx->stateData.destination.params, addressBuffer, SIZEOF(addressBuffer));
		ASSERT(addressSize > 0);
		ASSERT(addressSize <= MAX_ADDRESS_SIZE);

		ui_displayAddressScreen(
		    	subctx->ui_text3,
		        addressBuffer, addressSize,
		        this_fn
		);
	}
	UI_STEP(HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_DISPLAY_AMOUNT) {
		ui_displayAdaAmountScreen(subctx->ui_text4, subctx->stateData.adaAmount, this_fn);
	}
	UI_STEP(HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_RESPOND) {
		respondSuccessEmptyMsg();

		advanceState();
	}
	UI_STEP_END(HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_INVALID);
}

static void handleOutput_addressParams()
{
	output_context_t* subctx = accessSubcontext();
	ASSERT(subctx->stateData.destination.type == DESTINATION_DEVICE_OWNED);

	tx_output_description_t output = {
		.format = subctx->serializationFormat,
		.destination = {
			.type = DESTINATION_DEVICE_OWNED,
			.params = &subctx->stateData.destination.params
		},
		.amount = subctx->stateData.adaAmount,
		.numAssetGroups = subctx->numAssetGroups,
		.includeDatum = subctx->includeDatum,
		.includeRefScript = subctx->includeRefScript,
	};

	security_policy_t policy = policyForSignTxOutputAddressParams(
	                                   &output,
	                                   commonTxData->txSigningMode,
	                                   commonTxData->networkId, commonTxData->protocolMagic
	                           );
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);
	subctx->outputSecurityPolicy = policy;

	{
		// add to tx
		uint8_t addressBuffer[MAX_ADDRESS_SIZE] = {0};
		size_t addressSize = deriveAddress(
		                             &subctx->stateData.destination.params,
		                             addressBuffer,
		                             SIZEOF(addressBuffer)
		                     );
		ASSERT(addressSize > 0);
		ASSERT(addressSize <= MAX_ADDRESS_SIZE);

		// pass the derived address to tx hash builder
		output.destination.type = DESTINATION_THIRD_PARTY;
		output.destination.address.buffer = addressBuffer;
		output.destination.address.size = addressSize;

		txHashBuilder_addOutput_topLevelData(&BODY_CTX->txHashBuilder, &output);
	}

	{
		// select UI steps
		switch (policy) {
#define  CASE(POLICY, UI_STEP) case POLICY: {subctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_DISPLAY_BEGIN);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_RESPOND);
#undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}

		subctx->ui_text1 = "Change";
		subctx->ui_text2 = "output";
		subctx->ui_text3 = "Address";
		subctx->ui_text4 = "Send";

		signTx_handleOutput_addressParams_ui_runStep();
	}
}

static void parseTopLevelData(const uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		// safety checks
		CHECK_STATE(STATE_OUTPUT_TOP_LEVEL_DATA);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}

	output_context_t* subctx = accessSubcontext();
	{
		// parse all APDU data
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

		subctx->serializationFormat = parse_u1be(&view);
		TRACE("Output serialization format %d", (int) subctx->serializationFormat);
		// TODO validation

		subctx->stateData.destination.type = parse_u1be(&view);
		TRACE("Output destination type %d", (int) subctx->stateData.destination.type);
		// TODO validation

		switch (subctx->stateData.destination.type) {
		case DESTINATION_THIRD_PARTY: {
			STATIC_ASSERT(sizeof(subctx->stateData.destination.address.size) >= 4, "wrong address size type");
			subctx->stateData.destination.address.size = parse_u4be(&view);
			TRACE("Address length %u", subctx->stateData.destination.address.size);
			VALIDATE(subctx->stateData.destination.address.size <= MAX_ADDRESS_SIZE, ERR_INVALID_DATA);

			STATIC_ASSERT(SIZEOF(subctx->stateData.destination.address.buffer) >= MAX_ADDRESS_SIZE, "wrong address buffer size");
			view_parseBuffer(subctx->stateData.destination.address.buffer, &view, subctx->stateData.destination.address.size);
			TRACE_BUFFER(subctx->stateData.destination.address.buffer, subctx->stateData.destination.address.size);
			break;
		}
		case DESTINATION_DEVICE_OWNED: {
			view_parseAddressParams(&view, &subctx->stateData.destination.params);
			break;
		}

		default:
			THROW(ERR_INVALID_DATA);
		};

		uint64_t adaAmount = parse_u8be(&view);
		subctx->stateData.adaAmount = adaAmount;
		TRACE("Amount: %u.%06u", (unsigned) (adaAmount / 1000000), (unsigned)(adaAmount % 1000000));
		VALIDATE(adaAmount < LOVELACE_MAX_SUPPLY, ERR_INVALID_DATA);

		uint32_t numAssetGroups = parse_u4be(&view);
		TRACE("num asset groups %u", numAssetGroups);
		VALIDATE(numAssetGroups <= OUTPUT_ASSET_GROUPS_MAX, ERR_INVALID_DATA);

		STATIC_ASSERT(OUTPUT_ASSET_GROUPS_MAX <= UINT16_MAX, "wrong max token groups");
		ASSERT_TYPE(subctx->numAssetGroups, uint16_t);
		subctx->numAssetGroups = (uint16_t) numAssetGroups;

		subctx->includeDatum = signTx_parseIncluded(parse_u1be(&view));
		subctx->includeRefScript = signTx_parseIncluded(parse_u1be(&view));

		if (subctx->includeDatum || subctx->includeRefScript) {
			// it's easier to verify all Plutus-related things via txid all at once
			ctx->shouldDisplayTxid = true;
		}

		VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);
	}
}

static void handleTopLevelDataAPDU_output(const uint8_t* wireDataBuffer, size_t wireDataSize)
{
	CHECK_STATE(STATE_OUTPUT_TOP_LEVEL_DATA);

	parseTopLevelData(wireDataBuffer, wireDataSize);

	output_context_t* subctx = accessSubcontext();

	// call the appropriate handler depending on output type
	// the handlers serialize data into the tx hash
	// and take care of user interactions
	switch (subctx->stateData.destination.type) {

	case DESTINATION_THIRD_PARTY:
		handleOutput_addressBytes();
		break;

	case DESTINATION_DEVICE_OWNED:
		handleOutput_addressParams();
		break;

	default:
		ASSERT(false);
	};
}

enum {
	HANDLE_COLL_RET_OUTPUT_ADDRESS_BYTES_STEP_DISPLAY_INTRO = 3100,
	HANDLE_COLL_RET_OUTPUT_ADDRESS_BYTES_STEP_DISPLAY_ADDRESS,
	HANDLE_COLL_RET_OUTPUT_ADDRESS_BYTES_STEP_DISPLAY_ADA_AMOUNT,
	HANDLE_COLL_RET_OUTPUT_ADDRESS_BYTES_STEP_RESPOND,
	HANDLE_COLL_RET_OUTPUT_ADDRESS_BYTES_STEP_INVALID,
};

static void signTx_handleCollRetOutput_addressBytes_ui_runStep()
{
	output_context_t* subctx = accessSubcontext();
	TRACE("UI step %d", subctx->ui_step);
	ui_callback_fn_t* this_fn = signTx_handleOutput_address_bytes_ui_runStep;

	ASSERT(subctx->stateData.destination.type == DESTINATION_THIRD_PARTY);

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_COLL_RET_OUTPUT_ADDRESS_BYTES_STEP_DISPLAY_INTRO) {
		ui_displayPaginatedText(
			"Collateral",
			"return output",
			this_fn
		);
	}
	UI_STEP(HANDLE_COLL_RET_OUTPUT_ADDRESS_BYTES_STEP_DISPLAY_ADDRESS) {
		ASSERT(subctx->stateData.destination.address.size <= SIZEOF(subctx->stateData.destination.address.buffer));
		ui_displayAddressScreen(
		        "Address",
		        subctx->stateData.destination.address.buffer,
		        subctx->stateData.destination.address.size,
		        this_fn
		);
	}
	UI_STEP(HANDLE_COLL_RET_OUTPUT_ADDRESS_BYTES_STEP_DISPLAY_ADA_AMOUNT) {
		ui_displayAdaAmountScreen("Amount", subctx->stateData.adaAmount, this_fn);
	}
	UI_STEP(HANDLE_COLL_RET_OUTPUT_ADDRESS_BYTES_STEP_RESPOND) {
		respondSuccessEmptyMsg();

		advanceState();
	}
	UI_STEP_END(HANDLE_COLL_RET_OUTPUT_ADDRESS_BYTES_STEP_INVALID);
}

static void handleCollRetOutput_addressBytes()
{
	output_context_t* subctx = accessSubcontext();
	ASSERT(subctx->stateData.destination.type == DESTINATION_THIRD_PARTY);

	tx_output_description_t output = {
		.format = subctx->serializationFormat,
		.destination = {
			.type = DESTINATION_THIRD_PARTY,
			.address = {
				.buffer = subctx->stateData.destination.address.buffer,
				.size = subctx->stateData.destination.address.size
			}
		},
		.amount = subctx->stateData.adaAmount,
		.numAssetGroups = subctx->numAssetGroups,
		.includeDatum = subctx->includeDatum,
		.includeRefScript = subctx->includeRefScript,
	};

	// TODO maybe restric to specific address types? we don't support datum in coll ret outputs
	security_policy_t policy = policyForSignTxCollRetOutputAddressBytes(
									   &output,
	                                   commonTxData->txSigningMode,
	                                   commonTxData->networkId, commonTxData->protocolMagic
	                           );
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);
	subctx->outputSecurityPolicy = policy;
	{
		// add to tx
		txHashBuilder_addCollateralReturn(&BODY_CTX->txHashBuilder, &output);
	}
	{
		// select UI steps
		switch (policy) {
#define  CASE(POLICY, UI_STEP) case POLICY: {subctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_COLL_RET_OUTPUT_ADDRESS_BYTES_STEP_DISPLAY_ADDRESS);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_COLL_RET_OUTPUT_ADDRESS_BYTES_STEP_RESPOND);
#undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}

		signTx_handleCollRetOutput_addressBytes_ui_runStep();
	}
}

// enum {
// 	HANDLE_COLL_RET_OUTPUT_ADDRESS_PARAMS_STEP_DISPLAY_BEGIN = 3200,
// 	HANDLE_COLL_RET_OUTPUT_ADDRESS_PARAMS_STEP_DISPLAY_SPENDING_PATH,
// 	HANDLE_COLL_RET_OUTPUT_ADDRESS_PARAMS_STEP_DISPLAY_STAKING_INFO,
// 	HANDLE_COLL_RET_OUTPUT_ADDRESS_PARAMS_STEP_DISPLAY_ADDRESS,
// 	HANDLE_COLL_RET_OUTPUT_ADDRESS_PARAMS_STEP_DISPLAY_AMOUNT,
// 	HANDLE_COLL_RET_OUTPUT_ADDRESS_PARAMS_STEP_RESPOND,
// 	HANDLE_COLL_RET_OUTPUT_ADDRESS_PARAMS_STEP_INVALID,
// };

// __noinline_due_to_stack__
// static void signTx_handleCollRetOutput_addressParams_ui_runStep()
// {
// 	output_context_t* subctx = accessSubcontext();
// 	TRACE("UI step %d", subctx->ui_step);
// 	ui_callback_fn_t* this_fn = signTx_handleCollRetOutput_addressParams_ui_runStep;

// 	ASSERT(subctx->stateData.destination.type == DESTINATION_DEVICE_OWNED);

// 	UI_STEP_BEGIN(subctx->ui_step, this_fn);

// 	UI_STEP(HANDLE_COLL_RET_OUTPUT_ADDRESS_PARAMS_STEP_DISPLAY_BEGIN) {
// 		ui_displayPaginatedText("Collateral", "return output", this_fn);
// 	}
// 	UI_STEP(HANDLE_COLL_RET_OUTPUT_ADDRESS_PARAMS_STEP_DISPLAY_SPENDING_PATH) {
// 		if (determineSpendingChoice(subctx->stateData.destination.params.type) == SPENDING_NONE) {
// 			// reward address
// 			// TODO reward address is not allowed in outputs, why is this here?
// 			UI_STEP_JUMP(HANDLE_COLL_RET_OUTPUT_ADDRESS_PARAMS_STEP_DISPLAY_STAKING_INFO);
// 		}
// 		ui_displaySpendingInfoScreen(&subctx->stateData.destination.params, this_fn);
// 	}
// 	UI_STEP(HANDLE_COLL_RET_OUTPUT_ADDRESS_PARAMS_STEP_DISPLAY_STAKING_INFO) {
// 		ui_displayStakingInfoScreen(&subctx->stateData.destination.params, this_fn);
// 	}
// 	UI_STEP(HANDLE_COLL_RET_OUTPUT_ADDRESS_PARAMS_STEP_DISPLAY_ADDRESS) {
// 		uint8_t addressBuffer[MAX_ADDRESS_SIZE] = {0};
// 		size_t addressSize = deriveAddress(&subctx->stateData.destination.params, addressBuffer, SIZEOF(addressBuffer));
// 		ASSERT(addressSize > 0);
// 		ASSERT(addressSize <= MAX_ADDRESS_SIZE);

// 		ui_displayAddressScreen(
// 		        "Address",
// 		        addressBuffer, addressSize,
// 		        this_fn
// 		);
// 	}
// 	UI_STEP(HANDLE_COLL_RET_OUTPUT_ADDRESS_PARAMS_STEP_DISPLAY_AMOUNT) {
// 		ui_displayAdaAmountScreen("Amount", subctx->stateData.adaAmount, this_fn);
// 	}
// 	UI_STEP(HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_RESPOND) {
// 		respondSuccessEmptyMsg();

// 		advanceState();
// 	}
// 	UI_STEP_END(HANDLE_COLL_RET_OUTPUT_ADDRESS_PARAMS_STEP_INVALID);
// }

static void handleCollRetOutput_addressParams()
{
	output_context_t* subctx = accessSubcontext();
	ASSERT(subctx->stateData.destination.type == DESTINATION_DEVICE_OWNED);

	tx_output_description_t output = {
		.format = subctx->serializationFormat,
		.destination = {
			.type = DESTINATION_DEVICE_OWNED,
			.params = &subctx->stateData.destination.params
		},
		.amount = subctx->stateData.adaAmount,
		.numAssetGroups = subctx->numAssetGroups,
		.includeDatum = subctx->includeDatum,
		.includeRefScript = subctx->includeRefScript,
	};

	security_policy_t policy = policyForSignTxCollRetOutputAddressParams(
	                                   &output,
	                                   commonTxData->txSigningMode,
	                                   commonTxData->networkId, commonTxData->protocolMagic
	                           );
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);
	subctx->outputSecurityPolicy = policy;

	{
		// add to tx
		uint8_t addressBuffer[MAX_ADDRESS_SIZE] = {0};
		size_t addressSize = deriveAddress(
		                             &subctx->stateData.destination.params,
		                             addressBuffer,
		                             SIZEOF(addressBuffer)
		                     );
		ASSERT(addressSize > 0);
		ASSERT(addressSize <= MAX_ADDRESS_SIZE);

		// pass the derived address to tx hash builder
		output.destination.type = DESTINATION_THIRD_PARTY;
		output.destination.address.buffer = addressBuffer;
		output.destination.address.size = addressSize;

		txHashBuilder_addOutput_topLevelData(&BODY_CTX->txHashBuilder, &output);
	}

	{
		// select UI steps
		switch (policy) {
#define  CASE(POLICY, UI_STEP) case POLICY: {subctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_DISPLAY_BEGIN);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_RESPOND);
#undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}

		subctx->ui_text1 = "Collateral";
		subctx->ui_text2 = "return output";
		subctx->ui_text3 = "Address";
		subctx->ui_text4 = "Amount";

		signTx_handleOutput_addressParams_ui_runStep();
	}
}

static void handleTopLevelDataAPDU_collRetOutput(const uint8_t* wireDataBuffer, size_t wireDataSize)
{
	CHECK_STATE(STATE_OUTPUT_TOP_LEVEL_DATA);

	parseTopLevelData(wireDataBuffer, wireDataSize);

	output_context_t* subctx = accessSubcontext();

	// call the appropriate handler depending on output type
	// the handlers serialize data into the tx hash
	// and take care of user interactions
	switch (subctx->stateData.destination.type) {

	case DESTINATION_THIRD_PARTY:
		handleCollRetOutput_addressBytes();
		break;

	case DESTINATION_DEVICE_OWNED:
		handleCollRetOutput_addressParams();
		break;

	default:
		ASSERT(false);
	};
}
// ============================== ASSET GROUP ==============================

enum {
	HANDLE_ASSET_GROUP_STEP_DISPLAY = 3300,
	HANDLE_ASSET_GROUP_STEP_RESPOND,
	HANDLE_ASSET_GROUP_STEP_INVALID,
};

static void handleAssetGroup_ui_runStep()
{
	output_context_t* subctx = accessSubcontext();
	TRACE("UI step %d", subctx->ui_step);
	ui_callback_fn_t* this_fn = handleAssetGroup_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_ASSET_GROUP_STEP_RESPOND) {
		respondSuccessEmptyMsg();

		advanceState();
	}
	UI_STEP_END(HANDLE_ASSET_GROUP_STEP_INVALID);
}

static void handleAssetGroupAPDU(const uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		// sanity checks
		CHECK_STATE(STATE_OUTPUT_ASSET_GROUP);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}
	output_context_t* subctx = accessSubcontext();
	{
		token_group_t* tokenGroup = &subctx->stateData.tokenGroup;

		// parse data
		TRACE_BUFFER(wireDataBuffer, wireDataSize);
		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

		uint8_t candidatePolicyId[MINTING_POLICY_ID_SIZE] = {0};
		view_parseBuffer(candidatePolicyId, &view, MINTING_POLICY_ID_SIZE);

		if (subctx->stateData.currentAssetGroup > 0) {
			// compare with previous value before overwriting it
			VALIDATE(cbor_mapKeyFulfillsCanonicalOrdering(
			                 tokenGroup->policyId, MINTING_POLICY_ID_SIZE,
			                 candidatePolicyId, MINTING_POLICY_ID_SIZE
			         ), ERR_INVALID_DATA);
		}

		STATIC_ASSERT(SIZEOF(tokenGroup->policyId) >= MINTING_POLICY_ID_SIZE, "wrong policyId length");
		memmove(tokenGroup->policyId, candidatePolicyId, MINTING_POLICY_ID_SIZE);

		uint32_t numTokens = parse_u4be(&view);
		VALIDATE(numTokens <= OUTPUT_TOKENS_IN_GROUP_MAX, ERR_INVALID_DATA);
		VALIDATE(numTokens > 0, ERR_INVALID_DATA);
		STATIC_ASSERT(OUTPUT_TOKENS_IN_GROUP_MAX <= UINT16_MAX, "wrong max token amounts in a group");
		ASSERT_TYPE(subctx->stateData.numTokens, uint16_t);
		subctx->stateData.numTokens = (uint16_t) numTokens;

		VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);
	}

	{
		// add tokengroup to tx
		TRACE("Adding token group hash to tx hash");
		txHashBuilder_addOutput_tokenGroup(
		        &BODY_CTX->txHashBuilder,
		        subctx->stateData.tokenGroup.policyId, MINTING_POLICY_ID_SIZE,
		        subctx->stateData.numTokens
		);
		TRACE();
	}

	subctx->ui_step = HANDLE_ASSET_GROUP_STEP_RESPOND;
	handleAssetGroup_ui_runStep();
}

// ============================== TOKEN ==============================

enum {
	HANDLE_TOKEN_STEP_DISPLAY_NAME = 3400,
	HANDLE_TOKEN_STEP_DISPLAY_AMOUNT,
	HANDLE_TOKEN_STEP_RESPOND,
	HANDLE_TOKEN_STEP_INVALID,
};

static void handleToken_ui_runStep()
{
	output_context_t* subctx = accessSubcontext();
	TRACE("UI step %d", subctx->ui_step);
	ui_callback_fn_t* this_fn = handleToken_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_TOKEN_STEP_DISPLAY_NAME) {
		ui_displayAssetFingerprintScreen(
		        &subctx->stateData.tokenGroup,
		        subctx->stateData.token.assetNameBytes, subctx->stateData.token.assetNameSize,
		        this_fn
		);
	}
	UI_STEP(HANDLE_TOKEN_STEP_DISPLAY_AMOUNT) {
		ui_displayTokenAmountOutputScreen(
		        &subctx->stateData.tokenGroup,
		        subctx->stateData.token.assetNameBytes, subctx->stateData.token.assetNameSize,
		        subctx->stateData.token.amount,
		        this_fn
		);
	}
	UI_STEP(HANDLE_TOKEN_STEP_RESPOND) {
		respondSuccessEmptyMsg();

		ASSERT(subctx->stateData.currentToken < subctx->stateData.numTokens);
		subctx->stateData.currentToken++;

		if (subctx->stateData.currentToken == subctx->stateData.numTokens) {
			advanceState();
		}
	}
	UI_STEP_END(HANDLE_TOKEN_STEP_INVALID);
}

static void handleTokenAPDU(const uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		// sanity checks
		CHECK_STATE(STATE_OUTPUT_TOKEN);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}
	output_context_t* subctx = accessSubcontext();
	{
		output_token_amount_t* token = &subctx->stateData.token;

		// parse data
		TRACE_BUFFER(wireDataBuffer, wireDataSize);
		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

		const size_t candidateAssetNameSize = parse_u4be(&view);
		VALIDATE(candidateAssetNameSize <= ASSET_NAME_SIZE_MAX, ERR_INVALID_DATA);
		uint8_t candidateAssetNameBytes[ASSET_NAME_SIZE_MAX] = {0};
		view_parseBuffer(candidateAssetNameBytes, &view, candidateAssetNameSize);

		if (subctx->stateData.currentToken > 0) {
			// compare with previous value before overwriting it
			VALIDATE(cbor_mapKeyFulfillsCanonicalOrdering(
			                 token->assetNameBytes, token->assetNameSize,
			                 candidateAssetNameBytes, candidateAssetNameSize
			         ), ERR_INVALID_DATA);
		}

		token->assetNameSize = candidateAssetNameSize;
		STATIC_ASSERT(SIZEOF(token->assetNameBytes) >= ASSET_NAME_SIZE_MAX, "wrong asset name buffer size");
		memmove(token->assetNameBytes, candidateAssetNameBytes, candidateAssetNameSize);

		token->amount = parse_u8be(&view);
		TRACE_UINT64(token->amount);

		VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);
	}

	{
		// select UI step
		switch (subctx->outputSecurityPolicy) {
#define  CASE(POLICY, UI_STEP) case POLICY: {subctx->ui_step=UI_STEP; break;}
			CASE(POLICY_PROMPT_WARN_UNUSUAL, HANDLE_TOKEN_STEP_DISPLAY_NAME);
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_TOKEN_STEP_DISPLAY_NAME);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_TOKEN_STEP_RESPOND);
#undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	{
		// add tokengroup to tx
		TRACE("Adding token group hash to tx hash");
		txHashBuilder_addOutput_token(
		        &BODY_CTX->txHashBuilder,
		        subctx->stateData.token.assetNameBytes, subctx->stateData.token.assetNameSize,
		        subctx->stateData.token.amount);
		TRACE();
	}

	handleToken_ui_runStep();
}

// ========================== DATUM =============================

enum {
	HANDLE_DATUM_HASH_STEP_DISPLAY = 3500,
	HANDLE_DATUM_HASH_STEP_RESPOND,
	HANDLE_DATUM_HASH_STEP_INVALID,
};

static void signTxOutput_handleDatumHash_ui_runStep()
{
	output_context_t* subctx = accessSubcontext();
	TRACE("UI step %d", subctx->ui_step);
	ui_callback_fn_t* this_fn = signTxOutput_handleDatumHash_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_DATUM_HASH_STEP_DISPLAY) {
		ui_displayBech32Screen(
		        "Datum hash",
		        "datum",
		        subctx->stateData.datumHash, OUTPUT_DATUM_HASH_LENGTH,
		        this_fn
		);
	}
	UI_STEP(HANDLE_DATUM_HASH_STEP_RESPOND) {
		respondSuccessEmptyMsg();

		advanceState();
	}
	UI_STEP_END(HANDLE_DATUM_HASH_STEP_INVALID);
}

static void handleDatumHash(read_view_t* view)
{
	output_context_t* subctx = accessSubcontext();
	{
		// parse data
		STATIC_ASSERT(SIZEOF(subctx->stateData.datumHash) == OUTPUT_DATUM_HASH_LENGTH, "wrong datum hash length");
		view_parseBuffer(subctx->stateData.datumHash, view, OUTPUT_DATUM_HASH_LENGTH);
		VALIDATE(view_remainingSize(view) == 0, ERR_INVALID_DATA);
	}
	{
		// add to tx
		TRACE("Adding datum hash to tx hash");
		txHashBuilder_addOutput_datum(
		        &BODY_CTX->txHashBuilder,
		        subctx->stateData.datumType,
		        subctx->stateData.datumHash, SIZEOF(subctx->stateData.datumHash));
	}
	subctx->datumHashReceived = true;
	{
		// select UI step
		security_policy_t policy = policyForSignTxOutputDatumHash(subctx->outputSecurityPolicy);
		TRACE("Policy: %d", (int) policy);
		ENSURE_NOT_DENIED(policy);

		switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {subctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_DATUM_HASH_STEP_DISPLAY);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_DATUM_HASH_STEP_RESPOND);
#	undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	signTxOutput_handleDatumHash_ui_runStep();
}

// TODO
static void signTxOutput_handleDatumInline_ui_runStep()
{
	output_context_t* subctx = accessSubcontext();
	TRACE("UI step %d", subctx->ui_step);
	ui_callback_fn_t* this_fn = signTxOutput_handleDatumInline_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_DATUM_HASH_STEP_DISPLAY) {
		ui_displayBech32Screen(
		        "TODO",
		        "TODO",
		        subctx->stateData.datumHash, OUTPUT_DATUM_HASH_LENGTH,
		        this_fn
		);
	}
	UI_STEP(HANDLE_DATUM_HASH_STEP_RESPOND) {
		respondSuccessEmptyMsg();

		advanceState();
	}
	UI_STEP_END(HANDLE_DATUM_HASH_STEP_INVALID);
}

static void handleDatumInline(read_view_t* view)
{
	output_context_t* subctx = accessSubcontext();
	{
		// parse data
		subctx->stateData.datumRemainingBytes = parse_u4be(view);
		VALIDATE(subctx->stateData.datumRemainingBytes > 0, ERR_INVALID_DATA);
		// TODO some other validation?

		size_t chunkSize = parse_u4be(view);
		VALIDATE(chunkSize > 0, ERR_INVALID_DATA);
		VALIDATE(chunkSize <= MAX_CHUNK_SIZE, ERR_INVALID_DATA);
		VALIDATE(chunkSize <= subctx->stateData.datumRemainingBytes, ERR_INVALID_DATA);

		view_parseBuffer(subctx->stateData.datumChunk, view, chunkSize);
		VALIDATE(view_remainingSize(view) == 0, ERR_INVALID_DATA);

		subctx->stateData.datumChunkSize = chunkSize;
	}
	{
		// add to tx
		TRACE("Adding inline datum to tx hash");
		txHashBuilder_addOutput_datum(
		        &BODY_CTX->txHashBuilder,
		        subctx->stateData.datumType,
		        NULL, subctx->stateData.datumRemainingBytes
		);
		txHashBuilder_addOutput_datum_inline_chunk(
		        &BODY_CTX->txHashBuilder,
		        subctx->stateData.datumChunk, subctx->stateData.datumChunkSize
		);
	}
	{
		// we can't do this sooner because tx hash builder has to receive proper total size
		subctx->stateData.datumRemainingBytes -= subctx->stateData.datumChunkSize;
	}
	{
		// TODO all of this

		// select UI step
		security_policy_t policy = policyForSignTxOutputDatumHash(subctx->outputSecurityPolicy);
		TRACE("Policy: %d", (int) policy);
		ENSURE_NOT_DENIED(policy);

		switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {subctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_DATUM_HASH_STEP_DISPLAY);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_DATUM_HASH_STEP_RESPOND);
#	undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}

		// TODO
		respondSuccessEmptyMsg();
		advanceState();
		//signTxOutput_handleDatumInline_ui_runStep();
	}
}

static void handleDatumAPDU(const uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		// sanity checks
		CHECK_STATE(STATE_OUTPUT_DATUM);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}
	output_context_t* subctx = accessSubcontext();
	{
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

		subctx->stateData.datumType = parse_u1be(&view);
		TRACE("datumType = %d", subctx->stateData.datumType);

		switch (subctx->stateData.datumType) {

		case DATUM_HASH:
			handleDatumHash(&view);
			break;

		case DATUM_INLINE:
			handleDatumInline(&view);
			break;

		default:
			THROW(ERR_INVALID_DATA);
		}
	}
}

static void handleDatumChunkAPDU(const uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		// sanity checks
		CHECK_STATE(STATE_OUTPUT_DATUM_INLINE_CHUNKS);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}
	output_context_t* subctx = accessSubcontext();
	{
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

		const size_t chunkSize = parse_u4be(&view);
		VALIDATE(chunkSize > 0, ERR_INVALID_DATA);
		VALIDATE(chunkSize <= MAX_CHUNK_SIZE, ERR_INVALID_DATA);

		VALIDATE(chunkSize <= subctx->stateData.datumRemainingBytes, ERR_INVALID_DATA);
		subctx->stateData.datumRemainingBytes -= chunkSize;

		view_parseBuffer(subctx->stateData.datumChunk, &view, chunkSize);
		VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);

		subctx->stateData.datumChunkSize = chunkSize;
	}
	{
		// add to tx
		TRACE("Adding inline datum chunk to tx hash");
		txHashBuilder_addOutput_datum_inline_chunk(
		        &BODY_CTX->txHashBuilder,
		        subctx->stateData.datumChunk, subctx->stateData.datumChunkSize
		);
	}
	respondSuccessEmptyMsg();
	if (subctx->stateData.datumRemainingBytes == 0) {
		advanceState();
	}
}

// ========================== REFERENCE SCRIPT =============================

static void handleRefScriptAPDU(const uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		// sanity checks
		CHECK_STATE(STATE_OUTPUT_REFERENCE_SCRIPT);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}
	output_context_t* subctx = accessSubcontext();
	{
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

		// parse data
		subctx->stateData.refScriptRemainingBytes = parse_u4be(&view);
		VALIDATE(subctx->stateData.refScriptRemainingBytes > 0, ERR_INVALID_DATA);
		// TODO some other validation?

		size_t chunkSize = parse_u4be(&view);
		VALIDATE(chunkSize > 0, ERR_INVALID_DATA);
		VALIDATE(chunkSize <= MAX_CHUNK_SIZE, ERR_INVALID_DATA);
		VALIDATE(chunkSize <= subctx->stateData.refScriptRemainingBytes, ERR_INVALID_DATA);

		view_parseBuffer(subctx->stateData.scriptChunk, &view, chunkSize);
		VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);

		subctx->stateData.refScriptChunkSize = chunkSize;
	}
	{
		// add to tx
		TRACE("Adding reference script to tx hash");
		txHashBuilder_addOutput_referenceScript(
		        &BODY_CTX->txHashBuilder,
		        subctx->stateData.datumRemainingBytes
		);
		txHashBuilder_addOutput_referenceScript_dataChunk(
		        &BODY_CTX->txHashBuilder,
		        subctx->stateData.scriptChunk, subctx->stateData.refScriptChunkSize
		);
	}
	{
		// we can't do this sooner because tx hash builder has to receive proper total size
		subctx->stateData.refScriptRemainingBytes -= subctx->stateData.refScriptChunkSize;
	}
	{
		// TODO all of this

		// select UI step
		security_policy_t policy = policyForSignTxOutputDatumHash(subctx->outputSecurityPolicy);
		TRACE("Policy: %d", (int) policy);
		ENSURE_NOT_DENIED(policy);

		switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {subctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_DATUM_HASH_STEP_DISPLAY);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_DATUM_HASH_STEP_RESPOND);
#	undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}

		// TODO
		respondSuccessEmptyMsg();
		advanceState();
		//signTxOutput_handleDatumInline_ui_runStep();
	}
}

static void handleRefScriptChunkAPDU(const uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		// sanity checks
		CHECK_STATE(STATE_OUTPUT_REFERENCE_SCRIPT_CHUNKS);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}
	output_context_t* subctx = accessSubcontext();
	{
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

		const size_t chunkSize = parse_u4be(&view);
		VALIDATE(chunkSize > 0, ERR_INVALID_DATA);
		VALIDATE(chunkSize <= MAX_CHUNK_SIZE, ERR_INVALID_DATA);

		VALIDATE(chunkSize <= subctx->stateData.refScriptRemainingBytes, ERR_INVALID_DATA);
		subctx->stateData.refScriptRemainingBytes -= chunkSize;

		view_parseBuffer(subctx->stateData.scriptChunk, &view, chunkSize);
		VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);

		subctx->stateData.refScriptChunkSize = chunkSize;
	}
	{
		// add to tx
		TRACE("Adding inline datum chunk to tx hash");
		txHashBuilder_addOutput_referenceScript_dataChunk(
		        &BODY_CTX->txHashBuilder,
		        subctx->stateData.scriptChunk, subctx->stateData.refScriptChunkSize
		);
	}
	respondSuccessEmptyMsg();
	if (subctx->stateData.refScriptRemainingBytes == 0) {
		advanceState();
	}
}

// ============================== CONFIRM ==============================

enum {
	HANDLE_CONFIRM_STEP_FINAL_CONFIRM = 3600,
	HANDLE_CONFIRM_STEP_RESPOND,
	HANDLE_CONFIRM_STEP_INVALID,
};

static void signTxOutput_handleConfirm_ui_runStep()
{
	output_context_t* subctx = accessSubcontext();
	TRACE("UI step %d", subctx->ui_step);
	ui_callback_fn_t* this_fn = signTxOutput_handleConfirm_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_CONFIRM_STEP_FINAL_CONFIRM) {
		ui_displayPrompt(
				subctx->ui_text1,
				subctx->ui_text2,
		        this_fn,
		        respond_with_user_reject
		);
	}
	UI_STEP(HANDLE_CONFIRM_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		advanceState();
	}
	UI_STEP_END(HANDLE_CONFIRM_STEP_INVALID);
}

static void handleConfirmAPDU_output(const uint8_t* wireDataBuffer MARK_UNUSED, size_t wireDataSize)
{
	{
		CHECK_STATE(STATE_OUTPUT_CONFIRM);

		VALIDATE(wireDataSize == 0, ERR_INVALID_DATA);
	}

	output_context_t* subctx = accessSubcontext();
	security_policy_t policy = policyForSignTxOutputConfirm(
	                                   subctx->outputSecurityPolicy,
	                                   subctx->numAssetGroups
	                           );
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		// select UI step
		switch (policy) {
#define  CASE(POLICY, UI_STEP) case POLICY: {subctx->ui_step=UI_STEP; break;}
			CASE(POLICY_PROMPT_BEFORE_RESPONSE, HANDLE_CONFIRM_STEP_FINAL_CONFIRM);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_CONFIRM_STEP_RESPOND);
#undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}

		subctx->ui_text1 = "Confirm";
		subctx->ui_text2 = "output?";
	}

	signTxOutput_handleConfirm_ui_runStep();
}

static void handleConfirmAPDU_collRetOutput(const uint8_t* wireDataBuffer MARK_UNUSED, size_t wireDataSize)
{
	{
		CHECK_STATE(STATE_OUTPUT_CONFIRM);

		VALIDATE(wireDataSize == 0, ERR_INVALID_DATA);
	}

	output_context_t* subctx = accessSubcontext();
	security_policy_t policy = policyForSignTxCollRetOutputConfirm(
	                                   subctx->outputSecurityPolicy,
	                                   subctx->numAssetGroups
	                           );
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		// select UI step
		switch (policy) {
#define  CASE(POLICY, UI_STEP) case POLICY: {subctx->ui_step=UI_STEP; break;}
			CASE(POLICY_PROMPT_BEFORE_RESPONSE, HANDLE_CONFIRM_STEP_FINAL_CONFIRM);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_CONFIRM_STEP_RESPOND);
#undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}

		subctx->ui_text1 = "Confirm collateral";
		subctx->ui_text2 = "return output?";
	}

	signTxOutput_handleConfirm_ui_runStep();
}

// ============================== main APDU handler ==============================

enum {
	APDU_INSTRUCTION_TOP_LEVEL_DATA = 0x30,
	APDU_INSTRUCTION_ASSET_GROUP = 0x31,
	APDU_INSTRUCTION_TOKEN = 0x32,
	APDU_INSTRUCTION_DATUM = 0x34,
	APDU_INSTRUCTION_DATUM_CHUNK = 0x35,
	APDU_INSTRUCTION_REF_SCRIPT = 0x36,
	APDU_INSTRUCTION_REF_SCRIPT_CHUNK = 0x37,
	APDU_INSTRUCTION_CONFIRM = 0x33,
};

bool signTxOutput_isValidInstruction(uint8_t p2)
{
	switch (p2) {
	case APDU_INSTRUCTION_TOP_LEVEL_DATA:
	case APDU_INSTRUCTION_ASSET_GROUP:
	case APDU_INSTRUCTION_TOKEN:
	case APDU_INSTRUCTION_DATUM:
	case APDU_INSTRUCTION_DATUM_CHUNK:
	case APDU_INSTRUCTION_REF_SCRIPT:
	case APDU_INSTRUCTION_REF_SCRIPT_CHUNK:
	case APDU_INSTRUCTION_CONFIRM:
		return true;

	default:
		return false;
	}
}

void signTxOutput_handleAPDU(uint8_t p2, const uint8_t* wireDataBuffer, size_t wireDataSize)
{
	ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);

	switch (p2) {
	case APDU_INSTRUCTION_TOP_LEVEL_DATA:
		handleTopLevelDataAPDU_output(wireDataBuffer, wireDataSize);
		break;

	case APDU_INSTRUCTION_ASSET_GROUP:
		handleAssetGroupAPDU(wireDataBuffer, wireDataSize);
		break;

	case APDU_INSTRUCTION_TOKEN:
		handleTokenAPDU(wireDataBuffer, wireDataSize);
		break;

	case APDU_INSTRUCTION_DATUM:
		handleDatumAPDU(wireDataBuffer, wireDataSize);
		break;

	case APDU_INSTRUCTION_DATUM_CHUNK:
		handleDatumChunkAPDU(wireDataBuffer, wireDataSize);
		break;

	case APDU_INSTRUCTION_REF_SCRIPT:
		handleRefScriptAPDU(wireDataBuffer, wireDataSize);
		break;

	case APDU_INSTRUCTION_REF_SCRIPT_CHUNK:
		handleRefScriptChunkAPDU(wireDataBuffer, wireDataSize);
		break;

	case APDU_INSTRUCTION_CONFIRM:
		handleConfirmAPDU_output(wireDataBuffer, wireDataSize);
		break;

	default:
		// this is not supposed to be called with invalid p2
		ASSERT(false);
	}
}

bool signTxCollRetOutput_isValidInstruction(uint8_t p2)
{
	switch (p2) {
	case APDU_INSTRUCTION_TOP_LEVEL_DATA:
	case APDU_INSTRUCTION_ASSET_GROUP:
	case APDU_INSTRUCTION_TOKEN:
	case APDU_INSTRUCTION_DATUM:
	case APDU_INSTRUCTION_DATUM_CHUNK:
	case APDU_INSTRUCTION_REF_SCRIPT:
	case APDU_INSTRUCTION_REF_SCRIPT_CHUNK:
	case APDU_INSTRUCTION_CONFIRM:
		return true;

	default:
		return false;
	}
}

void signTxCollRetOutput_handleAPDU(uint8_t p2, const uint8_t* wireDataBuffer, size_t wireDataSize)
{
	ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);

	switch (p2) {
	case APDU_INSTRUCTION_TOP_LEVEL_DATA:
		handleTopLevelDataAPDU_collRetOutput(wireDataBuffer, wireDataSize);
		break;

	case APDU_INSTRUCTION_ASSET_GROUP:
		handleAssetGroupAPDU(wireDataBuffer, wireDataSize);
		break;

	case APDU_INSTRUCTION_TOKEN:
		handleTokenAPDU(wireDataBuffer, wireDataSize);
		break;

	case APDU_INSTRUCTION_CONFIRM:
		handleConfirmAPDU_collRetOutput(wireDataBuffer, wireDataSize);
		break;

	case APDU_INSTRUCTION_DATUM:
	case APDU_INSTRUCTION_DATUM_CHUNK:
	case APDU_INSTRUCTION_REF_SCRIPT:
	case APDU_INSTRUCTION_REF_SCRIPT_CHUNK:
		// we don't allow such items because there is no use case for them
		// if they were ever needed, APDU handling code needs to be added
		THROW(ERR_REJECTED_BY_POLICY);
		break;

	default:
		// this is not supposed to be called with invalid p2
		ASSERT(false);
	}
}
