#include "messageSigning.h"
#include "securityPolicy.h"
#include "signCVote.h"
#include "signTxUtils.h"
#include "state.h"
#include "signCVote_ui.h"

static ins_sign_cvote_context_t* ctx = &(instructionState.signCVoteContext);

void vote_advanceStage()
{
	TRACE("Advancing cip36 voting stage from: %d", ctx->stage);

	switch (ctx->stage) {
	case VOTECAST_STAGE_INIT:
		if (ctx->remainingVotecastBytes == 0) {
			ctx->stage = VOTECAST_STAGE_CONFIRM;
		} else {
			ctx->stage = VOTECAST_STAGE_CHUNK;
		}
		break;

	case VOTECAST_STAGE_CHUNK:
		ASSERT(ctx->remainingVotecastBytes == 0);
		ctx->stage = VOTECAST_STAGE_CONFIRM;
		break;

	case VOTECAST_STAGE_CONFIRM:
		ctx->stage = VOTECAST_STAGE_WITNESS;
		break;

	case VOTECAST_STAGE_WITNESS:
		ctx->stage = VOTECAST_STAGE_NONE;
		ui_idle(); // we are done
		break;

	case VOTECAST_STAGE_NONE:
		// vote_advanceStage() not supposed to be called after votecast processing is finished
		ASSERT(false);

	default:
		ASSERT(false);

	}

	TRACE("Advancing cip36 voting stage to: %d", ctx->stage);
}

// this is supposed to be called at the beginning of each APDU handler
static inline void CHECK_STAGE(sign_cvote_stage_t expected)
{
	TRACE("Checking stage... current one is %d, expected %d", ctx->stage, expected);
	VALIDATE(ctx->stage == expected, ERR_INVALID_STATE);
}

// ============================== INIT ==============================
__noinline_due_to_stack__
void signCVote_handleInitAPDU(
        const uint8_t* wireDataBuffer, size_t wireDataSize
)
{
	{
		//sanity checks
		CHECK_STAGE(VOTECAST_STAGE_INIT);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}
	{
		TRACE_BUFFER(wireDataBuffer, wireDataSize);
		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

		// parse total length of data to sign
		ctx->remainingVotecastBytes = parse_u4be(&view);
		TRACE("Remaining votecast bytes = %u", ctx->remainingVotecastBytes);
		// we need vote plan id, proposal index, payload type tag
		// and more data of unknown size for the fragment
		VALIDATE(view_remainingSize(&view) > VOTE_PLAN_ID_SIZE + 1 + 1, ERR_INVALID_DATA);

		// this is only parsed to be shown in the UI, the whole chunk is passed to hash builder
		STATIC_ASSERT(SIZEOF(ctx->votePlanId) == VOTE_PLAN_ID_SIZE, "wrong vote plan id size");
		view_parseBuffer(ctx->votePlanId, &view, VOTE_PLAN_ID_SIZE);
		TRACE("Vote plan id:");
		TRACE_BUFFER(ctx->votePlanId, VOTE_PLAN_ID_SIZE);

		ctx->proposalIndex = parse_u1be(&view);
		TRACE("Proposal index = %u", ctx->proposalIndex);

		ctx->payloadTypeTag = parse_u1be(&view);
		TRACE("Payload type tag = %u", ctx->payloadTypeTag);
	}

	// Check security policy
	security_policy_t policy = policyForSignCVoteInit();
	ENSURE_NOT_DENIED(policy);

	{
		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);
		view_skipBytes(&view, 4); // skip total length of data to sign

		const size_t chunkSize = view_remainingSize(&view);
		VALIDATE(chunkSize <= MAX_VOTECAST_CHUNK_SIZE, ERR_INVALID_DATA);
		VALIDATE(chunkSize <= ctx->remainingVotecastBytes, ERR_INVALID_DATA);

		votecastHashBuilder_init(&ctx->votecastHashBuilder, ctx->remainingVotecastBytes);
		votecastHashBuilder_chunk(&ctx->votecastHashBuilder, VIEW_REMAINING_TO_TUPLE_BUF_SIZE(&view));

		ASSERT(ctx->remainingVotecastBytes >= chunkSize);
		ctx->remainingVotecastBytes -= chunkSize;
	}

	switch (policy) {
#define  CASE(policy, step) case policy: {ctx->ui_step = step; break;}
		CASE(POLICY_PROMPT_BEFORE_RESPONSE, HANDLE_INIT_CONFIRM_START);
		CASE(POLICY_SHOW_BEFORE_RESPONSE,   HANDLE_INIT_VOTE_PLAN_ID);
		CASE(POLICY_ALLOW_WITHOUT_PROMPT,   HANDLE_INIT_RESPOND);
#undef   CASE
	default:
		THROW(ERR_NOT_IMPLEMENTED);
	}
	handleInit_ui_runStep();
}

// ============================== VOTECAST CHUNK ==============================

__noinline_due_to_stack__
void signCVote_handleVotecastChunkAPDU(
        const uint8_t* wireDataBuffer, size_t wireDataSize
)
{
	{
		//sanity checks
		CHECK_STAGE(VOTECAST_STAGE_CHUNK);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}
	{
		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);
		size_t chunkSize = view_remainingSize(&view);
		TRACE("chunkSize = %u", chunkSize);
		VALIDATE(chunkSize > 0, ERR_INVALID_DATA);
		VALIDATE(chunkSize <= MAX_VOTECAST_CHUNK_SIZE, ERR_INVALID_DATA);
		VALIDATE(chunkSize <= ctx->remainingVotecastBytes, ERR_INVALID_DATA);

		votecastHashBuilder_chunk(&ctx->votecastHashBuilder, VIEW_REMAINING_TO_TUPLE_BUF_SIZE(&view));

		ASSERT(ctx->remainingVotecastBytes >= chunkSize);
		ctx->remainingVotecastBytes -= chunkSize;
	}

	respondSuccessEmptyMsg();
	if (ctx->remainingVotecastBytes == 0) {
		vote_advanceStage();
	}
}

// ============================== CONFIRM ==============================
__noinline_due_to_stack__
void signCVote_handleConfirmAPDU(
        const uint8_t* wireDataBuffer MARK_UNUSED, size_t wireDataSize
)
{
	TRACE_STACK_USAGE();
	{
		//sanity checks
		CHECK_STAGE(VOTECAST_STAGE_CONFIRM);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}
	{
		// no data to receive
		VALIDATE(wireDataSize == 0, ERR_INVALID_DATA);
	}

	security_policy_t policy = policyForSignCVoteConfirm();
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		TRACE("Finalizing tx hash");

		votecastHashBuilder_finalize(
		        &ctx->votecastHashBuilder,
		        ctx->votecastHash, SIZEOF(ctx->votecastHash)
		);
	}

	{
		// select UI step
		switch (policy) {
#define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
			CASE(POLICY_PROMPT_BEFORE_RESPONSE, HANDLE_CONFIRM_STEP_FINAL_CONFIRM);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_CONFIRM_STEP_RESPOND);
#undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	handleConfirm_ui_runStep();
}

// ============================== WITNESS ==============================

__noinline_due_to_stack__
void signCVote_handleWitnessAPDU(
        const uint8_t* wireDataBuffer, size_t wireDataSize
)
{
	TRACE_STACK_USAGE();
	{
		// sanity checks
		CHECK_STAGE(VOTECAST_STAGE_WITNESS);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}

	{
		// parse
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		size_t parsedSize = bip44_parseFromWire(&ctx->witnessData.path, wireDataBuffer, wireDataSize);
		VALIDATE(parsedSize == wireDataSize, ERR_INVALID_DATA);

		TRACE();
		BIP44_PRINTF(&ctx->witnessData.path);
		PRINTF("\n");
	}

	security_policy_t policy = policyForSignCVoteWitness(&ctx->witnessData.path);
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		// compute witness
		TRACE("getCVoteWitness");
		TRACE("votecast hash:");
		TRACE_BUFFER(ctx->votecastHash, SIZEOF(ctx->votecastHash));

		getWitness(
		        &ctx->witnessData.path,
		        ctx->votecastHash, SIZEOF(ctx->votecastHash),
		        ctx->witnessData.signature, SIZEOF(ctx->witnessData.signature)
		);
	}

	{
		// choose UI steps
		switch (policy) {
#define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
			CASE(POLICY_PROMPT_WARN_UNUSUAL, HANDLE_WITNESS_STEP_WARNING);
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_WITNESS_STEP_DISPLAY);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_WITNESS_STEP_RESPOND);
#undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}
	handleWitness_ui_runStep();
}


// ============================== MAIN HANDLER ==============================

typedef void subhandler_fn_t(const uint8_t* dataBuffer, size_t dataSize);

static subhandler_fn_t* lookup_subhandler(uint8_t p1)
{
	switch (p1) {
#define  CASE(P1, HANDLER) case P1: return HANDLER;
#define  DEFAULT(HANDLER)  default: return HANDLER;
		CASE(0x01, signCVote_handleInitAPDU);
		CASE(0x02, signCVote_handleVotecastChunkAPDU);
		CASE(0x03, signCVote_handleConfirmAPDU);
		CASE(0x04, signCVote_handleWitnessAPDU);
		DEFAULT(NULL)
#undef   CASE
#undef   DEFAULT
	}
}

void signCVote_handleAPDU(
        uint8_t p1,
        uint8_t p2,
        const uint8_t* wireDataBuffer,
        size_t wireDataSize,
        bool isNewCall
)
{
	ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);

	if (isNewCall) {
		explicit_bzero(ctx, SIZEOF(*ctx));
		ctx->stage = VOTECAST_STAGE_INIT;
	}
	VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);

	subhandler_fn_t* subhandler = lookup_subhandler(p1);
	VALIDATE(subhandler != NULL, ERR_INVALID_REQUEST_PARAMETERS);
	subhandler(wireDataBuffer, wireDataSize);
}
