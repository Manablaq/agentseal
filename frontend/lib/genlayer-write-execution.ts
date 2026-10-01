import {
  ExecutionResult,
  TransactionStatus,
} from "genlayer-js/types";

import { getBradburyWriteClient } from "@/lib/genlayer-wallet";
import type { AgentSealTransactionPreview } from "@/lib/genlayer-transaction-preview";

const LIVE_BRADBURY_WRITE_UNLOCKED = false;

export type AgentSealExecutionResult = {
  hash: `0x${string}`;
  status: string;
  executionResult: string;
};

export function isLiveBradburyWriteUnlocked(): boolean {
  return LIVE_BRADBURY_WRITE_UNLOCKED;
}

export async function executeConfirmedBradburyTransaction(
  preview: AgentSealTransactionPreview,
): Promise<AgentSealExecutionResult> {
  if (!LIVE_BRADBURY_WRITE_UNLOCKED) {
    throw new Error(
      "Live Bradbury transaction submission is locked until an explicit blockchain-write authorization is applied.",
    );
  }

  const client = getBradburyWriteClient();

  const hash = await client.writeContract({
    address: preview.target as `0x${string}`,
    functionName: preview.functionName,
    args: preview.args,
    value: BigInt(0),
  });

  const receipt = await client.waitForTransactionReceipt({
    hash,
    status: TransactionStatus.FINALIZED,
  });

  if (receipt.txExecutionResultName !== ExecutionResult.FINISHED_WITH_RETURN) {
    throw new Error(
      `Finalized GenLayer transaction did not finish with a return value: ${receipt.txExecutionResultName}`,
    );
  }

  return {
    hash,
    status: TransactionStatus.FINALIZED,
    executionResult: String(receipt.txExecutionResultName),
  };
}
