import { createClient } from "genlayer-js";
import { testnetBradbury } from "genlayer-js/chains";
import { TransactionHashVariant } from "genlayer-js/types";

import { AGENTSEAL_RELEASE } from "@/lib/agentseal";

export type AgentSealCertificate = {
  certificate_id: number | string;
  assessment_id: number | string;
  subject_wallet: string;
  profile_digest: string;
  endpoint: string;
  capability_id: string;
  policy_id: string;
  policy_version: number | string;
  manifest_id: string;
  manifest_digest: string;
  case_a_id: string;
  case_b_id: string;
  binding_key: string;
  status: string;
  effective_status: string;
  issued_at: number | string;
  expires_at: number | string;
};

const certificateRegistry =
  AGENTSEAL_RELEASE.contracts.certificateRegistry as `0x${string}`;

let client: ReturnType<typeof createClient> | null = null;

function getClient() {
  if (testnetBradbury.id !== AGENTSEAL_RELEASE.chainId) {
    throw new Error(
      `Bradbury chain mismatch: SDK=${testnetBradbury.id}, AgentSeal=${AGENTSEAL_RELEASE.chainId}`,
    );
  }

  if (!client) {
    client = createClient({
      chain: testnetBradbury,
    });
  }

  return client;
}

function asRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Unexpected certificate response shape.");
  }
  return value as Record<string, unknown>;
}

function textField(record: Record<string, unknown>, key: string): string {
  const value = record[key];
  if (typeof value !== "string") {
    throw new Error(`Certificate field ${key} is not a string.`);
  }
  return value;
}

function scalarField(
  record: Record<string, unknown>,
  key: string,
): number | string {
  const value = record[key];
  if (typeof value !== "number" && typeof value !== "string") {
    throw new Error(`Certificate field ${key} is not a scalar.`);
  }
  return value;
}

function normalizeCertificate(value: unknown): AgentSealCertificate {
  const record = asRecord(value);

  return {
    certificate_id: scalarField(record, "certificate_id"),
    assessment_id: scalarField(record, "assessment_id"),
    subject_wallet: textField(record, "subject_wallet"),
    profile_digest: textField(record, "profile_digest"),
    endpoint: textField(record, "endpoint"),
    capability_id: textField(record, "capability_id"),
    policy_id: textField(record, "policy_id"),
    policy_version: scalarField(record, "policy_version"),
    manifest_id: textField(record, "manifest_id"),
    manifest_digest: textField(record, "manifest_digest"),
    case_a_id: textField(record, "case_a_id"),
    case_b_id: textField(record, "case_b_id"),
    binding_key: textField(record, "binding_key"),
    status: textField(record, "status"),
    effective_status: textField(record, "effective_status"),
    issued_at: scalarField(record, "issued_at"),
    expires_at: scalarField(record, "expires_at"),
  };
}

export async function readCertificate(
  certificateId: bigint,
): Promise<AgentSealCertificate | null> {
  if (certificateId < BigInt(1)) {
    throw new Error("Certificate ID must be at least 1.");
  }

  const readClient = getClient();

  const exists = await readClient.readContract({
    address: certificateRegistry,
    functionName: "certificate_exists",
    args: [certificateId],
    transactionHashVariant: TransactionHashVariant.LATEST_FINAL,
    jsonSafeReturn: true,
  });

  if (exists !== true) {
    return null;
  }

  const certificate = await readClient.readContract({
    address: certificateRegistry,
    functionName: "get_certificate",
    args: [certificateId],
    transactionHashVariant: TransactionHashVariant.LATEST_FINAL,
    jsonSafeReturn: true,
  });

  return normalizeCertificate(certificate);
}

export function getReadNetworkMetadata() {
  return {
    chainId: testnetBradbury.id,
    rpc: testnetBradbury.rpcUrls.default.http[0],
    transactionHashVariant: TransactionHashVariant.LATEST_FINAL,
    certificateRegistry,
  } as const;
}
