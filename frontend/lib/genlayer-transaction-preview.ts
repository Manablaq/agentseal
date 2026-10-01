import { AGENTSEAL_RELEASE } from "@/lib/agentseal";

export type AgentSealTransactionPreview = {
  kind: "assessment" | "challenge";
  account: string;
  chainId: number;
  target: string;
  contract: "Registry" | "Challenge";
  functionName: "create_assessment" | "open_challenge";
  args: Array<string | number>;
  value: "0";
  confirmationText: string;
};

function requireAccount(account: string): string {
  if (!/^0x[0-9a-fA-F]{40}$/.test(account)) {
    throw new Error("Connect a valid Bradbury wallet before preparing a transaction.");
  }
  return account;
}

function normalizeProfileDigest(value: string): string {
  const digest = value.trim();

  if (!/^[0-9a-f]{64}$/.test(digest)) {
    throw new Error("Profile digest must be exactly 64 lowercase hexadecimal characters.");
  }

  return digest;
}

function normalizeHttpsEndpoint(value: string): string {
  const endpoint = value.trim();

  let parsed: URL;
  try {
    parsed = new URL(endpoint);
  } catch {
    throw new Error("Agent endpoint must be a valid HTTPS URL.");
  }

  if (parsed.protocol !== "https:") {
    throw new Error("Agent endpoint must use HTTPS.");
  }

  if (parsed.username || parsed.password) {
    throw new Error("Agent endpoint must not contain embedded credentials.");
  }

  return endpoint;
}

function normalizeCertificateId(value: string): string {
  const trimmed = value.trim();

  if (!/^[0-9]+$/.test(trimmed)) {
    throw new Error("Certificate ID must contain decimal digits only.");
  }

  const normalized = trimmed.replace(/^0+/, "") || "0";

  if (normalized === "0") {
    throw new Error("Certificate ID must be at least 1.");
  }

  return normalized;
}

export function buildAssessmentTransactionPreview(input: {
  account: string;
  profileDigest: string;
  endpoint: string;
}): AgentSealTransactionPreview {
  const account = requireAccount(input.account);
  const profileDigest = normalizeProfileDigest(input.profileDigest);
  const endpoint = normalizeHttpsEndpoint(input.endpoint);

  return {
    kind: "assessment",
    account,
    chainId: AGENTSEAL_RELEASE.chainId,
    target: AGENTSEAL_RELEASE.contracts.registry,
    contract: "Registry",
    functionName: "create_assessment",
    args: [
      profileDigest,
      endpoint,
      AGENTSEAL_RELEASE.policyId,
      AGENTSEAL_RELEASE.policyVersion,
      AGENTSEAL_RELEASE.certificateTtlSeconds,
    ],
    value: "0",
    confirmationText:
      "I reviewed the Registry target, create_assessment arguments, Bradbury chain and zero-value call.",
  };
}

export function buildChallengeTransactionPreview(input: {
  account: string;
  certificateId: string;
}): AgentSealTransactionPreview {
  const account = requireAccount(input.account);
  const certificateId = normalizeCertificateId(input.certificateId);

  return {
    kind: "challenge",
    account,
    chainId: AGENTSEAL_RELEASE.chainId,
    target: AGENTSEAL_RELEASE.contracts.challenge,
    contract: "Challenge",
    functionName: "open_challenge",
    args: [certificateId],
    value: "0",
    confirmationText:
      "I reviewed the Challenge target, open_challenge certificate ID, Bradbury chain and zero-value call.",
  };
}
