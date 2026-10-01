export const AGENTSEAL_RELEASE = {
  name: "AgentSeal R7",
  network: "Bradbury Testnet",
  chainId: 4221,
  sourceCommit: "1ec79cc9ba9bf711e73df5ecea2cec0f621c8b2a",
  certificationCommit: "99e93710e2e450dd4063f9b407f861705eaf449f",
  manifestId: "agentseal-bradbury-manifest-v2",
  policyId: "agentseal-bradbury-v1",
  policyVersion: 2,
  certificateTtlSeconds: 604800,
  fixtureUrl: "https://agentseal-bradbury-fixtures.vercel.app",
  auditFingerprint: "dd054837e3a60776285040dcae05eaaa5cf2d3bbf92d8fe9d4ad2375a5240541",
  contracts: {
    policyRegistry: "0x551355C4690AAd6066626A87E94f24d71593B8a7",
    registry: "0xdbED185B52871ac70B5Cd114A26a2B7912224BBF",
    certificateRegistry: "0xB683ab8DeCE80b1d170473D4FBd4b83083BcaA73",
    deterministicSupport: "0x2B811C62F1e29E7edE29127c7bABEDC65fb8A162",
    challenge: "0x8ed9D8cb10BC4EDb4Ebb8f412f4Be68be7abf6Cd",
    semanticJudge: "0x3188310A01d64FACf6b1216aAF2722c748d03d28",
    assessmentEvidenceEvaluator: "0x70CAcB92efc405D98E6Afdc4f8BEf691448Bfc2C",
    challengeEvidenceEvaluator: "0x09f6404544A6F7bEAA157a84487D650A18001C91",
  },
  certifiedExecution: {
    setupRoots: "12/12",
    semanticRoots: "11/11",
    successfulReceipts: "23/23",
    auditedTransactions: 44,
  },
} as const;

export const PRODUCT_ACTIONS = {
  verify: {
    label: "Verify certificate",
    contract: "CertificateRegistry",
    method: "get_certificate",
  },
  assess: {
    label: "Assess agent",
    contract: "Registry",
    method: "create_assessment",
  },
  challenge: {
    label: "Challenge certificate",
    contract: "Challenge",
    method: "open_challenge",
  },
} as const;

export function shortenAddress(value: string, start = 6, end = 5) {
  if (value.length <= start + end + 3) return value;
  return `${value.slice(0, start)}…${value.slice(-end)}`;
}
