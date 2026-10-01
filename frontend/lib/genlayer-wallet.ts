import { createClient } from "genlayer-js";
import { testnetBradbury } from "genlayer-js/chains";

import { AGENTSEAL_RELEASE } from "@/lib/agentseal";

type ProviderRequest = {
  method: string;
  params?: unknown[];
};

export type Eip1193Provider = {
  request(args: ProviderRequest): Promise<unknown>;
};

export type AgentSealWalletConnection = {
  address: `0x${string}`;
  chainId: number;
};

type WriteClient = ReturnType<typeof createClient>;

const BRADBURY_CHAIN_ID_HEX = `0x${testnetBradbury.id.toString(16)}`;

let writeClient: WriteClient | null = null;

function injectedProvider(): Eip1193Provider | null {
  if (typeof window === "undefined") return null;

  return (
    window as Window & {
      ethereum?: Eip1193Provider;
    }
  ).ethereum ?? null;
}

function asAddress(value: unknown): `0x${string}` {
  if (
    typeof value !== "string" ||
    !/^0x[0-9a-fA-F]{40}$/.test(value)
  ) {
    throw new Error("Wallet returned an invalid account address.");
  }

  return value as `0x${string}`;
}

function asChainId(value: unknown): number {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]+$/.test(value)) {
    throw new Error("Wallet returned an invalid chain ID.");
  }

  return Number.parseInt(value, 16);
}

async function ensureBradbury(provider: Eip1193Provider): Promise<void> {
  const current = await provider.request({ method: "eth_chainId" });

  if (asChainId(current) === testnetBradbury.id) return;

  await provider.request({
    method: "wallet_addEthereumChain",
    params: [
      {
        chainId: BRADBURY_CHAIN_ID_HEX,
        chainName: testnetBradbury.name,
        rpcUrls: [...testnetBradbury.rpcUrls.default.http],
        nativeCurrency: testnetBradbury.nativeCurrency,
        blockExplorerUrls: testnetBradbury.blockExplorers?.default
          ? [testnetBradbury.blockExplorers.default.url]
          : [],
      },
    ],
  });

  await provider.request({
    method: "wallet_switchEthereumChain",
    params: [{ chainId: BRADBURY_CHAIN_ID_HEX }],
  });

  const switched = await provider.request({ method: "eth_chainId" });

  if (asChainId(switched) !== testnetBradbury.id) {
    throw new Error("Wallet did not switch to GenLayer Testnet Bradbury.");
  }
}

export function hasInjectedWallet(): boolean {
  return injectedProvider() !== null;
}

export async function connectBradburyWallet(): Promise<AgentSealWalletConnection> {
  if (testnetBradbury.id !== AGENTSEAL_RELEASE.chainId) {
    throw new Error(
      `Bradbury chain mismatch: SDK=${testnetBradbury.id}, AgentSeal=${AGENTSEAL_RELEASE.chainId}`,
    );
  }

  const provider = injectedProvider();

  if (!provider) {
    throw new Error("No injected EIP-1193 wallet was detected.");
  }

  await ensureBradbury(provider);

  const accounts = await provider.request({ method: "eth_requestAccounts" });

  if (!Array.isArray(accounts) || accounts.length === 0) {
    throw new Error("Wallet did not return an account.");
  }

  const address = asAddress(accounts[0]);

  writeClient = createClient({
    chain: testnetBradbury,
    account: address,
    provider: provider as never,
  });

  return {
    address,
    chainId: testnetBradbury.id,
  };
}

export function getBradburyWriteClient(): WriteClient {
  if (!writeClient) {
    throw new Error("Connect a Bradbury wallet before preparing a transaction.");
  }

  return writeClient;
}

export function clearBradburyWalletClient(): void {
  writeClient = null;
}
