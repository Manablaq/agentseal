# AgentSeal Frontend

Frontend foundation for the certified AgentSeal R7 Bradbury backend.

## Design direction

The interface adapts the high-energy sports-landing-page composition supplied as the visual reference: oversized typography, dark editorial framing, hard geometric cuts, bright red accents, stat strips and bold CTA blocks. All artwork in this implementation is original CSS/SVG-style geometry; no stock template assets are copied into the repository.

## Certified backend binding

The frontend constants in `lib/agentseal.ts` are pinned to the certified R7 release:

- certification commit: `99e93710e2e450dd4063f9b407f861705eaf449f`
- Bradbury chain ID: `4221`
- policy: `agentseal-bradbury-v1` version `2`
- manifest: `agentseal-bradbury-manifest-v2`
- certificate TTL: `604800` seconds
- all eight deployed R7 contract addresses

The current product workbench intentionally **does not fabricate wallet or RPC results**. It exposes the exact contract/method surfaces for verification, assessment and challenge flows. Browser transport/wallet execution should be wired only after the selected GenLayer frontend SDK/RPC path is verified against the certified R7 contract ABI surface.

## Live Bradbury certificate reads

The verification tab uses `genlayer-js@1.1.8` with the SDK's `testnetBradbury` chain definition and `LATEST_FINAL` reads. Certificate lookup is read-only and targets the certified R7 `CertificateRegistry`.

The workbench also includes an injected EIP-1193 wallet transport. On explicit user action it requests an account, binds the wallet to Bradbury (chain `4221`) and constructs a GenLayer write client using the connected address and provider.

Assessment and challenge flows now expose deterministic transaction previews for the exact certified targets and methods. Preparing a preview does not sign or submit anything. A separate acknowledgement checkbox and intent-confirmation action are required, and even confirmed intent remains execution-locked in this phase.

No `writeContract` call is wired to the product surface yet. Transaction submission is added only after the preview/confirmation boundary is certified and a real Bradbury write is separately authorized.

## Run locally

```bash
npm ci
npm run dev
```

Production check:

```bash
npm run build
```
