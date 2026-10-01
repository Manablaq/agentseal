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

## Run locally

```bash
npm ci
npm run dev
```

Production check:

```bash
npm run build
```
