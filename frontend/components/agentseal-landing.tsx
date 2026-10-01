"use client";

import { useMemo, useState } from "react";
import {
  AGENTSEAL_RELEASE,
  PRODUCT_ACTIONS,
  shortenAddress,
} from "@/lib/agentseal";
import {
  readCertificate,
  type AgentSealCertificate,
} from "@/lib/genlayer-read";
import {
  clearBradburyWalletClient,
  connectBradburyWallet,
  hasInjectedWallet,
} from "@/lib/genlayer-wallet";
import {
  buildAssessmentTransactionPreview,
  buildChallengeTransactionPreview,
  type AgentSealTransactionPreview,
} from "@/lib/genlayer-transaction-preview";

type Mode = keyof typeof PRODUCT_ACTIONS;

const modes: Mode[] = ["verify", "assess", "challenge"];

const proofCards = [
  {
    eyebrow: "Consensus",
    value: AGENTSEAL_RELEASE.certifiedExecution.successfulReceipts,
    label: "successful root receipts",
  },
  {
    eyebrow: "Audit",
    value: String(AGENTSEAL_RELEASE.certifiedExecution.auditedTransactions),
    label: "root + descendant tx audited",
  },
  {
    eyebrow: "Runtime",
    value: "8",
    label: "split contracts frozen",
  },
];

const flow = [
  {
    number: "01",
    title: "Bind",
    copy: "Lock the agent profile, endpoint and capability request to an immutable policy + manifest snapshot.",
  },
  {
    number: "02",
    title: "Evaluate",
    copy: "GenLayer validators evaluate the requested capability and finalize a semantic verdict under consensus.",
  },
  {
    number: "03",
    title: "Seal",
    copy: "Passing assessments can issue a time-bounded certificate tied to the exact agent binding.",
  },
  {
    number: "04",
    title: "Challenge",
    copy: "Certificates remain contestable. Upheld challenges revoke the live proof through consensus.",
  },
];

function SealMark({ compact = false }: { compact?: boolean }) {
  return (
    <span className={`seal-mark ${compact ? "seal-mark--compact" : ""}`} aria-hidden="true">
      <span className="seal-mark__core">A</span>
      <span className="seal-mark__orbit seal-mark__orbit--one" />
      <span className="seal-mark__orbit seal-mark__orbit--two" />
    </span>
  );
}

function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1200);
    } catch {
      setCopied(false);
    }
  }

  return (
    <button className="copy-button" type="button" onClick={copy} aria-label="Copy address">
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

export default function AgentSealLanding() {
  const [mode, setMode] = useState<Mode>("verify");
  const [query, setQuery] = useState("");
  const [profileDigest, setProfileDigest] = useState("");
  const [endpoint, setEndpoint] = useState("");
  const [menuOpen, setMenuOpen] = useState(false);
  const [certificate, setCertificate] = useState<AgentSealCertificate | null>(null);
  const [lookupState, setLookupState] = useState<
    "idle" | "loading" | "success" | "not-found" | "error"
  >("idle");
  const [lookupMessage, setLookupMessage] = useState("");
  const [walletState, setWalletState] = useState<
    "idle" | "connecting" | "connected" | "error"
  >("idle");
  const [walletAddress, setWalletAddress] = useState("");
  const [walletMessage, setWalletMessage] = useState(
    "Connect an injected wallet to prepare authenticated write flows.",
  );
  const [transactionPreview, setTransactionPreview] =
    useState<AgentSealTransactionPreview | null>(null);
  const [transactionPreviewMessage, setTransactionPreviewMessage] = useState("");
  const [transactionAcknowledged, setTransactionAcknowledged] = useState(false);
  const [transactionIntentConfirmed, setTransactionIntentConfirmed] = useState(false);

  const action = PRODUCT_ACTIONS[mode];

  function resetTransactionPreview() {
    setTransactionPreview(null);
    setTransactionPreviewMessage("");
    setTransactionAcknowledged(false);
    setTransactionIntentConfirmed(false);
  }

  const workbenchHint = useMemo(() => {
    if (mode === "verify") {
      return query.trim()
        ? `Ready to read certificate #${query.trim()} from the certified CertificateRegistry.`
        : "Enter a certificate ID to prepare a read-only certificate lookup.";
    }
    if (mode === "challenge") {
      if (walletState !== "connected") {
        return "Connect a Bradbury wallet, then enter a certificate ID to review the challenge transaction.";
      }
      return query.trim()
        ? `Certificate #${query.trim()} is ready for a no-submit challenge transaction preview.`
        : "Enter a certificate ID to prepare the challenge transaction preview.";
    }
    if (walletState !== "connected") {
      return "Connect a Bradbury wallet before reviewing an assessment transaction.";
    }
    if (profileDigest.trim() && endpoint.trim()) {
      return "Assessment inputs are ready for a no-submit transaction preview.";
    }
    return "Provide a 64-character lowercase profile digest and HTTPS endpoint.";
  }, [mode, query, profileDigest, endpoint, walletState]);

  function jumpToWorkbench() {
    document.getElementById("workbench")?.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  async function executeWorkbenchAction() {
    if (mode !== "verify") return;

    const value = query.trim();
    if (!value) {
      setCertificate(null);
      setLookupState("error");
      setLookupMessage("Enter a certificate ID before reading Bradbury.");
      return;
    }

    setCertificate(null);
    setLookupState("loading");
    setLookupMessage(`Reading certificate #${value} from finalized Bradbury state…`);

    try {
      const result = await readCertificate(BigInt(value));

      if (!result) {
        setLookupState("not-found");
        setLookupMessage(`Certificate #${value} does not exist in finalized Bradbury state.`);
        return;
      }

      setCertificate(result);
      setLookupState("success");
      setLookupMessage(
        `Certificate #${String(result.certificate_id)} loaded from finalized Bradbury state.`,
      );
    } catch (error) {
      setLookupState("error");
      setLookupMessage(
        error instanceof Error ? error.message : "Bradbury certificate lookup failed.",
      );
    }
  }

  async function connectWallet() {
    setWalletState("connecting");
    setWalletMessage("Requesting wallet access and Bradbury network binding…");

    try {
      if (!hasInjectedWallet()) {
        throw new Error("No injected EIP-1193 wallet was detected.");
      }

      const connection = await connectBradburyWallet();
      setWalletAddress(connection.address);
      setWalletState("connected");
      setWalletMessage(
        `Connected to GenLayer Testnet Bradbury / chain ${connection.chainId}.`,
      );
    } catch (error) {
      clearBradburyWalletClient();
      setWalletAddress("");
      setWalletState("error");
      setWalletMessage(
        error instanceof Error ? error.message : "Wallet connection failed.",
      );
    }
  }

  function disconnectWallet() {
    clearBradburyWalletClient();
    setWalletAddress("");
    setWalletState("idle");
    setWalletMessage("Wallet transport cleared locally. No transaction was submitted.");
    resetTransactionPreview();
  }

  function selectMode(nextMode: Mode) {
    setMode(nextMode);
    resetTransactionPreview();
  }

  function prepareTransactionPreview() {
    if (mode === "verify") return;

    if (walletState !== "connected" || !walletAddress) {
      setTransactionPreview(null);
      setTransactionPreviewMessage("Connect a Bradbury wallet before reviewing this transaction.");
      setTransactionAcknowledged(false);
      setTransactionIntentConfirmed(false);
      return;
    }

    try {
      const preview =
        mode === "assess"
          ? buildAssessmentTransactionPreview({
              account: walletAddress,
              profileDigest,
              endpoint,
            })
          : buildChallengeTransactionPreview({
              account: walletAddress,
              certificateId: query,
            });

      setTransactionPreview(preview);
      setTransactionPreviewMessage(
        "Review every field below. This preview cannot submit or sign a transaction.",
      );
      setTransactionAcknowledged(false);
      setTransactionIntentConfirmed(false);
    } catch (error) {
      setTransactionPreview(null);
      setTransactionPreviewMessage(
        error instanceof Error ? error.message : "Transaction preview could not be prepared.",
      );
      setTransactionAcknowledged(false);
      setTransactionIntentConfirmed(false);
    }
  }

  function confirmTransactionIntent() {
    if (!transactionPreview || !transactionAcknowledged) return;

    setTransactionIntentConfirmed(true);
    setTransactionPreviewMessage(
      "Intent confirmed locally. No transaction was submitted; execution remains locked.",
    );
  }

  return (
    <main>
      <header className="site-header">
        <a href="#top" className="brand" aria-label="AgentSeal home">
          <SealMark compact />
          <span>AGENT<span className="accent-text">SEAL</span></span>
        </a>

        <nav className={`desktop-nav ${menuOpen ? "desktop-nav--open" : ""}`}>
          <a href="#protocol" onClick={() => setMenuOpen(false)}>Protocol</a>
          <a href="#proof" onClick={() => setMenuOpen(false)}>Proof</a>
          <a href="#workbench" onClick={() => setMenuOpen(false)}>Workbench</a>
          <a href="#contracts" onClick={() => setMenuOpen(false)}>Contracts</a>
        </nav>

        <button className="header-cta" type="button" onClick={jumpToWorkbench}>
          Open verifier
        </button>

        <button
          className="menu-button"
          type="button"
          aria-label="Toggle navigation"
          aria-expanded={menuOpen}
          onClick={() => setMenuOpen((value) => !value)}
        >
          <span />
          <span />
        </button>
      </header>

      <section className="hero" id="top">
        <div className="hero-grid hero-grid--background" aria-hidden="true" />
        <div className="hero-copy">
          <div className="eyebrow-row">
            <span className="eyebrow-dot" />
            Certified on {AGENTSEAL_RELEASE.network}
          </div>
          <h1>
            PROVE THE <span className="accent-text">AGENT.</span>
            <br />
            TRUST THE <span className="outline-text">CAPABILITY.</span>
          </h1>
          <p className="hero-lede">
            AgentSeal is proof-of-capability infrastructure for autonomous agents — immutable policy bindings,
            semantic evaluation, time-bounded certificates and consensus-backed challenges.
          </p>
          <div className="hero-actions">
            <button className="button button--primary" type="button" onClick={jumpToWorkbench}>
              Verify an agent
              <span aria-hidden="true">↗</span>
            </button>
            <a className="button button--ghost" href="#protocol">
              See how it works
            </a>
          </div>
          <div className="hero-proofline">
            <span>R7</span>
            <span>Policy v{AGENTSEAL_RELEASE.policyVersion}</span>
            <span>{AGENTSEAL_RELEASE.certificateTtlSeconds / 86400}-day TTL</span>
            <span>Chain {AGENTSEAL_RELEASE.chainId}</span>
          </div>
        </div>

        <div className="hero-art" aria-label="AgentSeal proof network illustration">
          <div className="hero-art__slash hero-art__slash--top" />
          <div className="hero-art__slash hero-art__slash--bottom" />
          <div className="hero-art__mesh" />
          <div className="hero-art__seal">
            <SealMark />
          </div>
          <div className="signal-card signal-card--top">
            <span className="signal-card__index">01</span>
            <strong>BOUND</strong>
            <small>policy + manifest</small>
          </div>
          <div className="signal-card signal-card--bottom">
            <span className="status-pulse" />
            <strong>FINALIZED</strong>
            <small>consensus result</small>
          </div>
          <div className="hero-art__caption">PROOF / CAPABILITY / CONSENSUS</div>
        </div>
      </section>

      <section className="proof-strip" id="proof">
        {proofCards.map((card) => (
          <article className="proof-card" key={card.eyebrow}>
            <span>{card.eyebrow}</span>
            <strong>{card.value}</strong>
            <p>{card.label}</p>
          </article>
        ))}
        <article className="proof-card proof-card--accent">
          <span>Release</span>
          <strong>R7</strong>
          <p>certified backend surface</p>
        </article>
      </section>

      <section className="protocol-section" id="protocol">
        <div className="section-heading">
          <p className="section-kicker">THE PROTOCOL</p>
          <h2>From claim to <span className="accent-text">cryptographic context.</span></h2>
          <p>
            A certificate is not a badge. It is a verifiable snapshot of what an agent demonstrated, under which
            policy, against which immutable manifest, and when that proof expires.
          </p>
        </div>

        <div className="flow-grid">
          {flow.map((item) => (
            <article className="flow-card" key={item.number}>
              <span className="flow-card__number">{item.number}</span>
              <div className="flow-card__rule" />
              <h3>{item.title}</h3>
              <p>{item.copy}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="workbench-section" id="workbench">
        <div className="workbench-intro">
          <p className="section-kicker">LIVE PRODUCT SURFACE</p>
          <h2>AgentSeal <span className="accent-text">Workbench.</span></h2>
          <p>
            The interface is already bound to the certified R7 identities. Read/write transport is intentionally
            separated so no frontend mock can masquerade as a chain result.
          </p>

          <div className="release-badge">
            <span className="status-pulse" />
            <div>
              <strong>Certified release</strong>
              <small>{AGENTSEAL_RELEASE.manifestId}</small>
            </div>
          </div>

          <div
            className={`wallet-transport wallet-transport--${walletState}`}
            data-testid="wallet-transport"
            data-state={walletState}
          >
            <div className="wallet-transport__status">
              <span className="status-pulse" />
              <div>
                <strong>
                  {walletState === "connected"
                    ? "Bradbury wallet connected"
                    : "Wallet transport"}
                </strong>
                <small data-testid="wallet-message">{walletMessage}</small>
              </div>
            </div>

            {walletAddress ? (
              <code data-testid="wallet-address">
                {shortenAddress(walletAddress, 8, 6)}
              </code>
            ) : null}

            <button
              className="wallet-transport__button"
              type="button"
              data-testid="wallet-connect"
              onClick={walletState === "connected" ? disconnectWallet : connectWallet}
              disabled={walletState === "connecting"}
            >
              {walletState === "connecting"
                ? "Connecting…"
                : walletState === "connected"
                  ? "Disconnect"
                  : "Connect wallet"}
            </button>
          </div>
        </div>

        <div className="workbench-panel">
          <div className="mode-switcher" role="tablist" aria-label="AgentSeal product action">
            {modes.map((item) => (
              <button
                key={item}
                type="button"
                role="tab"
                aria-selected={mode === item}
                className={mode === item ? "is-active" : ""}
                onClick={() => selectMode(item)}
              >
                {PRODUCT_ACTIONS[item].label}
              </button>
            ))}
          </div>

          <div className="workbench-body">
            <div className="contract-callout">
              <span>{action.contract}</span>
              <code>{action.method}()</code>
            </div>

            {mode === "assess" ? (
              <div className="field-stack">
                <label>
                  Agent profile digest
                  <input
                    value={profileDigest}
                    onChange={(event) => {
                      setProfileDigest(event.target.value);
                      resetTransactionPreview();
                    }}
                    placeholder="64 lowercase hex characters"
                  />
                </label>
                <label>
                  Agent endpoint
                  <input
                    value={endpoint}
                    onChange={(event) => {
                      setEndpoint(event.target.value);
                      resetTransactionPreview();
                    }}
                    placeholder="https://agent.example/api"
                  />
                </label>
              </div>
            ) : (
              <label className="field-stack">
                {mode === "verify" ? "Certificate ID" : "Certificate ID to challenge"}
                <input
                  inputMode="numeric"
                  value={query}
                  onChange={(event) => {
                    setQuery(event.target.value.replace(/[^0-9]/g, ""));
                    resetTransactionPreview();
                  }}
                  placeholder="e.g. 42"
                />
              </label>
            )}

            <div className="workbench-status">
              <span className="workbench-status__marker">↳</span>
              <p>{workbenchHint}</p>
            </div>

            <button
              className="button button--primary button--wide"
              type="button"
              data-testid="workbench-primary-action"
              onClick={mode === "verify" ? executeWorkbenchAction : prepareTransactionPreview}
              disabled={
                mode === "verify"
                  ? lookupState === "loading" || !query.trim()
                  : walletState !== "connected" ||
                    (mode === "assess"
                      ? !profileDigest.trim() || !endpoint.trim()
                      : !query.trim())
              }
            >
              {mode === "verify"
                ? lookupState === "loading"
                  ? "Reading Bradbury…"
                  : "Verify certificate"
                : mode === "assess"
                  ? "Review assessment transaction"
                  : "Review challenge transaction"}
              <span aria-hidden="true">↗</span>
            </button>

            {mode === "verify" && lookupState !== "idle" ? (
              <div
                className={`live-read live-read--${lookupState}`}
                data-testid="live-certificate-result"
                data-state={lookupState}
              >
                <div className="live-read__heading">
                  <span>Bradbury / latest-final</span>
                  <strong>{lookupState === "success" ? "LIVE READ" : lookupState.toUpperCase()}</strong>
                </div>

                <p className="live-read__message">{lookupMessage}</p>

                {certificate ? (
                  <>
                    <div className="live-read__certificate">
                      <span>Certificate #{String(certificate.certificate_id)}</span>
                      <strong>{certificate.effective_status}</strong>
                    </div>
                    <dl className="live-read__grid">
                      <div>
                        <dt>Policy</dt>
                        <dd>{certificate.policy_id} / v{String(certificate.policy_version)}</dd>
                      </div>
                      <div>
                        <dt>Capability</dt>
                        <dd>{certificate.capability_id}</dd>
                      </div>
                      <div>
                        <dt>Subject</dt>
                        <dd>{shortenAddress(certificate.subject_wallet, 8, 6)}</dd>
                      </div>
                      <div>
                        <dt>Manifest</dt>
                        <dd>{certificate.manifest_id}</dd>
                      </div>
                      <div>
                        <dt>Expires</dt>
                        <dd>{String(certificate.expires_at)}</dd>
                      </div>
                      <div>
                        <dt>Binding</dt>
                        <dd>{certificate.binding_key}</dd>
                      </div>
                    </dl>
                  </>
                ) : null}
              </div>
            ) : null}

            {mode !== "verify" && transactionPreviewMessage ? (
              <div
                className={`transaction-preview ${
                  transactionIntentConfirmed ? "transaction-preview--confirmed" : ""
                }`}
                data-testid="transaction-preview"
                data-state={transactionIntentConfirmed ? "confirmed" : transactionPreview ? "review" : "error"}
              >
                <div className="transaction-preview__heading">
                  <span>Bradbury / transaction preview</span>
                  <strong>NO SUBMIT</strong>
                </div>

                <p>{transactionPreviewMessage}</p>

                {transactionPreview ? (
                  <>
                    <dl className="transaction-preview__grid">
                      <div>
                        <dt>Account</dt>
                        <dd>{transactionPreview.account}</dd>
                      </div>
                      <div>
                        <dt>Chain</dt>
                        <dd>{transactionPreview.chainId}</dd>
                      </div>
                      <div>
                        <dt>Contract</dt>
                        <dd>{transactionPreview.contract}</dd>
                      </div>
                      <div>
                        <dt>Target</dt>
                        <dd>{transactionPreview.target}</dd>
                      </div>
                      <div>
                        <dt>Method</dt>
                        <dd>{transactionPreview.functionName}</dd>
                      </div>
                      <div>
                        <dt>Value</dt>
                        <dd>{transactionPreview.value}</dd>
                      </div>
                      <div className="transaction-preview__args">
                        <dt>Arguments</dt>
                        <dd>{JSON.stringify(transactionPreview.args)}</dd>
                      </div>
                    </dl>

                    <label className="transaction-preview__ack">
                      <input
                        type="checkbox"
                        data-testid="transaction-confirmation-checkbox"
                        checked={transactionAcknowledged}
                        onChange={(event) => {
                          setTransactionAcknowledged(event.target.checked);
                          setTransactionIntentConfirmed(false);
                        }}
                      />
                      <span>{transactionPreview.confirmationText}</span>
                    </label>

                    <button
                      className="transaction-preview__confirm"
                      type="button"
                      data-testid="confirm-transaction-intent"
                      disabled={!transactionAcknowledged || transactionIntentConfirmed}
                      onClick={confirmTransactionIntent}
                    >
                      {transactionIntentConfirmed
                        ? "Intent confirmed / execution locked"
                        : "Confirm transaction intent"}
                    </button>
                  </>
                ) : null}
              </div>
            ) : null}

            <p className="workbench-note">
              Certificate verification reads finalized Bradbury state directly through the verified GenLayer SDK.
              Assessment and challenge flows now expose exact transaction previews and explicit intent confirmation,
              but no signing or transaction submission code exists in this phase.
            </p>
          </div>
        </div>
      </section>

      <section className="contracts-section" id="contracts">
        <div className="section-heading section-heading--contracts">
          <p className="section-kicker">R7 DEPLOYMENT</p>
          <h2>Eight contracts. <span className="outline-text outline-text--light">One proof surface.</span></h2>
          <p>
            Every address below is pinned to the certified Bradbury release. The frontend reads these constants from
            one immutable configuration module.
          </p>
        </div>

        <div className="contract-grid">
          {Object.entries(AGENTSEAL_RELEASE.contracts).map(([name, address]) => (
            <article className="contract-card" key={name}>
              <div>
                <span className="contract-card__name">{name.replace(/([A-Z])/g, " $1").trim()}</span>
                <strong>{shortenAddress(address)}</strong>
              </div>
              <CopyButton value={address} />
            </article>
          ))}
        </div>
      </section>

      <section className="final-cta">
        <div className="final-cta__copy">
          <p className="section-kicker">AUTONOMOUS DOESN'T MEAN UNACCOUNTABLE</p>
          <h2>Make capability <span className="accent-text">provable.</span></h2>
        </div>
        <button className="button button--light" type="button" onClick={jumpToWorkbench}>
          Open AgentSeal
          <span aria-hidden="true">↗</span>
        </button>
      </section>

      <footer className="site-footer">
        <a href="#top" className="brand brand--footer">
          <SealMark compact />
          <span>AGENT<span className="accent-text">SEAL</span></span>
        </a>
        <p>Proof-of-capability infrastructure secured by GenLayer consensus.</p>
        <div className="footer-meta">
          <span>R7 / Bradbury</span>
          <span>Policy v{AGENTSEAL_RELEASE.policyVersion}</span>
          <span>Chain {AGENTSEAL_RELEASE.chainId}</span>
        </div>
      </footer>
    </main>
  );
}
