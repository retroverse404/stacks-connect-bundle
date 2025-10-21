import express from "express";
import dotenv from "dotenv";
import fetch from "node-fetch";
import {
  AnchorMode,
  broadcastTransaction,
  makeContractCall,
  standardPrincipalCV,
  uintCV,
  validateStacksAddress,
} from "@stacks/transactions";
import { StacksMainnet, StacksTestnet } from "@stacks/network";

dotenv.config();

const app = express();
const PORT = Number(process.env.PORT) || 5173;
const HOST = process.env.HOST || process.env.SERVER_HOST || "0.0.0.0";
const GUIDE_STUB_TEXT =
  "> GUIDE: For now this is a prototype. Ask me about wallet, minting, or the explore scene.";

const DEFAULT_CONTRACT_ADDRESS = "ST2C2A6Y0Z3EXAMPLE000000000000000000";
const DEFAULT_CONTRACT_NAME = "finding-nakamoto-genesis";
const STACKS_NETWORK = (process.env.STACKS_NETWORK || "testnet").toLowerCase();
const STACKS_API_URL =
  process.env.STACKS_API_URL ||
  (STACKS_NETWORK === "mainnet"
    ? "https://stacks-node-api.mainnet.stacks.co"
    : "https://stacks-node-api.testnet.stacks.co");
const stacksNetwork =
  STACKS_NETWORK === "mainnet"
    ? new StacksMainnet({ url: STACKS_API_URL })
    : new StacksTestnet({ url: STACKS_API_URL });
const CONTRACT_ADDRESS = process.env.MINT_CONTRACT_ADDRESS || DEFAULT_CONTRACT_ADDRESS;
const CONTRACT_NAME = process.env.MINT_CONTRACT_NAME || DEFAULT_CONTRACT_NAME;
const CONTRACT_FUNCTION = process.env.MINT_FUNCTION_NAME || "mint";
const MINT_SIGNER_SECRET_KEY = process.env.MINT_SIGNER_SECRET_KEY;
const DEFAULT_FEE_RATE = Number(process.env.MINT_FEE_RATE) || 400;

app.use(express.json());
app.use(express.static("client"));
app.use("/node_modules", express.static("node_modules"));

app.get("/api/ping", (_, res) => res.json({ ok: true }));

app.post("/api/mint", async (req, res) => {
  const recipient = typeof req.body?.recipient === "string" ? req.body.recipient.trim() : "";
  const tokenIdInput = req.body?.tokenId;

  if (!recipient) {
    return res.status(400).json({ error: "recipient is required" });
  }

  if (!validateStacksAddress(recipient)) {
    return res.status(400).json({ error: "recipient must be a valid STX address" });
  }

  if (!MINT_SIGNER_SECRET_KEY) {
    return res.status(500).json({ error: "Mint signer key not configured" });
  }

  let tokenId = tokenIdInput;
  if (tokenId === undefined || tokenId === null || tokenId === "") {
    tokenId = Date.now();
  }
  if (typeof tokenId === "string") {
    tokenId = Number(tokenId);
  }

  if (!Number.isSafeInteger(tokenId) || tokenId < 0) {
    return res.status(400).json({ error: "tokenId must be a positive integer" });
  }

  try {
    const transaction = await makeContractCall({
      contractAddress: CONTRACT_ADDRESS,
      contractName: CONTRACT_NAME,
      functionName: CONTRACT_FUNCTION,
      functionArgs: [
        standardPrincipalCV(recipient),
        uintCV(BigInt(tokenId)),
      ],
      senderKey: MINT_SIGNER_SECRET_KEY,
      validateWithAbi: false,
      network: stacksNetwork,
      anchorMode: AnchorMode.Any,
      fee: BigInt(DEFAULT_FEE_RATE),
    });

    const broadcastResponse = await broadcastTransaction(transaction, stacksNetwork);

    if (typeof broadcastResponse === "string") {
      return res.status(201).json({ ok: true, txId: broadcastResponse, tokenId });
    }

    if (broadcastResponse?.txid) {
      return res.status(201).json({ ok: true, txId: broadcastResponse.txid, tokenId });
    }

    if (broadcastResponse?.error) {
      const reason = broadcastResponse?.reason || "";
      throw new Error(`${broadcastResponse.error}${reason ? `: ${reason}` : ""}`);
    }

    return res.status(502).json({ error: "Mint broadcast returned an unknown response" });
  } catch (error) {
    console.error("Mint transaction failed", error);
    return res.status(500).json({ error: error?.message || "Mint failed" });
  }
});

app.post("/api/guide", async (req, res) => {
  const message = typeof req.body?.message === "string" ? req.body.message.trim() : "";
  if (!message) {
    return res.status(400).json({ error: "message is required" });
  }

  const elizaUrl = process.env.ELIZA_API_URL;
  if (!elizaUrl) {
    // TODO: Replace stub once ElizaOS proxy starts returning { text, actions, audioUrl }.
    return res.json({ text: GUIDE_STUB_TEXT, actions: [], audioUrl: null });
  }

  try {
    const response = await fetch(elizaUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      // TODO: Update payload shape once the real Eliza OS endpoint contract is finalized.
      body: JSON.stringify({ input: message }),
    });

    if (!response.ok) {
      throw new Error(`ELIZA_API_URL responded with status ${response.status}`);
    }

    const payload = await response.json();
    // TODO: ElizaOS will eventually return { text, actions, audioUrl } directly.
    const replyCandidate =
      typeof payload?.reply === "string"
        ? payload.reply
        : typeof payload?.text === "string"
          ? payload.text
          : null;
    const reply = replyCandidate && replyCandidate.trim().length > 0
      ? replyCandidate
      : "Guide responded without text.";

    return res.json({
      text: reply,
      actions: Array.isArray(payload?.actions) ? payload.actions : [],
      audioUrl: payload?.audioUrl ?? null,
    });
  } catch (error) {
    console.error("Failed to reach Eliza guide", error);
    return res.json({
      text: "Guide link unavailable. Using local prototype responses until it comes back.",
      actions: [],
      audioUrl: null,
    });
  }
});

app.post("/api/guide/test", (_req, res) => {
  return res.json({
    text: "Test response.",
    actions: [
      { type: "open_url", label: "Open Leather", url: "https://leather.io" },
      { type: "open_route", label: "Go to Mint", screen: "MINT" },
    ],
    audioUrl: null,
  });
});

app.post("/api/tts", (req, res) => {
  const { text } = req.body ?? {};

  if (!text || typeof text !== "string") {
    return res.status(400).json({ error: "text is required" });
  }

  if (!process.env.ELEVENLABS_API_KEY) {
    return res.json({ audioUrl: null });
  }

  // TODO: Call ElevenLabs TTS, store or stream the audio, and return a URL the client can play.
  return res.json({ audioUrl: null });
});

const server = app.listen(PORT, HOST, (err) => {
  if (err) {
    console.error(`Server failed to start on http://${HOST}:${PORT}`, err);
    process.exitCode = 1;
    return;
  }
  console.log(`Server http://${HOST}:${PORT}`);
});

server.on("error", (err) => {
  console.error(`Server error on http://${HOST}:${PORT}`, err);
});

process.on("unhandledRejection", (reason) => {
  console.error("Unhandled promise rejection", reason);
});

process.on("uncaughtException", (err) => {
  console.error("Uncaught exception", err);
  process.exit(1);
});

export { app, server };
