import path from "node:path";
import process from "node:process";
import dotenv from "dotenv";
import fetch from "node-fetch";

const envPath = process.env.DOTENV_PATH || path.resolve(process.cwd(), ".env");
dotenv.config({ path: envPath });

function getEnv(name, fallback) {
  const value = process.env[name];
  if (value === undefined || value === null || value === "") {
    if (fallback !== undefined) {
      return fallback;
    }
    throw new Error(`Set ${name} in .env before running this script`);
  }
  return value;
}

const port = Number(process.env.PORT) || 5173;
const baseUrl = (process.env.TEST_SERVER_URL || `http://${process.env.TEST_SERVER_HOST || "127.0.0.1"}:${port}`)
  .replace(/\/$/, "");

const config = {
  mintRecipient: getEnv("TEST_STX_RECIPIENT"),
  mintTokenId: Number(process.env.TEST_MINT_TOKEN_ID || Date.now()),
  storyOwner: getEnv("TEST_IP_OWNER"),
  storyTitle: process.env.TEST_IP_TITLE || "Finding Nakamoto Route Test",
  storyMetadataUri: getEnv("TEST_METADATA_URI"),
  checkoutCurrency: process.env.TEST_CHECKOUT_CURRENCY || "USD",
  checkoutAmount: Number(process.env.TEST_CHECKOUT_AMOUNT || "5"),
  checkoutEmail: getEnv("TEST_CHECKOUT_EMAIL"),
};

if (!Number.isFinite(config.checkoutAmount) || config.checkoutAmount <= 0) {
  throw new Error("TEST_CHECKOUT_AMOUNT must be a positive number");
}

async function postJson(endpoint, body) {
  const url = `${baseUrl}${endpoint}`;
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  let payload = null;
  try {
    payload = await response.json();
  } catch (error) {
    throw new Error(`Failed to parse JSON response from ${url}: ${error.message}`);
  }

  if (!response.ok) {
    throw new Error(`HTTP ${response.status} ${response.statusText} -> ${JSON.stringify(payload)}`);
  }

  if (!payload?.ok) {
    throw new Error(`Endpoint returned ok !== true -> ${JSON.stringify(payload)}`);
  }

  return payload;
}

async function run() {
  console.log(`Loaded env from ${envPath}`);
  console.log(`Testing against ${baseUrl}`);

  const tests = [
    {
      name: "POST /api/mint",
      endpoint: "/api/mint",
      body: { recipient: config.mintRecipient, tokenId: config.mintTokenId },
      successHint: (payload) => `txId=${payload.txId || "<none>"}`,
    },
    {
      name: "POST /api/story/register-ip",
      endpoint: "/api/story/register-ip",
      body: {
        ownerAddress: config.storyOwner,
        title: config.storyTitle,
        metadataUri: config.storyMetadataUri,
      },
      successHint: (payload) => `ipId=${payload.ipId || "<none>"}`,
    },
    {
      name: "POST /api/coinbase/checkout",
      endpoint: "/api/coinbase/checkout",
      body: {
        currency: config.checkoutCurrency,
        amount: config.checkoutAmount,
        email: config.checkoutEmail,
      },
      successHint: (payload) => `checkoutId=${payload.checkoutId || "<none>"}`,
    },
  ];

  const results = [];
  for (const test of tests) {
    try {
      const payload = await postJson(test.endpoint, test.body);
      const hint = typeof test.successHint === "function" ? test.successHint(payload) : "";
      console.log(`✅ ${test.name} succeeded ${hint ? `(${hint})` : ""}`.trim());
      results.push({ name: test.name, ok: true });
    } catch (error) {
      console.error(`❌ ${test.name} failed: ${error.message}`);
      results.push({ name: test.name, ok: false });
    }
  }

  const failed = results.filter((item) => !item.ok);
  if (failed.length > 0) {
    console.error(`\n${failed.length} route(s) failed. Check logs above.`);
    process.exitCode = 1;
    return;
  }

  console.log("\nAll routes responded with { ok: true } ✅");
}

run().catch((error) => {
  console.error("Route test runner crashed", error);
  process.exitCode = 1;
});
