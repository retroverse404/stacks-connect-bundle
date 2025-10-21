import { Coinbase } from "@coinbase/coinbase-sdk";

let coinbaseClientPromise = null;

function requireEnv(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is required for Coinbase checkout`);
  }
  return value;
}

async function getCoinbaseClient() {
  if (!coinbaseClientPromise) {
    const apiKeyName = requireEnv("CDP_API_KEY_NAME");
    const privateKey = requireEnv("CDP_PRIVATE_KEY");
    const projectId = requireEnv("CDP_PROJECT_ID");

    coinbaseClientPromise = Coinbase.configure({
      apiKeyName,
      privateKey,
      projectId,
    });
  }
  return coinbaseClientPromise;
}

export async function createCheckout({ amount, currency, email }) {
  const client = await getCoinbaseClient();
  const session = await client.checkouts.create({
    amount: { amount: amount.toString(), currency },
    customerEmail: email,
  });

  return {
    checkoutId: session?.id || null,
    hostedUrl: session?.hostedUrl || session?.url || null,
  };
}
