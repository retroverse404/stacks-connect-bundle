import pkg from "@story-protocol/core-sdk";

const { StoryClient, StoryConfig, StoryNetwork } = pkg;

let storyClientPromise = null;

function requireEnv(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is required for Story Protocol integration`);
  }
  return value;
}

async function getStoryClient() {
  if (!storyClientPromise) {
    const accessKey = requireEnv("STORY_ACCESS_KEY");
    const secretKey = requireEnv("STORY_SECRET_KEY");
    const networkName = (process.env.STORY_NETWORK || "testnet").toLowerCase();

    const config = new StoryConfig({
      accessKey,
      secretKey,
      network: networkName === "mainnet" ? StoryNetwork.Mainnet : StoryNetwork.Testnet,
    });

    storyClientPromise = StoryClient.new(config);
  }
  return storyClientPromise;
}

export async function registerIpAsset({ ownerAddress, title, metadataUri }) {
  const client = await getStoryClient();
  const response = await client.ipAsset.registerIpAsset({
    owner: ownerAddress,
    title,
    metadataUri,
  });

  return {
    ipId: response?.ipId || null,
    txId: response?.txId || response?.transactionHash || null,
  };
}
