import express from "express";
import { registerIpAsset } from "../services/story.service.js";

const router = express.Router();

router.post("/register-ip", async (req, res) => {
  const ownerAddress = typeof req.body?.ownerAddress === "string" ? req.body.ownerAddress.trim() : "";
  const title = typeof req.body?.title === "string" ? req.body.title.trim() : "";
  const metadataUri = typeof req.body?.metadataUri === "string" ? req.body.metadataUri.trim() : "";

  if (!ownerAddress) {
    return res.status(400).json({ error: "ownerAddress is required" });
  }

  if (!title) {
    return res.status(400).json({ error: "title is required" });
  }

  if (!metadataUri) {
    return res.status(400).json({ error: "metadataUri is required" });
  }

  try {
    const result = await registerIpAsset({ ownerAddress, title, metadataUri });
    return res.status(201).json({ ok: true, ipId: result.ipId, txId: result.txId });
  } catch (error) {
    console.error("Story register-ip failed", error);
    return res.status(500).json({ error: error?.message || "Unable to register IP asset" });
  }
});

export default router;
