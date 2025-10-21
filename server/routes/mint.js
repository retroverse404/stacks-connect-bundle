import express from "express";
const router = express.Router();
router.post("/", async (req, res) => {
  const { address, state } = req.body;
  console.log("Mint stub:", address, state);
  res.json({ status: "ok", txid: "testnet-tx-001" });
});
export default router;
