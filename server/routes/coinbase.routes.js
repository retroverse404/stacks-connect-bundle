import express from "express";
import { createCheckout } from "../services/coinbase.service.js";

const router = express.Router();

router.post("/checkout", async (req, res) => {
  const currency = typeof req.body?.currency === "string" ? req.body.currency.trim() : "";
  const amount = Number(req.body?.amount);
  const email = typeof req.body?.email === "string" ? req.body.email.trim() : "";

  if (!currency) {
    return res.status(400).json({ error: "currency is required" });
  }

  if (!Number.isFinite(amount) || amount <= 0) {
    return res.status(400).json({ error: "amount must be a positive number" });
  }

  if (!email) {
    return res.status(400).json({ error: "email is required" });
  }

  try {
    const session = await createCheckout({ amount, currency, email });
    return res.status(201).json({ ok: true, checkoutId: session.checkoutId, hostedUrl: session.hostedUrl });
  } catch (error) {
    console.error("Coinbase checkout failed", error);
    return res.status(500).json({ error: error?.message || "Unable to create checkout session" });
  }
});

export default router;
