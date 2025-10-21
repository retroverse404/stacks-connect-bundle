import express from "express";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const PORT = Number(process.env.PORT) || 5173;
const HOST = process.env.HOST || process.env.SERVER_HOST || "0.0.0.0";

app.use(express.json());
app.use(express.static("client"));
app.use("/node_modules", express.static("node_modules"));

app.get("/api/ping", (_, res) => res.json({ ok: true }));

app.post("/api/mint", (req, res) => {
  const txid = `mock-tx-${Date.now()}`;
  res.status(201).json({ ok: true, txid });
});

app.post("/api/tts", (req, res) => {
  const { text } = req.body ?? {};

  if (!text || typeof text !== "string") {
    return res.status(400).json({ ok: false, error: "text is required" });
  }

  res.json({ ok: true, audio: "/static/canned-tts.mp3" });
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
