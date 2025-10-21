import express from "express";
const router = express.Router();
router.post("/", (req, res) => res.json({ audioUrl: "/assets/sample.mp3" }));
export default router;
