#!/usr/bin/env node
import { promises as fs } from "fs";
import path from "path";

const [, , rawSlug, ...titleParts] = process.argv;

if (!rawSlug) {
  console.error("Usage: node scripts/new-spec.mjs <slug> [Title words...]");
  process.exit(1);
}

const safeSlug = rawSlug
  .toLowerCase()
  .replace(/[^a-z0-9-]/g, "-")
  .replace(/-+/g, "-")
  .replace(/^-|-$/g, "");

if (!safeSlug) {
  console.error("Provide a slug using letters, numbers, or dashes.");
  process.exit(1);
}

const title = titleParts.length
  ? titleParts.join(" ")
  : safeSlug
      .split("-")
      .map((segment) => segment.charAt(0).toUpperCase() + segment.slice(1))
      .join(" ");

const today = new Date().toISOString().slice(0, 10);
const specName = `${today}-${safeSlug}.md`;
const specsDir = path.resolve(process.cwd(), "specs");
const templatePath = path.resolve(specsDir, "templates", "feature-spec-template.md");
const targetPath = path.resolve(specsDir, specName);

async function ensureTemplateExists() {
  try {
    await fs.access(templatePath);
  } catch (error) {
    console.error(`Template not found at ${templatePath}`);
    process.exit(1);
  }
}

async function ensureTargetAbsent() {
  try {
    await fs.access(targetPath);
    console.error(`Spec already exists: ${targetPath}`);
    process.exit(1);
  } catch (error) {
    // expected when file does not exist
  }
}

async function buildSpec() {
  await ensureTemplateExists();
  await ensureTargetAbsent();

  const raw = await fs.readFile(templatePath, "utf8");
  const populated = raw
    .replace(/{{TITLE}}/g, title)
    .replace(/{{DATE}}/g, today)
    .replace(/{{SLUG}}/g, safeSlug)
    .replace(/{{OWNER}}/g, "TBD")
    .replace(/{{PROBLEM}}/g, "TBD")
    .replace(/{{AUDIENCE}}/g, "TBD")
    .replace(/{{RELATED}}/g, "TBD");

  await fs.writeFile(targetPath, populated, "utf8");
  console.log(`Created ${path.relative(process.cwd(), targetPath)}`);
}

buildSpec().catch((error) => {
  console.error(error);
  process.exit(1);
});
