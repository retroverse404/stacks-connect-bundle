#!/usr/bin/env node
import { spawn } from 'child_process';
import fs from 'fs/promises';
import { existsSync, readFileSync, statSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '..');
const bundlePath = path.join(repoRoot, 'client', 'modules', 'vendor', 'stacks-connect.bundle.js');
const importMapPath = path.join(repoRoot, 'client', 'import-map.json');

async function runRollup() {
  await new Promise((resolve, reject) => {
    const child = spawn('npx', ['rollup', '-c'], {
      cwd: repoRoot,
      stdio: 'inherit',
      env: { ...process.env, NODE_ENV: process.env.NODE_ENV || 'development' },
    });
    child.on('exit', (code) => {
      if (code === 0) resolve();
      else reject(new Error(`Rollup exited with code ${code}`));
    });
    child.on('error', reject);
  });

  if (!existsSync(bundlePath)) {
    throw new Error(`Expected bundle at ${bundlePath} was not produced`);
  }
}

async function collectModuleFiles(dir) {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  const files = await Promise.all(
    entries.map(async (entry) => {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        return collectModuleFiles(fullPath);
      }
      if (entry.isFile() && /\.(mjs|js)$/i.test(entry.name)) {
        return [fullPath];
      }
      return [];
    })
  );
  return files.flat();
}

function matchSpecifiers(code, regex) {
  const matches = [];
  let match;
  while ((match = regex.exec(code))) {
    matches.push(match[1]);
  }
  return matches;
}

function locatePackage(spec) {
  if (spec.startsWith('@')) {
    const [scope, name, ...rest] = spec.split('/');
    return {
      dir: path.join(repoRoot, 'node_modules', scope, name),
      subpath: rest.length ? '/' + rest.join('/') : '',
    };
  }
  const [name, ...rest] = spec.split('/');
  return {
    dir: path.join(repoRoot, 'node_modules', name),
    subpath: rest.length ? '/' + rest.join('/') : '',
  };
}

function pickExportPath(pkgJson, subpath) {
  const pick = (entry) => {
    if (!entry) return null;
    if (typeof entry === 'string') return entry;
    if (typeof entry.import === 'string') return entry.import;
    if (typeof entry.browser === 'string') return entry.browser;
    if (typeof entry.module === 'string') return entry.module;
    if (typeof entry.default === 'string') return entry.default;
    if (typeof entry.require === 'string') return entry.require;
    return null;
  };

  if (!subpath) {
    return (
      pick(pkgJson.exports?.['.']) ||
      (typeof pkgJson.module === 'string' ? pkgJson.module : null) ||
      (typeof pkgJson.browser === 'string' ? pkgJson.browser : null) ||
      (typeof pkgJson.main === 'string' ? pkgJson.main : null)
    );
  }

  const key = `.${subpath}`;
  return pick(pkgJson.exports?.[key]) || subpath;
}

function resolveBareSpecifier(spec) {
  const { dir, subpath } = locatePackage(spec);
  const pkgPath = path.join(dir, 'package.json');
  if (!existsSync(pkgPath)) return null;
  let rel;
  try {
    const pkgJson = JSON.parse(readFileSync(pkgPath, 'utf8'));
    rel = pickExportPath(pkgJson, subpath);
  } catch (err) {
    console.warn(`bundle-stacks-connect: unable to parse ${pkgPath}: ${err.message}`);
    return null;
  }
  if (!rel || typeof rel !== 'string') return null;
  if (rel.startsWith('./')) rel = rel.slice(2);
  if (!rel.startsWith('/')) rel = `/${rel}`;
  const candidate = path.join(dir, rel);
  if (existsSync(candidate) && statSync(candidate).isFile()) {
    return candidate;
  }
  return null;
}

async function generateImportMap() {
  const modulesDir = path.join(repoRoot, 'client', 'modules');
  const files = await collectModuleFiles(modulesDir);
  const ignorePrefixes = [
    path.join(modulesDir, 'vendor', '@stacks') + path.sep,
    path.join(modulesDir, 'vendor', '@reown') + path.sep,
  ];
  const bareSpecifiers = new Set();
  const staticImport = /(?:import|export)\s+[^;]*?from\s*['\"]([^'\"]+)['\"]/g;
  const dynamicImport = /import\s*\(\s*['\"]([^'\"]+)['\"]\s*\)/g;

  for (const file of files) {
    if (file === bundlePath) continue;
    if (ignorePrefixes.some((prefix) => file.startsWith(prefix))) continue;
    const code = readFileSync(file, 'utf8');
    const specs = [
      ...matchSpecifiers(code, staticImport),
      ...matchSpecifiers(code, dynamicImport),
    ];
    specs.forEach((spec) => {
      if (!spec) return;
      if (spec.startsWith('.') || spec.startsWith('/') || spec.startsWith('data:')) return;
      bareSpecifiers.add(spec);
    });
  }

  const entries = [];
  const unresolved = [];
  for (const spec of [...bareSpecifiers].sort()) {
    const resolved = resolveBareSpecifier(spec);
    if (resolved) {
      const url = '/' + path.relative(repoRoot, resolved).replace(/\\/g, '/');
      entries.push([spec, url]);
    } else {
      unresolved.push(spec);
    }
  }

  await fs.writeFile(importMapPath, JSON.stringify(Object.fromEntries(entries), null, 2));

  if (entries.length) {
    console.log(`bundle-stacks-connect: wrote import map with ${entries.length} entries -> ${importMapPath}`);
  } else {
    console.log('bundle-stacks-connect: wrote empty import map');
  }

  if (unresolved.length) {
    console.warn('bundle-stacks-connect: unresolved specifiers:', unresolved.join(', '));
  } else {
    console.log('bundle-stacks-connect: no unresolved specifiers');
  }
}

async function main() {
  await runRollup();
  await generateImportMap();
}

main().catch((err) => {
  console.error('bundle-stacks-connect: fatal', err);
  process.exit(1);
});
