import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";

const root = process.cwd();
const packagedVerifier = process.env.WARPTWEET_PUBLIC_RELEASE_VERIFIER;
const verifierCommand = packagedVerifier || "go";
const verifierArguments = packagedVerifier ? [] : ["run", "./cmd/verify-public-release"];
const goVerify = spawnSync(verifierCommand, verifierArguments, {
  cwd: root,
  encoding: "utf8",
  env: {
    ...process.env,
    GOCACHE: process.env.GOCACHE || resolve(tmpdir(), "warptweet-go-build")
  }
});
if (goVerify.status !== 0) {
  throw new Error(
    `authoritative public-release validator failed: ${goVerify.error?.message || goVerify.stderr || goVerify.stdout || "exit " + goVerify.status}`
  );
}
const brandSource = await readFile(resolve(root, "src/lib/brand.ts"), "utf8");
const caddyfile = await readFile(resolve(root, "Caddyfile"), "utf8");
const releaseGate = JSON.parse(
  await readFile(resolve(root, "packaging/evidence/public-release.json"), "utf8")
);
const indexHtml = await readFile(resolve(root, "dist/index.html"), "utf8");

if (releaseGate.kind !== "warptweet.public-release-gate" || releaseGate.schema_version !== 2) {
  throw new Error("public release gate document is invalid");
}
if (releaseGate.links?.evidence_checklist !== "packaging/evidence/checklist-v3.json") {
  throw new Error("public release gate must point at the v3 evidence checklist");
}
if (!caddyfile.includes("script-src 'self'")) {
  throw new Error("Caddy CSP must allow Astro's same-origin copy-control script");
}

const llms = await readFile(resolve(root, "dist/llms.txt"), "utf8");
if (!llms.includes("WarpTweet gives a developer or agent one local service socket")) {
  throw new Error("llms.txt must publish the product thesis");
}

function isConnectNextCommand(value) {
  if (typeof value !== "string") {
    return false;
  }
  const tokens = value.trim().split(/\s+/);
  return tokens[0] === "warptweet" && tokens[1] === "connect";
}

const nextCommandRejects = [
  ["prefixed text", "please run warptweet connect <invite-file>"],
  ["incorrect action", "warptweet enroll <invite-file>"],
  ["non-string", 12]
];
for (const [label, value] of nextCommandRejects) {
  if (isConnectNextCommand(value)) {
    throw new Error(`next_command validator accepted ${label}`);
  }
}

if (!isConnectNextCommand(releaseGate.next_command)) {
  throw new Error("public-release next_command must be the connect action");
}

if (!indexHtml.includes("warptweet connect --listen-port 15432 staging-db.wtinvite")) {
  throw new Error("website connect example must put flags before the invite path");
}
if (!indexHtml.includes("One private service. On <em>localhost.")) {
  throw new Error("website hero must lead with the localhost service outcome");
}
if (indexHtml.includes("—")) {
  throw new Error("website customer copy must not use em dashes");
}
for (const landmark of ['<html lang="en">', 'href="#main-content"', 'id="main-content"', 'aria-live="polite"']) {
  if (!indexHtml.includes(landmark)) {
    throw new Error(`website omits required accessibility structure: ${landmark}`);
  }
}
const headings = indexHtml.match(/<h1(?:\s|>)/g) ?? [];
if (headings.length !== 1) {
  throw new Error(`website must render exactly one h1, found ${headings.length}`);
}
const ids = [...indexHtml.matchAll(/\sid="([^"]+)"/g)].map((match) => match[1]);
if (new Set(ids).size !== ids.length) {
  throw new Error("website renders duplicate element IDs");
}
const idSet = new Set(ids);
for (const match of indexHtml.matchAll(/\shref="#([^"]*)"/g)) {
  if (!match[1] || !idSet.has(match[1])) {
    throw new Error(`website renders a broken in-page link: #${match[1]}`);
  }
}
for (const productFact of ["Apple Silicon Mac", "Linux host", "AMD64", "ARM64"]) {
  if (!indexHtml.includes(productFact)) {
    throw new Error(`website omits first-edition support fact: ${productFact}`);
  }
}
if (!indexHtml.includes("chacha20-poly1305@openssh.com") || indexHtml.includes("AES-256-GCM")) {
  throw new Error("website must render the exact Profile v1 cipher without alternatives");
}

if (!releaseGate.qualification_complete) {
  throw new Error("website source must not claim incomplete first-edition qualification");
}
if (!indexHtml.includes(releaseGate.qualification_message)) {
  throw new Error("website must render the package qualification state");
}

if (!releaseGate.public_distribution_ready) {
  if (!indexHtml.includes(releaseGate.distribution_message)) {
    throw new Error("website must show the distribution state while public packages are unavailable");
  }
  if (indexHtml.includes('class="install-command"') || indexHtml.includes("data-install-command")) {
    throw new Error("website must not render an install-command block while CTA is dark");
  }
  if (indexHtml.includes("data-copy-command=")) {
    throw new Error("website must not expose a copy control for install commands while CTA is dark");
  }
  if (indexHtml.includes(releaseGate.homebrew_command)) {
    throw new Error("website must not expose the Homebrew install command before public distribution is ready");
  }
} else {
  if (!releaseGate.required_evidence_document || !releaseGate.required_distribution_evidence_document) {
    throw new Error("public distribution requires qualification and clean-install evidence");
  }
  if (!indexHtml.includes(releaseGate.homebrew_command)) {
    throw new Error("enabled Homebrew CTA must render the reviewed install command");
  }
  const nextCommandHtml = releaseGate.next_command
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
  if (!indexHtml.includes(releaseGate.next_command) && !indexHtml.includes(nextCommandHtml)) {
    throw new Error("enabled Homebrew CTA must render the enroll next action");
  }
  if (indexHtml.includes("/docs/package-interop")) {
    throw new Error("enabled Homebrew CTA must not link to a nonexistent /docs/package-interop route");
  }
}

function sourceConstant(name) {
  const match = brandSource.match(new RegExp(`export const ${name} = "([^"]+)";`));
  if (!match) {
    throw new Error(`missing brand source constant ${name}`);
  }
  return match[1];
}

const geometry = {
  plate: sourceConstant("brandPlatePath"),
  route: sourceConstant("brandRoutePath"),
  endpoints: sourceConstant("brandEndpointPath"),
  favicon: sourceConstant("faviconRoutePath")
};

const outputs = [
  ["brand/warptweet-mark.svg", [geometry.plate, geometry.route, geometry.endpoints, "#17201D", "#1F6258"]],
  ["brand/warptweet-mark-mono.svg", [geometry.plate, geometry.route, geometry.endpoints, "#000000"]],
  ["brand/warptweet-mark-reverse.svg", [geometry.plate, geometry.route, geometry.endpoints, "#F4F0E7", "#77BEB4"]],
  ["favicon.svg", [geometry.favicon, "#F4F0E7", "#17201D", 'stroke-linejoin="bevel"']]
];

const forbidden = [
  "<script",
  "<foreignObject",
  "<image",
  "<text",
  "<style",
  "href=",
  "xlink:",
  "data:",
  "javascript:",
  "onload=",
  "onclick=",
  "url("
];

for (const [relativePath, required] of outputs) {
  const output = await readFile(resolve(root, "dist", relativePath), "utf8");
  if (!output.startsWith("<svg ") || !output.endsWith("</svg>\n")) {
    throw new Error(`${relativePath} is not a canonical SVG document`);
  }
  for (const value of required) {
    if (!output.includes(value)) {
      throw new Error(`${relativePath} omits required brand value ${value}`);
    }
  }
  for (const value of forbidden) {
    if (output.includes(value)) {
      throw new Error(`${relativePath} contains forbidden SVG content ${value}`);
    }
  }
}

const favicon = await readFile(resolve(root, "dist/favicon.svg"), "utf8");
if (!favicon.includes('<rect width="16" height="16" rx="2" fill="#F4F0E7" />')) {
  throw new Error("favicon does not provide its own contrast-preserving matte tile");
}
