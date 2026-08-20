import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const root = process.cwd();
const brandSource = await readFile(resolve(root, "src/lib/brand.ts"), "utf8");
const releaseGate = JSON.parse(
  await readFile(resolve(root, "packaging/evidence/public-release.json"), "utf8")
);
const indexHtml = await readFile(resolve(root, "dist/index.html"), "utf8");

if (releaseGate.kind !== "warptweet.public-release-gate" || releaseGate.schema_version !== 1) {
  throw new Error("public release gate document is invalid");
}
if (releaseGate.links?.evidence_checklist !== "packaging/evidence/checklist-v2.json") {
  throw new Error("public release gate must point at the v2 evidence checklist");
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

if (!releaseGate.homebrew_cta_enabled) {
  if (!indexHtml.includes("Homebrew package in release qualification")) {
    throw new Error("website must show Homebrew qualification message while CTA is dark");
  }
  if (indexHtml.includes('class="install-command"') || indexHtml.includes("data-install-command")) {
    throw new Error("website must not render an install-command block while CTA is dark");
  }
  if (indexHtml.includes("data-copy-command=")) {
    throw new Error("website must not expose a copy control for install commands while CTA is dark");
  }
  if (indexHtml.includes(releaseGate.homebrew_command)) {
    throw new Error("website must not expose the Homebrew install command while CTA is dark");
  }
} else {
  if (!releaseGate.required_evidence_document) {
    throw new Error("enabled Homebrew CTA requires required_evidence_document");
  }
  if (!indexHtml.includes(releaseGate.homebrew_command)) {
    throw new Error("enabled Homebrew CTA must render the reviewed install command");
  }
  if (!indexHtml.includes(releaseGate.next_command)) {
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
