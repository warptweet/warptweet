import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const root = process.cwd();
const brandSource = await readFile(resolve(root, "src/lib/brand.ts"), "utf8");

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
