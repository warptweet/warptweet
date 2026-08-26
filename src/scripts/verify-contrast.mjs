import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const css = await readFile(resolve(process.cwd(), "src/styles/global.css"), "utf8");
const lightRoot = css.match(/^:root\s*{([\s\S]*?)^}/m)?.[1];
const darkRoot = css.match(
  /@media \(prefers-color-scheme: dark\)\s*{\s*:root\s*{([\s\S]*?)\n\s*}/
)?.[1];
if (!lightRoot || !darkRoot) {
  throw new Error("missing light or dark theme token block");
}

function parseTokens(block) {
  return new Map(
    [...block.matchAll(/^\s*(--[a-z0-9-]+):\s*(#[0-9a-f]{6});/gim)].map((match) => [
      match[1],
      match[2]
    ])
  );
}

const lightTokens = parseTokens(lightRoot);
const darkTokens = new Map([...lightTokens, ...parseTokens(darkRoot)]);

function themePairs(theme, dark) {
  const openSourceBackground = dark ? "#163f38" : "--route";
  const primaryForeground = dark ? "#0e1412" : "#f7fffd";
  return [
    [`${theme} body text`, "--ink", "--canvas", 4.5],
    [`${theme} muted text on canvas`, "--ink-muted", "--canvas", 4.5],
    [`${theme} muted text on surface`, "--ink-muted", "--surface", 4.5],
    [`${theme} muted text on muted surface`, "--ink-muted", "--surface-muted", 4.5],
    [`${theme} signal text on canvas`, "--signal", "--canvas", 4.5],
    [`${theme} signal text on surface`, "--signal", "--surface", 4.5],
    [`${theme} signal text on muted surface`, "--signal", "--surface-muted", 4.5],
    [`${theme} night text`, "--night-text", "--night", 4.5],
    [`${theme} bright route text`, "--route-bright", "--night", 4.5],
    [`${theme} dark subdued text`, "#aeb8b2", "--night", 4.5],
    [`${theme} dark secondary text`, "#b7c0ba", "--night", 4.5],
    [`${theme} dark detail text`, "#c5cec8", "--night", 4.5],
    [`${theme} machine code`, "#c8d0cb", "#202b27", 4.5],
    [`${theme} route card text`, "#eef4f0", openSourceBackground, 4.5],
    [`${theme} primary button`, primaryForeground, "--route", 4.5],
    [`${theme} primary button hover`, primaryForeground, "--signal-hover", 4.5],
    [`${theme} open source kicker`, "#bbe5dd", openSourceBackground, 4.5],
    [`${theme} paper button`, "#17201d", "#fffdf8", 4.5],
    [`${theme} open source link`, "#ffffff", openSourceBackground, 4.5],
    [`${theme} focus indicator`, "--focus", "--focus-halo", 3],
    [`${theme} dark-surface focus indicator`, "#9ecbff", "#17201d", 3],
    [`${theme} machine boundary`, "#66766f", "#202b27", 3],
    [`${theme} route graphic`, "--route-bright", "--night", 3],
    [`${theme} support status boundary`, "--route", "--surface", 3]
  ];
}

const matrices = [
  [lightTokens, themePairs("light", false)],
  [darkTokens, themePairs("dark", true)],
  [
    lightTokens,
    [
      ["increased-contrast muted text on canvas", "#26312c", "--canvas", 4.5],
      ["increased-contrast muted text on surface", "#26312c", "--surface", 4.5],
      ["increased-contrast muted text on muted surface", "#26312c", "--surface-muted", 4.5]
    ]
  ]
];

function resolveColor(reference, tokens) {
  const color = reference.startsWith("--") ? tokens.get(reference) : reference;
  if (!color || !/^#[0-9a-f]{6}$/i.test(color)) {
    throw new Error(`missing six-digit authored color ${reference}`);
  }
  return color;
}

function luminance(color) {
  const channels = color
    .slice(1)
    .match(/../g)
    .map((channel) => Number.parseInt(channel, 16) / 255)
    .map((channel) =>
      channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4
    );
  return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
}

function contrast(foreground, background) {
  const a = luminance(foreground);
  const b = luminance(background);
  return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
}

let count = 0;
const minima = new Map([
  [4.5, { name: "", ratio: Number.POSITIVE_INFINITY }],
  [3, { name: "", ratio: Number.POSITIVE_INFINITY }]
]);
for (const [tokens, pairs] of matrices) {
  for (const [name, foregroundReference, backgroundReference, required] of pairs) {
    count += 1;
    const foreground = resolveColor(foregroundReference, tokens);
    const background = resolveColor(backgroundReference, tokens);
    const ratio = contrast(foreground, background);
    if (ratio < required) {
      throw new Error(
        `${name} contrast ${ratio.toFixed(3)}:1 is below ${required}:1 (${foreground} on ${background})`
      );
    }
    const minimum = minima.get(required);
    if (ratio < minimum.ratio) {
      minima.set(required, { name, ratio });
    }
  }
}

console.log(
  `contrast: PASS ${count} authored pairs; text minimum ${minima.get(4.5).ratio.toFixed(3)}:1 (${minima.get(4.5).name}); non-text minimum ${minima.get(3).ratio.toFixed(3)}:1 (${minima.get(3).name})`
);
