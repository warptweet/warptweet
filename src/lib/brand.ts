export const brandViewBox = "0 0 64 64";
export const brandPlatePath = "M14 8H43L54 19V56H14V8Z";
export const brandRoutePath = "M4 24H14L22 43L32 24L42 43L50 24H60";
export const brandEndpointPath = "M4 20V28M60 20V28";

export const faviconViewBox = "0 0 16 16";
export const faviconRoutePath = "M2 3V7M2 5H4L6 13L8 5L10 13L12 5H14M14 3V7";

type BrandVariant = "color" | "mono" | "reverse";

interface BrandPalette {
  plate: string;
  route: string;
}

const brandPalettes: Record<BrandVariant, BrandPalette> = {
  color: { plate: "#17201D", route: "#1F6258" },
  mono: { plate: "#000000", route: "#000000" },
  reverse: { plate: "#F4F0E7", route: "#77BEB4" }
};

export function renderBrandMarkSVG(variant: BrandVariant): string {
  const palette = brandPalettes[variant];

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${brandViewBox}" fill="none">
  <title>WarpTweet</title>
  <path d="${brandPlatePath}" stroke="${palette.plate}" stroke-width="4" stroke-linejoin="miter" />
  <path d="${brandRoutePath}" stroke="${palette.route}" stroke-width="5" stroke-linecap="square" stroke-linejoin="miter" />
  <path d="${brandEndpointPath}" stroke="${palette.route}" stroke-width="5" stroke-linecap="square" />
</svg>
`;
}

export function renderFaviconSVG(): string {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${faviconViewBox}" fill="none">
  <title>WarpTweet</title>
  <rect width="16" height="16" rx="2" fill="#F4F0E7" />
  <path d="${faviconRoutePath}" stroke="#17201D" stroke-width="2" stroke-linecap="square" stroke-linejoin="bevel" />
</svg>
`;
}
