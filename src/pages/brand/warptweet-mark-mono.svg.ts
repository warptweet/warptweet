import { renderBrandMarkSVG } from "../../lib/brand";

export const prerender = true;

export function GET(): Response {
  return new Response(renderBrandMarkSVG("mono"), {
    headers: { "Content-Type": "image/svg+xml; charset=utf-8" }
  });
}
