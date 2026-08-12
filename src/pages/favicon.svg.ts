import { renderFaviconSVG } from "../lib/brand";

export const prerender = true;

export function GET(): Response {
  return new Response(renderFaviconSVG(), {
    headers: { "Content-Type": "image/svg+xml; charset=utf-8" }
  });
}
