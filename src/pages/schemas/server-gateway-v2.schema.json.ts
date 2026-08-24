import schema from "../../../schemas/server-gateway-v2.schema.json";

export const prerender = true;

export function GET(): Response {
  return new Response(`${JSON.stringify(schema, null, 2)}\n`, {
    headers: {
      "Content-Type": "application/schema+json; charset=utf-8"
    }
  });
}
