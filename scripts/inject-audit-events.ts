import { makeAuditEntries } from "./audit-events.js";

interface Args {
  count: number;
  offset: number;
  url: string;
}

function readArgs(): Args {
  const args = process.argv.slice(2);
  const out: Args = {
    count: 1,
    offset: 0,
    url: "http://localhost:7001"
  };

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    const value = args[index + 1];
    if (arg === "--count" && value) {
      out.count = Number(value);
      index += 1;
    } else if (arg === "--offset" && value) {
      out.offset = Number(value);
      index += 1;
    } else if (arg === "--url" && value) {
      out.url = value.replace(/\/$/, "");
      index += 1;
    } else {
      throw new Error(`unknown or incomplete argument: ${arg}`);
    }
  }

  if (!Number.isSafeInteger(out.count) || out.count <= 0) {
    throw new Error("--count must be a positive integer");
  }
  if (!Number.isSafeInteger(out.offset) || out.offset < 0) {
    throw new Error("--offset must be a non-negative integer");
  }
  return out;
}

async function postJson(url: string, body: unknown): Promise<unknown> {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body)
  });
  const text = await response.text();
  const parsed = text ? JSON.parse(text) : null;
  if (!response.ok) {
    throw new Error(`${url} returned ${response.status}: ${text}`);
  }
  return parsed;
}

async function main() {
  const args = readArgs();
  const entries = makeAuditEntries(args.count, args.offset);
  const result = await postJson(`${args.url}/dev/audit-entries`, { entries });
  console.log(JSON.stringify(result, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
