import { readFileSync } from "node:fs";
import { request } from "node:https";
import { join } from "node:path";

interface Options {
  url: string;
  institution: "a" | "b";
}

function parseArgs(): Options {
  const args = process.argv.slice(2);
  const options: Partial<Options> = {};

  for (let index = 0; index < args.length; index += 1) {
    if (args[index] === "--url") {
      options.url = args[index + 1];
      index += 1;
    } else if (args[index] === "--institution") {
      options.institution = args[index + 1] as "a" | "b";
      index += 1;
    }
  }

  if (!options.url || !options.institution || !["a", "b"].includes(options.institution)) {
    throw new Error("Usage: npx tsx scripts/orthanc-get.ts --url <url> --institution <a|b>");
  }

  return options as Options;
}

async function main() {
  const options = parseArgs();
  const outDir = join(process.cwd(), "scripts", "out");
  const instDir = join(outDir, `inst-${options.institution}`);

  const response = await new Promise<string>((resolve, reject) => {
    const req = request(
      options.url,
      {
        ca: readFileSync(join(outDir, "ca", "ca.cert.pem")),
        cert: readFileSync(join(instDir, "cert.pem")),
        key: readFileSync(join(instDir, "key.pem")),
        method: "GET"
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => {
          const body = Buffer.concat(chunks).toString("utf8");
          if (!res.statusCode || res.statusCode >= 400) {
            reject(new Error(`Orthanc returned HTTP ${res.statusCode}: ${body}`));
            return;
          }
          resolve(body);
        });
      }
    );

    req.on("error", reject);
    req.end();
  });

  console.log(response);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
