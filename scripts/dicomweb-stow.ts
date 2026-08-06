import { readFileSync } from "node:fs";
import { request } from "node:https";
import { join } from "node:path";

interface Options {
  file: string;
  url: string;
  institution: "a" | "b";
}

function parseArgs(): Options {
  const args = process.argv.slice(2);
  const options: Partial<Options> = {
    institution: "a",
    url: "https://localhost:8042"
  };

  for (let index = 0; index < args.length; index += 1) {
    if (args[index] === "--file") {
      options.file = args[index + 1];
      index += 1;
    } else if (args[index] === "--url") {
      options.url = args[index + 1];
      index += 1;
    } else if (args[index] === "--institution") {
      options.institution = args[index + 1] as "a" | "b";
      index += 1;
    }
  }

  if (!options.file || !options.url || !options.institution || !["a", "b"].includes(options.institution)) {
    throw new Error(
      "Usage: npx tsx scripts/dicomweb-stow.ts --file <dicom> --url <orthanc-url> --institution <a|b>"
    );
  }

  return options as Options;
}

async function main() {
  const options = parseArgs();
  const outDir = join(process.cwd(), "scripts", "out");
  const instDir = join(outDir, `inst-${options.institution}`);
  const boundary = "vadrex-boundary";
  const dicom = readFileSync(options.file);
  const body = Buffer.concat([
    Buffer.from(`--${boundary}\r\nContent-Type: application/dicom\r\n\r\n`, "ascii"),
    dicom,
    Buffer.from(`\r\n--${boundary}--\r\n`, "ascii")
  ]);

  const response = await new Promise<string>((resolve, reject) => {
    const req = request(
      new URL("/dicom-web/studies", options.url),
      {
        ca: readFileSync(join(outDir, "ca", "ca.cert.pem")),
        cert: readFileSync(join(instDir, "cert.pem")),
        key: readFileSync(join(instDir, "key.pem")),
        method: "POST",
        headers: {
          "Content-Type": `multipart/related; type="application/dicom"; boundary=${boundary}`,
          "Content-Length": body.length
        }
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => {
          const responseBody = Buffer.concat(chunks).toString("utf8");
          if (!res.statusCode || res.statusCode >= 400) {
            reject(new Error(`Orthanc returned HTTP ${res.statusCode}: ${responseBody}`));
            return;
          }
          resolve(responseBody);
        });
      }
    );

    req.on("error", reject);
    req.write(body);
    req.end();
  });

  console.log(response);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
