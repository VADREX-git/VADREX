// Canonical JSON: keys sorted by Unicode code point, no whitespace, UTF-8.
// Every hash in the system is taken over the output of canonicalize(), so any change
// here invalidates existing entry hashes, Merkle leaves and anchors.

// String.prototype.sort compares UTF-16 code units, which orders U+FFFF after a
// surrogate pair such as U+1F600. Code point order is the one the contract specifies.
function compareCodePoints(left: string, right: string): number {
  const leftPoints = Array.from(left, (char) => char.codePointAt(0) ?? 0);
  const rightPoints = Array.from(right, (char) => char.codePointAt(0) ?? 0);
  const length = Math.min(leftPoints.length, rightPoints.length);

  for (let index = 0; index < length; index += 1) {
    const diff = leftPoints[index] - rightPoints[index];
    if (diff !== 0) {
      return diff;
    }
  }

  return leftPoints.length - rightPoints.length;
}

function renderCanonical(value: unknown): string {
  if (value === null) {
    return "null";
  }

  if (typeof value === "string") {
    return JSON.stringify(value);
  }

  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError("canonical JSON does not support non-finite numbers");
    }
    return JSON.stringify(value);
  }

  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }

  if (Array.isArray(value)) {
    return `[${value.map((item) => renderCanonical(item)).join(",")}]`;
  }

  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort(compareCodePoints);
    const fields = keys.map((key) => {
      const fieldValue = record[key];
      if (fieldValue === undefined || typeof fieldValue === "function" || typeof fieldValue === "symbol") {
        throw new TypeError(`canonical JSON cannot encode field ${key}`);
      }
      return `${JSON.stringify(key)}:${renderCanonical(fieldValue)}`;
    });
    return `{${fields.join(",")}}`;
  }

  throw new TypeError(`canonical JSON cannot encode ${typeof value}`);
}

export function canonicalize(obj: unknown): Buffer {
  return Buffer.from(renderCanonical(obj), "utf8");
}
