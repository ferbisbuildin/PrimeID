/**
 * RFC 8785 JSON Canonicalization Scheme (JCS) Implementation
 * Ensures deterministic serialization across Issuer, Device, and Verifier
 * regardless of platform or JSON key insertion order.
 */

export function canonicalizeJson(obj: unknown): string {
  if (obj === null || obj === undefined) {
    return "null";
  }

  if (typeof obj === "boolean" || typeof obj === "number") {
    return JSON.stringify(obj);
  }

  if (typeof obj === "string") {
    return JSON.stringify(obj);
  }

  if (Array.isArray(obj)) {
    const serializedElements = obj.map((element) => canonicalizeJson(element));
    return `[${serializedElements.join(",")}]`;
  }

  if (typeof obj === "object") {
    const keys = Object.keys(obj as Record<string, unknown>).sort();
    const pairs = keys.map((key) => {
      const value = (obj as Record<string, unknown>)[key];
      if (value === undefined) {
        return null;
      }
      return `${JSON.stringify(key)}:${canonicalizeJson(value)}`;
    }).filter((pair): pair is string => pair !== null);

    return `{${pairs.join(",")}}`;
  }

  return JSON.stringify(obj);
}
