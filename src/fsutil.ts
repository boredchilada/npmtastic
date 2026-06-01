// SPDX-License-Identifier: AGPL-3.0-or-later
import { readFileSync } from "node:fs";

/**
 * Read a file as text, detecting and stripping a leading BOM.
 * Handles UTF-16 LE/BE (Windows `>` redirection artifacts) and UTF-8 BOM,
 * falling back to UTF-8. Mirrors the Python sister tool's decode order.
 */
export function readText(path: string): string {
  const buf = readFileSync(path);
  if (buf.length >= 2 && buf[0] === 0xff && buf[1] === 0xfe) {
    return buf.toString("utf16le").replace(/^﻿/, "");
  }
  if (buf.length >= 2 && buf[0] === 0xfe && buf[1] === 0xff && buf.length % 2 === 0) {
    return Buffer.from(buf).swap16().toString("utf16le").replace(/^﻿/, "");
  }
  if (buf.length >= 3 && buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) {
    return buf.toString("utf8").slice(1);
  }
  return buf.toString("utf8");
}
