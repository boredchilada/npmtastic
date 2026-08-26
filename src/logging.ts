// SPDX-License-Identifier: AGPL-3.0-or-later
import { appendFileSync } from "node:fs";

let quiet = false;
let logFilePath: string | null = null;

export function setQuiet(q: boolean): void {
  quiet = q;
}

export function setLogFile(path: string | null): void {
  logFilePath = path;
}

function emit(text: string): void {
  process.stderr.write(text);
  if (logFilePath !== null) {
    try {
      appendFileSync(logFilePath, text);
    } catch {
      // a log-file write must never crash the scan
    }
  }
}

export function warn(message: string): void {
  if (!quiet) emit(`warning: ${message}\n`);
}

export function info(message: string): void {
  if (!quiet) emit(`${message}\n`);
}

export function error(message: string): void {
  emit(`error: ${message}\n`);
}
