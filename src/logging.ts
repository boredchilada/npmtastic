// SPDX-License-Identifier: AGPL-3.0-or-later

let quiet = false;

export function setQuiet(q: boolean): void {
  quiet = q;
}

export function warn(message: string): void {
  if (!quiet) process.stderr.write(`warning: ${message}\n`);
}

export function info(message: string): void {
  if (!quiet) process.stderr.write(`${message}\n`);
}

export function error(message: string): void {
  process.stderr.write(`error: ${message}\n`);
}
