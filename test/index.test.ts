// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import * as api from "../src/index.js";

describe("public API surface", () => {
  it("re-exports the core functions and clients", () => {
    expect(typeof api.auditProject).toBe("function");
    expect(typeof api.discoverTree).toBe("function");
    expect(typeof api.discoverOne).toBe("function");
    expect(typeof api.collectDeps).toBe("function");
    expect(typeof api.RegistryClient).toBe("function");
    expect(typeof api.VulnClient).toBe("function");
    expect(typeof api.renderAuditJson).toBe("function");
    expect(typeof api.renderSarif).toBe("function");
    expect(typeof api.renderTerminal).toBe("function");
    expect(api.SCHEMA_VERSION).toBe(1);
  });
});
