import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("plugin metadata contains no private network coordinates", async () => {
    const raw = await readFile(new URL("../plugin.json", import.meta.url), "utf8");
    const metadata = JSON.parse(raw);

    assert.equal(metadata.schema_version, 1);
    assert.match(metadata.mcp_endpoint_template, /^https:\/\//);
    assert.doesNotMatch(raw, /(?:127\.0\.0\.1|localhost|\.internal)/);
});
