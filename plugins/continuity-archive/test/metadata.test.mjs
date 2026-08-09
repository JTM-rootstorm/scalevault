import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const pluginRoot = new URL("../", import.meta.url);
const profileUrl = new URL("profiles/chatgpt-pro-private.json", pluginRoot);

const expectedReadTools = [
    "memory_context_pack",
    "memory_search",
    "memory_get",
    "memory_timeline",
    "memory_conflicts",
    "memory_lineage",
    "memory_selection_history",
    "memory_ingress_status",
    "memory_transport_status",
    "memory_selection_decisions",
];

const expectedForbiddenTools = [
    "memory_nominate",
    "memory_observe",
    "memory_remember",
    "memory_revise",
    "memory_link",
    "memory_open_conflict",
    "memory_resolve_conflict",
    "memory_retire",
    "memory_forget",
];

async function readJson(url) {
    return JSON.parse(await readFile(url, "utf8"));
}

test("canonical plugin manifest declares read-only capabilities", async () => {
    const manifest = await readJson(
        new URL(".codex-plugin/plugin.json", pluginRoot),
    );
    const packageMetadata = await readJson(new URL("package.json", pluginRoot));
    const packageProfile = await readJson(new URL("plugin.json", pluginRoot));

    assert.equal(manifest.name, "continuity-archive");
    assert.equal(manifest.version, packageMetadata.version);
    assert.deepEqual(manifest.interface.capabilities, ["Interactive", "Read"]);
    assert.equal(manifest.skills, "./skills/");
    assert.equal(manifest.apps, undefined);
    assert.equal(manifest.mcpServers, undefined);
    assert.equal(packageProfile.capability_profile, "chatgpt_pro_private_read");
});

test("private app profile pins only the canonical read tools", async () => {
    const profile = await readJson(profileUrl);

    assert.equal(profile.profile_id, "chatgpt_pro_private_read");
    assert.equal(profile.surface, "chatgpt_web_private_app");
    assert.equal(profile.transport.kind, "secure_mcp_tunnel");
    assert.equal(profile.transport.public_inbound_required, false);
    assert.equal(profile.mcp.discovery_policy, "exact_allowlist");
    assert.equal(profile.mcp.on_discovery_mismatch, "disable_profile");
    assert.equal(profile.mcp.tool_snapshot, "frozen_by_chatgpt");
    assert.equal(profile.mcp.refresh_after_tool_change, true);
    assert.deepEqual(profile.mcp.allowed_tools, expectedReadTools);
    assert.deepEqual(profile.mcp.forbidden_tools, expectedForbiddenTools);
    assert.deepEqual(profile.mcp.required_annotations, {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
    });

    const overlap = profile.mcp.allowed_tools.filter((tool) =>
        profile.mcp.forbidden_tools.includes(tool),
    );
    assert.deepEqual(overlap, []);
});

test("GitHub fallback remains create-only and non-canonical", async () => {
    const profile = await readJson(profileUrl);

    assert.deepEqual(profile.write_fallback, {
        availability: "disabled_by_default",
        standard_chatgpt_github_integration: "unavailable_read_only",
        provider: "github_create_capable_connected_action",
        repository: "operator_configured_private_repository",
        activation_probe: "exact_account_side_create_file_action",
        approval: "explicit_per_action",
        on_probe_failure: "unavailable",
        contract: "chatgpt-memory-proposal-v2",
        operation: "nominate",
        action: "create_file",
        path_template:
            "ingress/v2/{installation_id}/{yyyy}/{mm}/{proposal_id}.json",
        create_only: true,
        ambiguous_retry: "same_proposal_id_path_and_body",
        status_tool: "memory_ingress_status",
        canonical_commit_claim: "prohibited",
    });
    assert.equal(profile.privacy.maximum_proposal_sensitivity, 0);

    const fallback = await readFile(
        new URL(
            "skills/persona-continuity/references/github-proposal-fallback.md",
            pluginRoot,
        ),
        "utf8",
    );
    assert.match(fallback, /without a blob SHA/);
    assert.match(
        fallback,
        /Never describe repository creation as a\s+canonical memory commit/,
    );
    assert.match(
        fallback,
        /standard ChatGPT GitHub integration\s+is read-only/,
    );
    assert.match(fallback, /explicitly approves this proposal action/);
    assert.match(fallback, /Never generate a second proposal identifier/);
    assert.match(fallback, /never\s+edits the prior file/);
});

test("bundled proposal schema is byte-identical to the canonical contract", async () => {
    const bundled = await readFile(
        new URL(
            "skills/persona-continuity/references/chatgpt-memory-proposal-v2.schema.json",
            pluginRoot,
        ),
    );
    const canonical = await readFile(
        new URL(
            "../../../schemas/chatgpt-memory-proposal-v2.schema.json",
            import.meta.url,
        ),
    );

    assert.deepEqual(bundled, canonical);
});

test("skill prohibits direct mutation and unsafe proposal contents", async () => {
    const skill = await readFile(
        new URL("skills/persona-continuity/SKILL.md", pluginRoot),
        "utf8",
    );

    assert.match(
        skill,
        /Never invoke `memory_nominate` or any direct mutation tool/,
    );
    assert.match(
        skill,
        /Do not disguise a write as search, fetch, or status retrieval/,
    );
    assert.match(skill, /sensitivity is unknown/);
    assert.match(skill, /credentials, hidden\nreasoning, a transcript/);
    assert.match(skill, /Report it as queued through a third-party transport/);
    assert.match(skill, /standard ChatGPT GitHub integration is read-only/);
    assert.match(
        skill,
        /current account-side probe verifies the exact\ncreate-file action/,
    );
});

test("package artifacts contain no private coordinates or credential values", async () => {
    const urls = [
        new URL("plugin.json", pluginRoot),
        new URL(".codex-plugin/plugin.json", pluginRoot),
        profileUrl,
        new URL("README.md", pluginRoot),
        new URL("skills/persona-continuity/SKILL.md", pluginRoot),
        new URL(
            "skills/persona-continuity/references/github-proposal-fallback.md",
            pluginRoot,
        ),
    ];
    const raw = (
        await Promise.all(urls.map((url) => readFile(url, "utf8")))
    ).join("\n");

    assert.doesNotMatch(raw, /(?:127\.0\.0\.1|localhost|\.internal\b)/i);
    assert.doesNotMatch(raw, /memory-relay\.example/i);
    assert.doesNotMatch(raw, /JTM-rootstorm/i);
    assert.doesNotMatch(
        raw,
        /(?:gh[pousr]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,})/,
    );
    assert.doesNotMatch(raw, /Authorization:\s*Bearer/i);
});
