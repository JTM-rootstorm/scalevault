import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import test from "node:test";
import ts from "typescript";

const pluginRoot = new URL("../", import.meta.url);
const profileUrl = new URL("profiles/chatgpt-pro-private.json", pluginRoot);
const publicProfileUrl = new URL(
    "profiles/chatgpt-public-relay-read.json",
    pluginRoot,
);

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

async function importCapabilities() {
    const source = await readFile(
        new URL("src/capabilities.ts", pluginRoot),
        "utf8",
    );
    const output = ts.transpileModule(source, {
        compilerOptions: {
            module: ts.ModuleKind.ES2022,
            target: ts.ScriptTarget.ES2022,
        },
    }).outputText;
    return import(
        `data:text/javascript;base64,${Buffer.from(output).toString("base64")}`
    );
}

async function packageFiles(directory = pluginRoot) {
    const entries = await readdir(directory, { withFileTypes: true });
    const files = [];
    for (const entry of entries) {
        if (entry.name === "node_modules") {
            continue;
        }
        const url = new URL(entry.name, directory);
        if (entry.isDirectory()) {
            files.push(
                ...(await packageFiles(new URL(`${entry.name}/`, directory))),
            );
        } else if (entry.isFile()) {
            files.push(url);
        }
    }
    return files;
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

test("public candidate is coordinate-free, read-only, and fail-closed", async () => {
    const packageProfile = await readJson(new URL("plugin.json", pluginRoot));
    const profile = await readJson(publicProfileUrl);

    assert.equal(profile.profile_id, "chatgpt_public_plugin_read");
    assert.equal(profile.surface, "chatgpt_public_plugin");
    assert.deepEqual(profile.activation, {
        initial_profile: "chatgpt_public_plugin_detected",
        requires_oauth: true,
        requires_installation_binding: true,
        requires_relay_online: true,
        requires_current_capability_probe: true,
        on_failure: "disable_profile",
    });
    assert.deepEqual(profile.transport, {
        kind: "public_relay",
        registered_app_connection_required: true,
        endpoint_in_plugin_package: false,
        private_network_coordinates_in_artifact: false,
        memory_body_persistence: "prohibited",
        on_offline: "fail_closed",
    });
    assert.deepEqual(profile.authentication, {
        kind: "oauth",
        installation_binding: "required",
        anonymous_access: false,
        on_unknown_identity: "fail_closed",
    });
    assert.equal(profile.endpoint, undefined);
    assert.equal(profile.transport.endpoint, undefined);
    assert.equal(profile.mcp.discovery_policy, "exact_allowlist");
    assert.deepEqual(profile.mcp.allowed_tools, expectedReadTools);
    assert.deepEqual(profile.mcp.forbidden_tools, expectedForbiddenTools);
    assert.equal(profile.mcp.on_discovery_mismatch, "disable_profile");
    assert.deepEqual(profile.mcp.required_annotations, {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
    });
    assert.deepEqual(profile.full_profile, {
        configuration: "dormant",
        profile_id: "chatgpt_public_plugin_full",
        activation:
            "current_explicit_write_capability_probe_and_exact_full_toolset",
        infer_from_installation: false,
        on_unverified: "remain_detected",
    });
    assert.deepEqual(packageProfile.profiles, [
        "./profiles/chatgpt-pro-private.json",
        "./profiles/chatgpt-public-relay-read.json",
    ]);
    assert.equal(
        packageProfile.public_candidate.app_registration_bundled,
        false,
    );
});

test("public capability negotiation requires exact live evidence", async () => {
    const capabilities = await importCapabilities();
    assert.deepEqual(capabilities.capabilityProfiles, [
        "chatgpt_pro_private_read",
        "chatgpt_pro_read_github_propose",
        "chatgpt_workspace_private_full",
        "chatgpt_public_plugin_detected",
        "chatgpt_public_plugin_read",
        "chatgpt_public_plugin_full",
    ]);
    assert.deepEqual(capabilities.readToolNames, expectedReadTools);
    assert.deepEqual(
        capabilities.directMutationToolNames,
        expectedForbiddenTools,
    );
    const baseProbe = {
        oauthAuthenticated: true,
        installationBindingVerified: true,
        relayOnline: true,
        discoveredToolNames: [...expectedReadTools],
        directWriteCapabilityVerified: false,
    };

    assert.deepEqual(capabilities.negotiatePublicPluginCapability(baseProbe), {
        profile: "chatgpt_public_plugin_read",
        enabled: true,
        directWrite: false,
        state: "read_ready",
    });

    for (const [field, state] of [
        ["oauthAuthenticated", "oauth_required"],
        ["installationBindingVerified", "installation_binding_required"],
        ["relayOnline", "relay_offline"],
    ]) {
        assert.deepEqual(
            capabilities.negotiatePublicPluginCapability({
                ...baseProbe,
                [field]: false,
            }),
            {
                profile: "chatgpt_public_plugin_detected",
                enabled: false,
                directWrite: false,
                state,
            },
        );
    }

    for (const discoveredToolNames of [
        expectedReadTools.slice(1),
        [...expectedReadTools, "unexpected-tool"],
        [...expectedReadTools, expectedReadTools[0]],
    ]) {
        assert.deepEqual(
            capabilities.negotiatePublicPluginCapability({
                ...baseProbe,
                discoveredToolNames,
            }),
            {
                profile: "chatgpt_public_plugin_detected",
                enabled: false,
                directWrite: false,
                state: "toolset_mismatch",
            },
        );
    }

    const fullToolNames = [...expectedReadTools, ...expectedForbiddenTools];
    assert.equal(
        capabilities.negotiatePublicPluginCapability({
            ...baseProbe,
            discoveredToolNames: fullToolNames,
        }).enabled,
        false,
    );
    assert.deepEqual(
        capabilities.negotiatePublicPluginCapability({
            ...baseProbe,
            discoveredToolNames: fullToolNames,
            directWriteCapabilityVerified: true,
        }),
        {
            profile: "chatgpt_public_plugin_full",
            enabled: true,
            directWrite: true,
            state: "full_ready",
        },
    );
    assert.equal(
        capabilities.hasDirectWrite("chatgpt_public_plugin_full"),
        false,
    );
    assert.equal(
        capabilities.hasDirectWrite("chatgpt_public_plugin_full", true),
        true,
    );
    assert.equal(
        capabilities.hasDirectWrite("chatgpt_public_plugin_read", true),
        false,
    );
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

test("package artifacts recursively contain no private coordinates or credentials", async () => {
    const urls = await packageFiles();
    const raw = (
        await Promise.all(urls.map((url) => readFile(url, "utf8")))
    ).join("\n");

    const privateCoordinatePatterns = [
        new RegExp(["127", "0", "0", "1"].join("\\.")),
        new RegExp(["0", "0", "0", "0"].join("\\.")),
        new RegExp("10" + "\\.(?:\\d{1,3}\\.){2}\\d{1,3}"),
        new RegExp("172" + "\\.(?:1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}"),
        new RegExp("192" + "\\.168\\.\\d{1,3}\\.\\d{1,3}"),
        new RegExp("\\[?::" + "1\\]?"),
        new RegExp(["local", "host"].join(""), "i"),
        new RegExp("\\.inter" + "nal\\b", "i"),
        new RegExp("\\.lo" + "cal\\b", "i"),
        new RegExp("\\.la" + "n\\b", "i"),
        new RegExp("\\.home" + "\\.arpa\\b", "i"),
        new RegExp("memory-re" + "lay\\.example", "i"),
        new RegExp("JTM-" + "rootstorm", "i"),
        new RegExp("plugin_asdk" + "_app_[A-Za-z0-9]+"),
    ];
    const credentialPatterns = [
        new RegExp("gh" + "[pousr]_[A-Za-z0-9_]{20,}"),
        new RegExp("sk" + "-[A-Za-z0-9_-]{20,}"),
        new RegExp("Authoriz" + "ation:\\s*Bearer", "i"),
    ];
    for (const pattern of [
        ...privateCoordinatePatterns,
        ...credentialPatterns,
    ]) {
        assert.doesNotMatch(raw, pattern);
    }
});
