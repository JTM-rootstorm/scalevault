export const capabilityProfiles = [
    "chatgpt_pro_private_read",
    "chatgpt_pro_read_github_propose",
    "chatgpt_workspace_private_full",
    "chatgpt_public_plugin_detected",
    "chatgpt_public_plugin_read",
    "chatgpt_public_plugin_full",
] as const;

export type CapabilityProfile = (typeof capabilityProfiles)[number];

export const readToolNames = [
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
] as const;

export const directMutationToolNames = [
    "memory_nominate",
    "memory_observe",
    "memory_remember",
    "memory_revise",
    "memory_link",
    "memory_open_conflict",
    "memory_resolve_conflict",
    "memory_retire",
    "memory_forget",
] as const;

export const publicPluginProfiles = [
    "chatgpt_public_plugin_detected",
    "chatgpt_public_plugin_read",
    "chatgpt_public_plugin_full",
] as const;

export type PublicPluginProfile = (typeof publicPluginProfiles)[number];

export interface PublicPluginCapabilityProbe {
    oauthAuthenticated: boolean;
    installationBindingVerified: boolean;
    relayOnline: boolean;
    discoveredToolNames: readonly string[];
    directWriteCapabilityVerified: boolean;
}

export interface PublicPluginCapabilityResult {
    profile: PublicPluginProfile;
    enabled: boolean;
    directWrite: boolean;
    state:
        | "oauth_required"
        | "installation_binding_required"
        | "relay_offline"
        | "toolset_mismatch"
        | "read_ready"
        | "full_ready";
}

function hasExactToolSet(
    actual: readonly string[],
    expected: readonly string[],
): boolean {
    if (actual.length !== expected.length) {
        return false;
    }
    const actualSet = new Set(actual);
    return (
        actualSet.size === expected.length &&
        expected.every((name) => actualSet.has(name))
    );
}

export function negotiatePublicPluginCapability(
    probe: PublicPluginCapabilityProbe,
): PublicPluginCapabilityResult {
    if (!probe.oauthAuthenticated) {
        return disabled("oauth_required");
    }
    if (!probe.installationBindingVerified) {
        return disabled("installation_binding_required");
    }
    if (!probe.relayOnline) {
        return disabled("relay_offline");
    }
    if (hasExactToolSet(probe.discoveredToolNames, readToolNames)) {
        return {
            profile: "chatgpt_public_plugin_read",
            enabled: true,
            directWrite: false,
            state: "read_ready",
        };
    }

    const fullToolNames = [...readToolNames, ...directMutationToolNames];
    if (
        probe.directWriteCapabilityVerified &&
        hasExactToolSet(probe.discoveredToolNames, fullToolNames)
    ) {
        return {
            profile: "chatgpt_public_plugin_full",
            enabled: true,
            directWrite: true,
            state: "full_ready",
        };
    }
    return disabled("toolset_mismatch");
}

function disabled(
    state: Exclude<
        PublicPluginCapabilityResult["state"],
        "read_ready" | "full_ready"
    >,
): PublicPluginCapabilityResult {
    return {
        profile: "chatgpt_public_plugin_detected",
        enabled: false,
        directWrite: false,
        state,
    };
}

export function hasDirectWrite(
    profile: CapabilityProfile,
    currentWriteCapabilityVerified = false,
): boolean {
    return (
        currentWriteCapabilityVerified &&
        (profile === "chatgpt_workspace_private_full" ||
            profile === "chatgpt_public_plugin_full")
    );
}

export interface GithubProposalCapability {
    currentCreateFileActionProbeVerified: boolean;
    explicitActionApproval: boolean;
}

export function hasGithubProposalFallback(
    profile: CapabilityProfile,
    capability: GithubProposalCapability,
): boolean {
    return (
        profile === "chatgpt_pro_read_github_propose" &&
        capability.currentCreateFileActionProbeVerified &&
        capability.explicitActionApproval
    );
}
