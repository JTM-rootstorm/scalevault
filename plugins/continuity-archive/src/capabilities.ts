export const capabilityProfiles = [
    "chatgpt_pro_private_read",
    "chatgpt_pro_read_github_propose",
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

export function hasDirectWrite(_profile: CapabilityProfile): false {
    return false;
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
