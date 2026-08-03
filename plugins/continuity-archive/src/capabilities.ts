export const capabilityProfiles = [
    "chatgpt_pro_private_read",
    "chatgpt_pro_read_github_propose",
    "chatgpt_workspace_private_full",
    "chatgpt_public_plugin_detected",
    "chatgpt_public_plugin_read",
    "chatgpt_public_plugin_full",
] as const;

export type CapabilityProfile = (typeof capabilityProfiles)[number];

export function hasDirectWrite(profile: CapabilityProfile): boolean {
    return (
        profile === "chatgpt_workspace_private_full" ||
        profile === "chatgpt_public_plugin_full"
    );
}
