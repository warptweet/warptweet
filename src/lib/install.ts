import gate from "../../packaging/evidence/public-release.json";

export type PublicReleaseGate = {
  kind: "warptweet.public-release-gate";
  schema_version: number;
  homebrew_cta_enabled: boolean;
  homebrew_command: string;
  next_command: string;
  qualification_message: string;
  required_evidence_document: string;
  links: {
    cask_template: string;
    evidence_checklist: string;
    security_policy: string;
    uninstall_macos: string;
    package_interop: string;
  };
  notes: string[];
};

const releaseGate = gate as PublicReleaseGate;

if (releaseGate.kind !== "warptweet.public-release-gate" || releaseGate.schema_version !== 1) {
  throw new Error("invalid public release gate document");
}

if (releaseGate.homebrew_cta_enabled) {
  if (!releaseGate.required_evidence_document.trim()) {
    throw new Error("homebrew CTA requires required_evidence_document");
  }
  if (!releaseGate.homebrew_command.includes("brew install --cask warptweet/tap/warptweet")) {
    throw new Error("homebrew CTA command must install the reviewed cask path");
  }
}

export const publicReleaseGate = releaseGate;

export const homebrewCtaEnabled = releaseGate.homebrew_cta_enabled;
export const homebrewCommand = releaseGate.homebrew_command;
export const enrollCommand = releaseGate.next_command;
export const qualificationMessage = releaseGate.qualification_message;
