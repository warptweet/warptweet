import gate from "../../packaging/evidence/public-release.json";

export type PublicReleaseGate = {
  kind: "warptweet.public-release-gate";
  schema_version: number;
  qualification_complete: boolean;
  public_distribution_ready: boolean;
  homebrew_command: string;
  next_command: string;
  qualification_message: string;
  distribution_message: string;
  required_evidence_document: string;
  required_distribution_evidence_document: string;
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

if (releaseGate.kind !== "warptweet.public-release-gate" || releaseGate.schema_version !== 2) {
  throw new Error("invalid public release gate document");
}

if (releaseGate.qualification_complete && !releaseGate.required_evidence_document.trim()) {
  throw new Error("complete qualification requires required_evidence_document");
}

if (releaseGate.public_distribution_ready) {
  if (!releaseGate.qualification_complete) {
    throw new Error("public distribution requires complete qualification");
  }
  if (!releaseGate.required_distribution_evidence_document.trim()) {
    throw new Error("public distribution requires distribution evidence");
  }
  if (!releaseGate.required_evidence_document.trim()) {
    throw new Error("public distribution requires required_evidence_document");
  }
  if (!releaseGate.homebrew_command.includes("brew install --cask warptweet/tap/warptweet")) {
    throw new Error("homebrew CTA command must install the reviewed cask path");
  }
}

export const publicReleaseGate = releaseGate;

export const qualificationComplete = releaseGate.qualification_complete;
export const publicDistributionReady = releaseGate.public_distribution_ready;
export const homebrewCommand = releaseGate.homebrew_command;
export const enrollCommand = releaseGate.next_command;
export const qualificationMessage = releaseGate.qualification_message;
export const distributionMessage = releaseGate.distribution_message;
