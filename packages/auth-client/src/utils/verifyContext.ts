import { Verify } from "@exodus/walletconnect-types";
import { AuthClientTypes } from "../types";

export interface BuildVerifyContextDeps {
  resolve: (args: {
    attestationId: string;
    verifyUrl?: string;
  }) => Promise<{ origin?: string; isScam?: boolean } | string | undefined>;
  logError?: (err: unknown) => void;
}

export const buildVerifyContext = async (
  { resolve, logError }: BuildVerifyContextDeps,
  attestationId: string,
  metadata: AuthClientTypes.Metadata,
): Promise<Verify.Context> => {
  if (!metadata?.url) {
    const context: Verify.Context = {
      verified: { verifyUrl: "", validation: "UNKNOWN", origin: "" },
    };
    try {
      const attestation = await resolve({ attestationId });
      if (attestation) {
        const origin =
          typeof attestation === "string" ? attestation : (attestation as any).origin;
        if (origin && typeof origin === "string") {
          // Registered dApps always declare metadata.url; receiving an attested
          // origin while the dApp claims nothing is mismatch by definition.
          context.verified.origin = origin;
          context.verified.validation = "INVALID";
        }
        if (typeof attestation === "object" && (attestation as any).isScam) {
          context.verified.isScam = true;
        }
      }
    } catch (e) {
      logError?.(e);
    }
    return context;
  }

  const context: Verify.Context = {
    verified: {
      verifyUrl: metadata.verifyUrl || "",
      validation: "UNKNOWN",
      origin: metadata.url || "",
    },
  };

  try {
    const attestation = await resolve({
      attestationId,
      verifyUrl: metadata.verifyUrl,
    });
    if (attestation) {
      const origin = typeof attestation === "string" ? attestation : (attestation as any).origin;
      if (origin && typeof origin === "string") {
        context.verified.origin = origin;
        let claimedOrigin = metadata.url || "";
        try {
          claimedOrigin = new URL(metadata.url).origin;
        } catch {}
        context.verified.validation = origin === claimedOrigin ? "VALID" : "INVALID";
      }
      if (typeof attestation === "object" && (attestation as any).isScam) {
        context.verified.isScam = true;
      }
    }
  } catch (e) {
    logError?.(e);
  }

  return context;
};
