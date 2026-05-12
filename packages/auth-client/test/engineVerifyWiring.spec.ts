import { expect, describe, it, vi, beforeEach } from "vitest";
import { AuthEngine } from "../src/controllers/engine";
import { AuthClientTypes } from "../src/types";

const WALLET_URL = "https://mywallet.app";
const DAPP_URL = "https://app.uniswap.org";

const walletMetadata: AuthClientTypes.Metadata = {
  name: "My Wallet",
  description: "",
  url: WALLET_URL,
  icons: [],
};

const dappMetadata: AuthClientTypes.Metadata = {
  name: "Uniswap",
  description: "",
  url: DAPP_URL,
  icons: [],
};

const authRequestPayload = {
  id: 1,
  jsonrpc: "2.0" as const,
  method: "wc_authRequest" as const,
  params: {
    requester: {
      publicKey: "abc123",
      metadata: dappMetadata,
    },
    payloadParams: {
      type: "eip4361" as const,
      chainId: "eip155:1",
      domain: "app.uniswap.org",
      aud: "https://app.uniswap.org/login",
      version: "1",
      nonce: "deadbeef",
      iat: new Date().toISOString(),
    },
  },
};

function createMockClient(verifyResolveReturn: unknown) {
  return {
    metadata: walletMetadata,
    logger: {
      info: vi.fn(),
      error: vi.fn(),
      debug: vi.fn(),
    },
    requests: {
      set: vi.fn().mockResolvedValue(undefined),
    },
    core: {
      verify: {
        resolve: vi.fn().mockResolvedValue(verifyResolveReturn),
      },
      pairing: {
        register: vi.fn(),
      },
    },
    emit: vi.fn(),
  } as any;
}

describe("AuthEngine.onAuthRequest verifyContext wiring", () => {
  it("produces VALID when attested origin matches requester (dApp) URL", async () => {
    const mockClient = createMockClient({ origin: DAPP_URL });
    const engine = new AuthEngine(mockClient);

    await (engine as any).onAuthRequest("topic", authRequestPayload);

    const [eventName, eventArgs] = mockClient.emit.mock.calls[0];
    expect(eventName).toBe("auth_request");
    expect(eventArgs.verifyContext.verified.validation).toBe("VALID");
    expect(eventArgs.verifyContext.verified.origin).toBe(DAPP_URL);
  });

  it("produces INVALID when attested origin matches wallet URL but not requester URL (regression guard)", async () => {
    const mockClient = createMockClient({ origin: WALLET_URL });
    const engine = new AuthEngine(mockClient);

    await (engine as any).onAuthRequest("topic", authRequestPayload);

    const [eventName, eventArgs] = mockClient.emit.mock.calls[0];
    expect(eventName).toBe("auth_request");
    expect(eventArgs.verifyContext.verified.validation).toBe("INVALID");
    expect(eventArgs.verifyContext.verified.origin).toBe(WALLET_URL);
  });
});
