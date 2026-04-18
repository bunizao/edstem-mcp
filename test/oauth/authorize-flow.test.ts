import { afterEach, describe, expect, it } from "vitest";
import supertest from "supertest";
import type { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";

import { createApp } from "../../src/app.js";
import { startFakeEdServer } from "../support/fake-ed-server.js";
import { createTestRuntime, extractCsrfToken } from "../support/test-runtime.js";

const TEST_CLIENT: OAuthClientInformationFull = {
  client_id: "test-client",
  client_name: "Test Client",
  grant_types: ["authorization_code", "refresh_token"],
  redirect_uris: ["http://127.0.0.1/callback"],
  response_types: ["code"],
  token_endpoint_auth_method: "none"
};

describe("oauth authorize flow", () => {
  const cleanups: Array<() => Promise<void>> = [];

  afterEach(async () => {
    while (cleanups.length > 0) {
      await cleanups.pop()?.();
    }
  });

  it("signs up a user, verifies the Ed token, and issues an authorization code", async () => {
    const fakeEd = await startFakeEdServer([
      {
        courses: [
          {
            course: {
              code: "COMP101",
              id: 1,
              name: "Intro",
              session: "S1",
              status: "active",
              year: "2026"
            },
            role: { role: "student" }
          }
        ],
        token: "ed-token-a",
        user: {
          avatar: "",
          course_role: "student",
          email: "ada@example.com",
          id: 101,
          name: "Ada",
          role: "student"
        }
      }
    ]);
    cleanups.push(fakeEd.close);

    const { runtime, cleanup } = await createTestRuntime({
      apiBaseUrl: fakeEd.baseUrl
    });
    cleanups.push(cleanup);
    runtime.store.saveClient(TEST_CLIENT);

    const app = createApp(runtime);
    const agent = supertest.agent(app);

    const page = await agent
      .get("/authorize")
      .query({
        client_id: TEST_CLIENT.client_id,
        code_challenge: "challenge",
        code_challenge_method: "S256",
        redirect_uri: TEST_CLIENT.redirect_uris[0],
        response_type: "code",
        scope: "mcp:tools.read mcp:tools.write"
      })
      .expect(200);

    const csrfToken = extractCsrfToken(page.text);
    const response = await agent
      .post("/authorize")
      .type("form")
      .send({
        client_id: TEST_CLIENT.client_id,
        code_challenge: "challenge",
        code_challenge_method: "S256",
        csrf_token: csrfToken,
        ed_token: "ed-token-a",
        redirect_uri: TEST_CLIENT.redirect_uris[0],
        response_type: "code",
        scope: "mcp:tools.read mcp:tools.write",
        scope_read: "1",
        scope_write: "1",
        signup_confirm_password: "this-is-secure",
        signup_display_name: "Ada",
        signup_email: "ada@example.com",
        signup_password: "this-is-secure",
        tab: "signup"
      })
      .expect(302);

    const redirect = new URL(response.headers.location!, "http://127.0.0.1");
    const code = redirect.searchParams.get("code");
    expect(code).toBeTruthy();
    expect(runtime.users.findByEmail("ada@example.com")).not.toBeNull();
    expect(runtime.credentials.getConnectionStatus(1)).toMatchObject({
      connected: true,
      edUserName: "Ada"
    });

    const tokens = await runtime.oauthProvider.exchangeAuthorizationCode(
      TEST_CLIENT,
      code!,
      undefined,
      TEST_CLIENT.redirect_uris[0]!
    );
    expect(tokens.scope).toBe("mcp:tools.read mcp:tools.write");
  });

  it("rejects invalid Ed tokens without persisting the account", async () => {
    const fakeEd = await startFakeEdServer([]);
    cleanups.push(fakeEd.close);

    const { runtime, cleanup } = await createTestRuntime({
      apiBaseUrl: fakeEd.baseUrl
    });
    cleanups.push(cleanup);
    runtime.store.saveClient(TEST_CLIENT);

    const app = createApp(runtime);
    const agent = supertest.agent(app);

    const page = await agent
      .get("/authorize")
      .query({
        client_id: TEST_CLIENT.client_id,
        code_challenge: "challenge",
        code_challenge_method: "S256",
        redirect_uri: TEST_CLIENT.redirect_uris[0],
        response_type: "code",
        scope: "mcp:tools.read"
      })
      .expect(200);

    const csrfToken = extractCsrfToken(page.text);
    await agent
      .post("/authorize")
      .type("form")
      .send({
        client_id: TEST_CLIENT.client_id,
        code_challenge: "challenge",
        code_challenge_method: "S256",
        csrf_token: csrfToken,
        ed_token: "bad-token",
        redirect_uri: TEST_CLIENT.redirect_uris[0],
        response_type: "code",
        scope: "mcp:tools.read",
        scope_read: "1",
        signup_confirm_password: "this-is-secure",
        signup_email: "ada@example.com",
        signup_password: "this-is-secure",
        tab: "signup"
      })
      .expect(422);

    expect(runtime.users.findByEmail("ada@example.com")).toBeNull();
  });
});
