import { afterEach, describe, expect, it } from "bun:test";

import {
  DuplicateEmailError,
  InvalidCredentialsError
} from "../../src/users/service.js";
import { createTestRuntime } from "../support/test-runtime.js";

describe("users service", () => {
  const cleanups: Array<() => Promise<void>> = [];

  afterEach(async () => {
    while (cleanups.length > 0) {
      await cleanups.pop()?.();
    }
  });

  it("registers and authenticates a user", async () => {
    const { runtime, cleanup } = await createTestRuntime({
      apiBaseUrl: "http://127.0.0.1:1/api/"
    });
    cleanups.push(cleanup);

    await runtime.users.register({
      email: "ada@example.com",
      password: "this-is-secure",
      displayName: "Ada"
    });

    const user = await runtime.users.authenticate("ada@example.com", "this-is-secure");
    expect(user.email).toBe("ada@example.com");
    expect(user.displayName).toBe("Ada");
  });

  it("rejects duplicate emails", async () => {
    const { runtime, cleanup } = await createTestRuntime({
      apiBaseUrl: "http://127.0.0.1:1/api/"
    });
    cleanups.push(cleanup);

    await runtime.users.register({
      email: "ada@example.com",
      password: "this-is-secure"
    });

    await expect(
      runtime.users.register({
        email: "Ada@Example.com",
        password: "this-is-secure"
      })
    ).rejects.toBeInstanceOf(DuplicateEmailError);
  });

  it("rejects the wrong password", async () => {
    const { runtime, cleanup } = await createTestRuntime({
      apiBaseUrl: "http://127.0.0.1:1/api/"
    });
    cleanups.push(cleanup);

    await runtime.users.register({
      email: "ada@example.com",
      password: "this-is-secure"
    });

    await expect(
      runtime.users.authenticate("ada@example.com", "wrong-password")
    ).rejects.toBeInstanceOf(InvalidCredentialsError);
  });
});
