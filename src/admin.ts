import { randomBytes } from "node:crypto";

import { loadConfig } from "./config.js";
import { createRuntime } from "./runtime.js";

async function main(): Promise<void> {
  const [command, email, passwordArg] = process.argv.slice(2);
  if (command !== "reset-password" || !email) {
    throw new Error("Usage: npm run admin -- reset-password <email> [new-password]");
  }

  const config = loadConfig();
  const runtime = createRuntime(config);

  try {
    const user = runtime.users.findByEmail(email);
    if (!user) {
      throw new Error(`User not found: ${email}`);
    }

    const password = passwordArg || randomBytes(12).toString("base64url");
    await runtime.users.resetPassword(user.id, password);
    console.log(password);
  } finally {
    runtime.close();
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
