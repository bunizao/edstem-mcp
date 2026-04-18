import type { AddressInfo } from "node:net";
import { once } from "node:events";

import express from "express";

export interface FakeEdUser {
  answerResult?: {
    correct?: boolean | null;
    explanation?: unknown;
    slide_completed?: boolean;
    solution?: unknown;
  };
  courses: Array<{
    course: {
      code: string;
      id: number;
      name: string;
      session: string;
      status: string;
      year: string;
    };
    role: {
      role: string;
    };
  }>;
  token: string;
  user: {
    avatar: string;
    course_role: string;
    email: string;
    id: number;
    name: string;
    role: string;
  };
}

export async function startFakeEdServer(users: FakeEdUser[]) {
  const app = express();
  app.use(express.json());

  const submissions = {
    answers: [] as Array<{
      amend: boolean;
      body: unknown;
      questionId: number;
      token: string;
    }>,
    slides: [] as Array<{
      slideId: number;
      token: string;
    }>
  };

  const byToken = new Map(users.map((user) => [user.token, user]));

  app.get("/api/user", (request, response) => {
    const user = getUser(request.header("authorization"), byToken);
    if (!user) {
      response.status(401).json({ code: "bad_token", message: "invalid token" });
      return;
    }

    response.json({
      courses: user.courses,
      user: user.user
    });
  });

  app.post("/api/lessons/slides/questions/:questionId/responses", (request, response) => {
    const user = getUser(request.header("authorization"), byToken);
    if (!user) {
      response.status(401).json({ code: "bad_token", message: "invalid token" });
      return;
    }

    submissions.answers.push({
      amend: request.query.amend === "1",
      body: request.body,
      questionId: Number.parseInt(request.params.questionId, 10),
      token: user.token
    });

    response.json({
      correct: user.answerResult?.correct ?? true,
      explanation: user.answerResult?.explanation ?? null,
      slide_completed: user.answerResult?.slide_completed ?? true,
      solution: user.answerResult?.solution ?? [1]
    });
  });

  app.post("/api/lessons/slides/:slideId/questions/submit_all", (request, response) => {
    const user = getUser(request.header("authorization"), byToken);
    if (!user) {
      response.status(401).json({ code: "bad_token", message: "invalid token" });
      return;
    }

    submissions.slides.push({
      slideId: Number.parseInt(request.params.slideId, 10),
      token: user.token
    });

    response.json({ submitted: true });
  });

  const server = app.listen(0);
  await once(server, "listening");
  const address = server.address() as AddressInfo;

  return {
    baseUrl: `http://127.0.0.1:${address.port}/api/`,
    close: async () => {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => {
          if (error) {
            reject(error);
            return;
          }
          resolve();
        });
      });
    },
    submissions
  };
}

function getUser(
  authorization: string | undefined,
  byToken: Map<string, FakeEdUser>
): FakeEdUser | undefined {
  const token = authorization?.replace(/^Bearer\s+/i, "") || "";
  return byToken.get(token);
}
