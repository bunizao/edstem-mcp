import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { z } from "zod";

import type { AppConfig } from "../config.js";
import {
  EdApiError,
  EdAuthExpiredError,
  EdClient,
} from "../ed/client.js";
import { filterThreads } from "../ed/filter.js";
import {
  serializeCourse,
  serializeLesson,
  serializeLessonModule,
  serializeLessonQuestion,
  serializeLessonQuestionResponse,
  serializeThread,
  serializeUser
} from "../ed/serialization.js";
import type { CredentialsService } from "../credentials/service.js";
import {
  EdNotConnectedError,
  EdReconnectRequiredError
} from "../credentials/service.js";

const MAX_THREAD_FETCH = 100;
const MAX_ACTIVITY_FETCH = 50;
const THREAD_SORT_OPTIONS = ["new", "old", "top", "hot"] as const;
const ACTIVITY_FILTERS = ["all", "thread", "answer", "comment"] as const;
const READ_ONLY_ANNOTATIONS = {
  destructiveHint: false,
  readOnlyHint: true
} as const;
const WRITE_ANNOTATIONS = {
  destructiveHint: true,
  readOnlyHint: false
} as const;

export function createServer(
  config: AppConfig,
  credentials: CredentialsService
): McpServer {
  const server = new McpServer({
    name: "edstem-mcp",
    version: "0.2.0"
  });

  server.registerTool(
    "get_user",
    {
      annotations: READ_ONLY_ANNOTATIONS,
      description: "Get the current Ed user profile and enrolled courses."
    },
    async (extra) => {
      return runReadTool(extra, config, credentials, async (client) => {
        const result = await client.fetchUser();
        return jsonResult({
          ...serializeUser(result.user),
          courses: result.courses.map((course) => serializeCourse(course))
        });
      });
    }
  );

  server.registerTool(
    "list_courses",
    {
      annotations: READ_ONLY_ANNOTATIONS,
      description: "List enrolled Ed courses.",
      inputSchema: {
        includeArchived: z.boolean().optional().default(false)
      }
    },
    async ({ includeArchived }, extra) => {
      return runReadTool(extra, config, credentials, async (client) => {
        const result = await client.fetchUser();
        const courses = includeArchived
          ? result.courses
          : result.courses.filter((course) => course.status.toLowerCase() !== "archived");
        return jsonResult(courses.map((course) => serializeCourse(course)));
      });
    }
  );

  server.registerTool(
    "list_lessons",
    {
      annotations: READ_ONLY_ANNOTATIONS,
      description: "List lessons in an Ed course with optional filters.",
      inputSchema: {
        courseId: z.number().int().positive(),
        module: z.string().trim().min(1).optional(),
        lessonType: z.string().trim().min(1).optional(),
        state: z.string().trim().min(1).optional(),
        status: z.string().trim().min(1).optional()
      }
    },
    async ({ courseId, module, lessonType, state, status }, extra) => {
      return runReadTool(extra, config, credentials, async (client) => {
        const result = await client.fetchLessons(courseId);
        const lessons = result.lessons.filter((lesson) => {
          if (module) {
            const query = module.toLowerCase();
            const moduleId = String(lesson.moduleId).toLowerCase();
            const moduleName = lesson.moduleName.toLowerCase();
            if (moduleId !== query && !moduleName.includes(query)) {
              return false;
            }
          }
          if (lessonType && lesson.type.toLowerCase() !== lessonType.toLowerCase()) {
            return false;
          }
          if (state && lesson.state.toLowerCase() !== state.toLowerCase()) {
            return false;
          }
          if (status && lesson.status.toLowerCase() !== status.toLowerCase()) {
            return false;
          }
          return true;
        });

        return jsonResult({
          lessons: lessons.map((lesson) => serializeLesson(lesson)),
          modules: result.modules.map((moduleEntry) => serializeLessonModule(moduleEntry))
        });
      });
    }
  );

  server.registerTool(
    "get_lesson",
    {
      annotations: READ_ONLY_ANNOTATIONS,
      description: "Get a lesson with slide content.",
      inputSchema: {
        lessonId: z.number().int().positive()
      }
    },
    async ({ lessonId }, extra) => {
      return runReadTool(extra, config, credentials, async (client) => {
        const lesson = await client.fetchLesson(lessonId);
        return jsonResult(serializeLesson(lesson));
      });
    }
  );

  server.registerTool(
    "list_slide_questions",
    {
      annotations: READ_ONLY_ANNOTATIONS,
      description: "List quiz questions for a lesson slide.",
      inputSchema: {
        slideId: z.number().int().positive()
      }
    },
    async ({ slideId }, extra) => {
      return runReadTool(extra, config, credentials, async (client) => {
        const questions = await client.fetchSlideQuestions(slideId);
        return jsonResult(questions.map((question) => serializeLessonQuestion(question)));
      });
    }
  );

  server.registerTool(
    "list_slide_responses",
    {
      annotations: READ_ONLY_ANNOTATIONS,
      description: "List saved quiz responses for a lesson slide.",
      inputSchema: {
        slideId: z.number().int().positive()
      }
    },
    async ({ slideId }, extra) => {
      return runReadTool(extra, config, credentials, async (client) => {
        const responses = await client.fetchSlideQuestionResponses(slideId);
        return jsonResult(
          responses.map((response) => serializeLessonQuestionResponse(response))
        );
      });
    }
  );

  server.registerTool(
    "list_threads",
    {
      annotations: READ_ONLY_ANNOTATIONS,
      description: "List threads in a course with optional filters.",
      inputSchema: {
        answered: z.boolean().optional(),
        category: z.string().trim().min(1).optional(),
        courseId: z.number().int().positive(),
        limit: z.number().int().positive().max(MAX_THREAD_FETCH).optional().default(30),
        sort: z.enum(THREAD_SORT_OPTIONS).optional().default("new"),
        threadType: z.string().trim().min(1).optional()
      }
    },
    async ({ answered, category, courseId, limit, sort, threadType }, extra) => {
      return runReadTool(extra, config, credentials, async (client) => {
        const threads = await client.fetchThreads(courseId, { limit, sort });
        const filtered = filterThreads(threads, { answered, category, threadType });
        return jsonResult(filtered.map((thread) => serializeThread(thread)));
      });
    }
  );

  server.registerTool(
    "get_thread",
    {
      annotations: READ_ONLY_ANNOTATIONS,
      description: "Get a thread by thread ID.",
      inputSchema: {
        threadId: z.number().int().positive()
      }
    },
    async ({ threadId }, extra) => {
      return runReadTool(extra, config, credentials, async (client) => {
        const thread = await client.fetchThread(threadId);
        return jsonResult(serializeThread(thread));
      });
    }
  );

  server.registerTool(
    "get_course_thread",
    {
      annotations: READ_ONLY_ANNOTATIONS,
      description: "Get a thread by course ID and course-local thread number.",
      inputSchema: {
        courseId: z.number().int().positive(),
        number: z.number().int().positive()
      }
    },
    async ({ courseId, number }, extra) => {
      return runReadTool(extra, config, credentials, async (client) => {
        const thread = await client.fetchCourseThread(courseId, number);
        return jsonResult(serializeThread(thread));
      });
    }
  );

  server.registerTool(
    "list_activity",
    {
      annotations: READ_ONLY_ANNOTATIONS,
      description: "List activity items for the current user, optionally scoped to one course.",
      inputSchema: {
        courseId: z.number().int().positive().optional(),
        filterType: z.enum(ACTIVITY_FILTERS).optional().default("all"),
        limit: z.number().int().positive().max(MAX_ACTIVITY_FETCH).optional().default(30)
      }
    },
    async ({ courseId, filterType, limit }, extra) => {
      return runReadTool(extra, config, credentials, async (client) => {
        const result = await client.fetchUser();
        const items = await client.fetchUserActivity(result.user.id, {
          courseId,
          filterType,
          limit
        });
        return jsonResult(items);
      });
    }
  );

  server.registerTool(
    "submit_slide_answer",
    {
      annotations: WRITE_ANNOTATIONS,
      description: "Submit a quiz answer on the user's behalf.",
      inputSchema: {
        amend: z.boolean().optional().default(false),
        choices: z.array(z.number().int().positive()).optional().default([]),
        questionId: z.number().int().positive()
      }
    },
    async ({ amend, choices, questionId }, extra) => {
      return runTool(extra, config, credentials, true, async (client) => {
        const result = await client.submitSlideAnswer(
          questionId,
          choices.map((choice) => choice - 1),
          { amend }
        );
        return jsonResult(result);
      });
    }
  );

  server.registerTool(
    "submit_slide",
    {
      annotations: WRITE_ANNOTATIONS,
      description: "Submit all saved slide answers on the user's behalf.",
      inputSchema: {
        slideId: z.number().int().positive()
      }
    },
    async ({ slideId }, extra) => {
      return runTool(extra, config, credentials, true, async (client) => {
        const result = await client.submitSlide(slideId);
        return jsonResult(result);
      });
    }
  );

  return server;
}

async function runTool(
  extra: {
    authInfo?: AuthInfo;
  },
  config: AppConfig,
  credentials: CredentialsService,
  requiresWriteScope: boolean,
  fn: (client: EdClient, userId?: number) => Promise<ToolResult>
): Promise<ToolResult> {
  try {
    if (requiresWriteScope && !hasWriteScope(extra, config)) {
      return jsonError("INSUFFICIENT_SCOPE", "Write access is required for this tool.");
    }

    const { client, userId } = resolveClient(extra, config, credentials);
    const result = await fn(client, userId);
    return result;
  } catch (error) {
    return handleToolError(error, extra, credentials, config);
  }
}

async function runReadTool(
  extra: {
    authInfo?: AuthInfo;
  },
  config: AppConfig,
  credentials: CredentialsService,
  fn: (client: EdClient, userId?: number) => Promise<ToolResult>
): Promise<ToolResult> {
  return runTool(extra, config, credentials, false, fn);
}

function resolveClient(
  extra: {
    authInfo?: AuthInfo;
  },
  config: AppConfig,
  credentials: CredentialsService
): { client: EdClient; userId?: number } {
  const userId = extra.authInfo?.extra?.userId;
  if (typeof userId === "number") {
    const token = credentials.getDecryptedEdToken(userId);
    return {
      client: new EdClient({
        apiBaseUrl: config.apiBaseUrl,
        token
      }),
      userId
    };
  }

  if (config.devEdApiToken) {
    return {
      client: new EdClient({
        apiBaseUrl: config.apiBaseUrl,
        token: config.devEdApiToken
      })
    };
  }

  throw new EdNotConnectedError();
}

function hasWriteScope(
  extra: {
    authInfo?: AuthInfo;
  },
  config: AppConfig
): boolean {
  if (!extra.authInfo) {
    return Boolean(config.devEdApiToken);
  }
  return extra.authInfo.scopes.includes(config.oauth.writeScope);
}

function handleToolError(
  error: unknown,
  extra: {
    authInfo?: AuthInfo;
  },
  credentials: CredentialsService,
  config: AppConfig
): ToolResult {
  if (error instanceof EdAuthExpiredError && typeof extra.authInfo?.extra?.userId === "number") {
    credentials.markInvalid(extra.authInfo.extra.userId);
    return jsonError(
      "EDSTEM_REAUTH_REQUIRED",
      "Ed Discussion credentials expired or are no longer valid.",
      {
        reconnect_url: new URL("/reconnect", config.publicBaseUrl).toString()
      }
    );
  }

  if (error instanceof EdNotConnectedError) {
    return jsonError("EDSTEM_NOT_CONNECTED", error.message);
  }

  if (error instanceof EdReconnectRequiredError) {
    return jsonError(
      "EDSTEM_REAUTH_REQUIRED",
      error.message,
      {
        reconnect_url: new URL("/reconnect", config.publicBaseUrl).toString()
      }
    );
  }

  if (error instanceof EdApiError) {
    return jsonError("EDSTEM_API_ERROR", error.message, { statusCode: error.statusCode });
  }

  if (error instanceof Error) {
    return jsonError("EDSTEM_UPSTREAM_ERROR", error.message);
  }

  return jsonError("EDSTEM_UPSTREAM_ERROR", String(error));
}

type ToolResult = {
  content: Array<{ text: string; type: "text" }>;
  isError?: boolean;
  structuredContent?: Record<string, unknown>;
};

function jsonResult(payload: unknown): ToolResult {
  const structuredContent = asRecord(payload);
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(payload, null, 2)
      }
    ],
    ...(structuredContent ? { structuredContent } : {})
  };
}

function jsonError(
  type: string,
  message: string,
  extra: Record<string, unknown> = {}
): ToolResult {
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(
          {
            error: {
              ...extra,
              message,
              type
            }
          },
          null,
          2
        )
      }
    ],
    isError: true,
    structuredContent: {
      error: {
        ...extra,
        message,
        type
      }
    }
  };
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}
