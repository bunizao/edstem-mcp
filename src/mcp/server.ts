import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import type { AppConfig } from "../config.js";
import { EdApiError, EdClient } from "../ed/client.js";
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

const MAX_THREAD_FETCH = 100;
const MAX_ACTIVITY_FETCH = 50;
const THREAD_SORT_OPTIONS = ["new", "old", "top", "hot"] as const;
const ACTIVITY_FILTERS = ["all", "thread", "answer", "comment"] as const;
const READ_ONLY_ANNOTATIONS = {
  destructiveHint: false,
  readOnlyHint: true
} as const;

export function createServer(config: AppConfig): McpServer {
  const server = new McpServer({
    name: "edstem-mcp",
    version: "0.1.0"
  });

  server.registerTool(
    "get_user",
    {
      annotations: READ_ONLY_ANNOTATIONS,
      description: "Get the current Ed user profile and enrolled courses."
    },
    async () => {
      const client = createClient(config);
      const result = await client.fetchUser();
      return jsonResult({
        ...serializeUser(result.user),
        courses: result.courses.map((course) => serializeCourse(course))
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
    async ({ includeArchived }) => {
      const client = createClient(config);
      const result = await client.fetchUser();
      const courses = includeArchived
        ? result.courses
        : result.courses.filter((course) => course.status.toLowerCase() !== "archived");
      return jsonResult(courses.map((course) => serializeCourse(course)));
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
    async ({ courseId, module, lessonType, state, status }) => {
      const client = createClient(config);
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
        modules: result.modules.map((moduleEntry) => serializeLessonModule(moduleEntry)),
        lessons: lessons.map((lesson) => serializeLesson(lesson))
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
    async ({ lessonId }) => {
      const client = createClient(config);
      const lesson = await client.fetchLesson(lessonId);
      return jsonResult(serializeLesson(lesson));
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
    async ({ slideId }) => {
      const client = createClient(config);
      const questions = await client.fetchSlideQuestions(slideId);
      return jsonResult(questions.map((question) => serializeLessonQuestion(question)));
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
    async ({ slideId }) => {
      const client = createClient(config);
      const responses = await client.fetchSlideQuestionResponses(slideId);
      return jsonResult(
        responses.map((response) => serializeLessonQuestionResponse(response))
      );
    }
  );

  server.registerTool(
    "list_threads",
    {
      annotations: READ_ONLY_ANNOTATIONS,
      description: "List threads in a course with optional filters.",
      inputSchema: {
        courseId: z.number().int().positive(),
        limit: z.number().int().positive().max(MAX_THREAD_FETCH).optional().default(30),
        sort: z.enum(THREAD_SORT_OPTIONS).optional().default("new"),
        category: z.string().trim().min(1).optional(),
        threadType: z.string().trim().min(1).optional(),
        answered: z.boolean().optional()
      }
    },
    async ({ courseId, limit, sort, category, threadType, answered }) => {
      const client = createClient(config);
      const threads = await client.fetchThreads(courseId, { limit, sort });
      const filtered = filterThreads(threads, { answered, category, threadType });
      return jsonResult(filtered.map((thread) => serializeThread(thread)));
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
    async ({ threadId }) => {
      const client = createClient(config);
      const thread = await client.fetchThread(threadId);
      return jsonResult(serializeThread(thread));
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
    async ({ courseId, number }) => {
      const client = createClient(config);
      const thread = await client.fetchCourseThread(courseId, number);
      return jsonResult(serializeThread(thread));
    }
  );

  server.registerTool(
    "list_activity",
    {
      annotations: READ_ONLY_ANNOTATIONS,
      description: "List activity items for the current user, optionally scoped to one course.",
      inputSchema: {
        courseId: z.number().int().positive().optional(),
        limit: z.number().int().positive().max(MAX_ACTIVITY_FETCH).optional().default(30),
        filterType: z.enum(ACTIVITY_FILTERS).optional().default("all")
      }
    },
    async ({ courseId, limit, filterType }) => {
      const client = createClient(config);
      const result = await client.fetchUser();
      const items = await client.fetchUserActivity(result.user.id, {
        courseId,
        limit,
        filterType
      });
      return jsonResult(items);
    }
  );

  return server;
}

function createClient(config: AppConfig): EdClient {
  return new EdClient({
    apiBaseUrl: config.apiBaseUrl,
    token: config.edApiToken
  });
}

function jsonResult(payload: unknown) {
  return {
    content: [
      {
        type: "text" as const,
        text: JSON.stringify(payload, null, 2)
      }
    ]
  };
}

export function mapToolError(error: unknown): Error {
  if (error instanceof EdApiError) {
    return new Error(error.message);
  }
  if (error instanceof Error) {
    return error;
  }
  return new Error(String(error));
}
