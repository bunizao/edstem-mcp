import type {
  Comment,
  Course,
  Lesson,
  LessonModule,
  LessonQuestion,
  LessonQuestionResponse,
  LessonSlide,
  Thread,
  ThreadMetrics,
  User,
  UserWithCourses
} from "./models.js";

export class EdApiError extends Error {
  statusCode: number;

  constructor(statusCode: number, message: string) {
    super(message);
    this.name = "EdApiError";
    this.statusCode = statusCode;
  }
}

interface EdClientOptions {
  apiBaseUrl: string;
  token: string;
}

export class EdClient {
  private readonly apiBaseUrl: string;
  private readonly token: string;

  constructor(options: EdClientOptions) {
    this.apiBaseUrl = options.apiBaseUrl;
    this.token = options.token;
  }

  async fetchUser(): Promise<UserWithCourses> {
    const data = await this.get("user");
    const userData = asRecord(data.user);
    const user = parseUser(userData);
    const courses = asArray(data.courses).map((enrollment) => {
      const record = asRecord(enrollment);
      const course = asRecord(record.course);
      const role = asRecord(record.role);
      return parseCourse(course, asString(role.role));
    });
    return { user, courses };
  }

  async fetchThreads(courseId: number, options: { limit?: number; offset?: number; sort?: string } = {}): Promise<Thread[]> {
    const data = await this.get(`courses/${courseId}/threads`, {
      limit: String(Math.min(options.limit ?? 30, 100)),
      offset: String(options.offset ?? 0),
      sort: options.sort ?? "new"
    });
    const threads = Array.isArray(data.threads) ? data.threads : Array.isArray(data) ? data : [];
    return threads.map((entry) => parseThread(asRecord(entry)));
  }

  async fetchLessons(courseId: number): Promise<{ modules: LessonModule[]; lessons: Lesson[] }> {
    const data = await this.get(`courses/${courseId}/lessons`);
    const modules = asArray(data.modules).map((entry) => parseLessonModule(asRecord(entry)));
    const moduleNames = new Map<number, string>(modules.map((module) => [module.id, module.name]));
    const lessons = asArray(data.lessons).map((entry) =>
      parseLesson(asRecord(entry), moduleNames)
    );
    return { modules, lessons };
  }

  async fetchLesson(lessonId: number): Promise<Lesson> {
    const data = await this.get(`lessons/${lessonId}`);
    return parseLesson(asRecord(data.lesson ?? data));
  }

  async fetchSlideQuestions(slideId: number): Promise<LessonQuestion[]> {
    const data = await this.get(`lessons/slides/${slideId}/questions`);
    return asArray(data.questions).map((entry) => parseLessonQuestion(asRecord(entry)));
  }

  async fetchSlideQuestionResponses(slideId: number): Promise<LessonQuestionResponse[]> {
    const data = await this.get(`lessons/slides/${slideId}/questions/responses`);
    return asArray(data.responses).map((entry) =>
      parseLessonQuestionResponse(asRecord(entry))
    );
  }

  async fetchThread(threadId: number): Promise<Thread> {
    const data = await this.get(`threads/${threadId}`);
    const users = buildUsersMap(asArray(data.users));
    return parseThread(asRecord(data.thread ?? data), users);
  }

  async fetchCourseThread(courseId: number, number: number): Promise<Thread> {
    const data = await this.get(`courses/${courseId}/threads/${number}`);
    const users = buildUsersMap(asArray(data.users));
    return parseThread(asRecord(data.thread ?? data), users);
  }

  async fetchUserActivity(
    userId: number,
    options: { courseId?: number; limit?: number; offset?: number; filterType?: string } = {}
  ): Promise<unknown[]> {
    const params: Record<string, string> = {
      limit: String(Math.min(options.limit ?? 30, 50)),
      offset: String(options.offset ?? 0),
      filter: options.filterType ?? "all"
    };

    if (options.courseId) {
      params.course_id = String(options.courseId);
    }

    const data = await this.get(`users/${userId}/profile/activity`, params);
    return asArray(data.items);
  }

  private async get(path: string, params?: Record<string, string>): Promise<Record<string, unknown>> {
    const url = new URL(path.replace(/^\/+/, ""), this.apiBaseUrl);
    for (const [key, value] of Object.entries(params ?? {})) {
      url.searchParams.set(key, value);
    }

    let response: Response;
    try {
      response = await fetch(url, {
        headers: {
          Accept: "application/json",
          Authorization: `Bearer ${this.token}`
        },
        redirect: "manual"
      });
    } catch (error) {
      throw new EdApiError(0, `Failed to reach the Ed API: ${String(error)}`);
    }

    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get("location") ?? "an unknown location";
      throw new EdApiError(
        response.status,
        `Ed API base URL redirected to ${location}. Set ED_API_BASE_URL to a valid JSON API endpoint.`
      );
    }

    const payload = await parseJson(response);
    const code = asString(payload.code);
    const message = asString(payload.message);

    if (response.status === 400 || response.status === 401 || response.status === 403) {
      if (code === "bad_token" || response.status === 401) {
        throw new EdApiError(
          response.status,
          `Authentication failed (HTTP ${response.status}). Check your Ed API token.`
        );
      }
      throw new EdApiError(response.status, formatApiError(response.status, message));
    }

    if (response.status === 404) {
      throw new EdApiError(response.status, message || `Not found: ${path}`);
    }

    if (!response.ok) {
      throw new EdApiError(response.status, formatApiError(response.status, message));
    }

    return payload;
  }
}

async function parseJson(response: Response): Promise<Record<string, unknown>> {
  try {
    const payload = await response.json();
    return asRecord(payload);
  } catch {
    throw new EdApiError(
      response.status,
      "Ed API returned a non-JSON response. Set ED_API_BASE_URL to a valid JSON API endpoint."
    );
  }
}

function formatApiError(statusCode: number, message: string): string {
  if (message) {
    return `Ed API error (HTTP ${statusCode}): ${message}`;
  }
  return `Ed API error (HTTP ${statusCode})`;
}

function buildUsersMap(entries: unknown[]): Map<number, User> {
  return new Map(
    entries
      .map((entry) => parseUser(asRecord(entry)))
      .filter((user) => user.id > 0)
      .map((user) => [user.id, user] satisfies [number, User])
  );
}

function parseUser(data: Record<string, unknown>): User {
  return {
    id: asInt(data.id),
    name: asString(data.name),
    email: asString(data.email),
    role: asString(data.role),
    courseRole: asString(data.course_role),
    avatar: asString(data.avatar)
  };
}

function parseCourse(data: Record<string, unknown>, role = ""): Course {
  return {
    id: asInt(data.id),
    code: asString(data.code),
    name: asString(data.name),
    year: asString(data.year),
    session: asString(data.session),
    status: asString(data.status),
    role
  };
}

function parseLessonModule(data: Record<string, unknown>): LessonModule {
  return {
    id: asInt(data.id),
    courseId: asInt(data.course_id),
    name: asString(data.name),
    userId: asInt(data.user_id),
    createdAt: asString(data.created_at),
    updatedAt: asString(data.updated_at)
  };
}

function parseLessonSlide(data: Record<string, unknown>): LessonSlide {
  return {
    id: asInt(data.id),
    lessonId: asInt(data.lesson_id),
    courseId: asInt(data.course_id),
    title: asString(data.title),
    type: asString(data.type),
    content: asString(data.content),
    index: asInt(data.index),
    status: asString(data.status),
    isHidden: Boolean(data.is_hidden)
  };
}

function parseLessonQuestion(data: Record<string, unknown>): LessonQuestion {
  const question = asRecord(data.data);
  return {
    id: asInt(data.id),
    slideId: asInt(data.lesson_slide_id),
    index: asInt(data.index),
    type: asString(question.type),
    content: asString(question.content),
    explanation: asString(question.explanation),
    answers: asArray(question.answers).map((value) => asString(value)),
    solution: asArray(question.solution).map((value) => asInt(value)),
    multipleSelection: Boolean(question.multiple_selection),
    isAssessed: Boolean(question.assessed),
    isFormatted: Boolean(question.formatted),
    lessonMarkableId: asInt(data.lesson_markable_id)
  };
}

function parseLessonQuestionResponse(data: Record<string, unknown>): LessonQuestionResponse {
  const correct = data.correct;
  return {
    questionId: asInt(data.question_id),
    userId: asInt(data.user_id),
    createdAt: asString(data.created_at),
    correct: typeof correct === "boolean" ? correct : null,
    data: data.data ?? null
  };
}

function parseLesson(
  data: Record<string, unknown>,
  moduleNames: Map<number, string> = new Map()
): Lesson {
  const moduleId = asInt(data.module_id);
  return {
    id: asInt(data.id),
    courseId: asInt(data.course_id),
    moduleId,
    moduleName: asString(data.module_name) || moduleNames.get(moduleId) || "",
    number: asInt(data.number),
    title: asString(data.title),
    type: asString(data.type),
    kind: asString(data.kind),
    state: asString(data.state),
    status: asString(data.status),
    outline: asString(data.outline),
    slideCount: asInt(data.slide_count),
    slides: asArray(data.slides).map((entry) => parseLessonSlide(asRecord(entry))),
    openable: Boolean(data.openable),
    openableWithoutAttempt: Boolean(data.openable_without_attempt),
    isHidden: Boolean(data.is_hidden),
    isUnlisted: Boolean(data.is_unlisted),
    isTimed: Boolean(data.is_timed),
    availableAt: asString(data.effective_available_at) || asString(data.available_at),
    dueAt: asString(data.effective_due_at) || asString(data.due_at),
    lockedAt: asString(data.effective_locked_at) || asString(data.locked_at),
    solutionsAt: asString(data.effective_solutions_at) || asString(data.solutions_at),
    createdAt: asString(data.created_at),
    updatedAt: asString(data.updated_at)
  };
}

function parseThread(
  data: Record<string, unknown>,
  usersMap: Map<number, User> = new Map()
): Thread {
  const userId = asInt(data.user_id);
  return {
    id: asInt(data.id),
    number: asInt(data.number),
    title: asString(data.title),
    content: asString(data.content),
    document: asString(data.document),
    type: asString(data.type),
    category: asString(data.category),
    subcategory: asString(data.subcategory),
    subsubcategory: asString(data.subsubcategory),
    metrics: parseThreadMetrics(data),
    answers: asArray(data.answers).map((entry) => parseComment(asRecord(entry), usersMap)),
    comments: asArray(data.comments).map((entry) => parseComment(asRecord(entry), usersMap)),
    userId,
    courseId: asInt(data.course_id),
    isPinned: Boolean(data.is_pinned),
    isPrivate: Boolean(data.is_private),
    isEndorsed: Boolean(data.is_endorsed),
    isAnswered: Boolean(data.is_answered),
    isAnonymous: Boolean(data.is_anonymous),
    isLocked: Boolean(data.is_locked),
    createdAt: asString(data.created_at),
    updatedAt: asString(data.updated_at),
    author: usersMap.get(userId) ?? null
  };
}

function parseThreadMetrics(data: Record<string, unknown>): ThreadMetrics {
  return {
    voteCount: asInt(data.vote_count),
    viewCount: asInt(data.view_count),
    uniqueViewCount: asInt(data.unique_view_count),
    replyCount: asInt(data.reply_count),
    unresolvedCount: asInt(data.unresolved_count),
    starCount: asInt(data.star_count),
    flagCount: asInt(data.flag_count)
  };
}

function parseComment(
  data: Record<string, unknown>,
  usersMap: Map<number, User> = new Map()
): Comment {
  const userId = asInt(data.user_id);
  return {
    id: asInt(data.id),
    content: asString(data.content),
    document: asString(data.document),
    type: asString(data.type),
    userId,
    voteCount: asInt(data.vote_count),
    isEndorsed: Boolean(data.is_endorsed),
    isAnonymous: Boolean(data.is_anonymous),
    isResolved: Boolean(data.is_resolved),
    createdAt: asString(data.created_at),
    comments: asArray(data.comments).map((entry) => parseComment(asRecord(entry), usersMap)),
    author: usersMap.get(userId) ?? null
  };
}

function asRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }
  return value as Record<string, unknown>;
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function asString(value: unknown): string {
  return typeof value === "string" ? value : value == null ? "" : String(value);
}

function asInt(value: unknown): number {
  if (typeof value === "number" && Number.isFinite(value)) {
    return Math.trunc(value);
  }
  if (typeof value === "string" && value.trim() !== "") {
    const parsed = Number.parseInt(value, 10);
    if (!Number.isNaN(parsed)) {
      return parsed;
    }
  }
  return 0;
}
