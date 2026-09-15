// Local pi extension API type surface.
// Shapes confirmed from @earendil-works/pi-coding-agent@0.85.1 .d.ts.
// Only index.ts imports from the actual package; everything else uses these types.

export interface ImageContent {
  type: "image";
  source: { type: string; data: string; media_type: string };
}

export interface TextContent {
  type: "text";
  text: string;
}

export type ContentBlock = TextContent | ImageContent;

export type InputSource = "interactive" | "rpc" | "extension";

export interface InputEvent {
  type: "input";
  text: string;
  images?: ImageContent[];
  source: InputSource;
}

export type InputEventResult =
  | { action: "continue" }
  | { action: "transform"; text: string; images?: ImageContent[] }
  | { action: "handled" };

export interface ToolCallEvent {
  type: "tool_call";
  toolCallId: string;
  toolName: string;
  input: Record<string, unknown>;
}

export interface ToolCallEventResult {
  block?: boolean;
  reason?: string;
  terminate?: boolean;
}

export interface ToolResultEvent {
  type: "tool_result";
  toolCallId: string;
  toolName: string;
  input: Record<string, unknown>;
  content: ContentBlock[];
  isError: boolean;
}

export interface ToolResultEventResult {
  content?: ContentBlock[];
}

export interface BeforeProviderRequestEvent {
  type: "before_provider_request";
  payload: unknown;
}

export interface SessionStartEvent {
  type: "session_start";
}

export interface SessionShutdownEvent {
  type: "session_shutdown";
}

export interface MarkdownTransformContext {
  messageType: "user" | "assistant" | "assistant-thinking";
  isStreaming: boolean;
  availableWidth: number;
}

export interface ExtensionUIContext {
  notify(message: string, type?: "info" | "warning" | "error"): void;
  setStatus(key: string, text: string | undefined): void;
  confirm(title: string, message: string): Promise<boolean>;
}

export interface ExtensionContext {
  ui: ExtensionUIContext;
  cwd: string;
  isProjectTrusted(): boolean;
  abort(): void;
}

export interface ExtensionCommandContext extends ExtensionContext {
  // Command contexts have additional session control methods not needed here
}

export type ExtensionHandler<E, R = undefined> = (
  event: E,
  ctx: ExtensionContext,
) => Promise<R | void> | R | void;

export type MarkdownTransformer = (
  markdown: string,
  context: MarkdownTransformContext,
) => string;

export interface ExtensionAPI {
  on(
    event: "session_start",
    handler: ExtensionHandler<SessionStartEvent>,
  ): void;
  on(
    event: "session_shutdown",
    handler: ExtensionHandler<SessionShutdownEvent>,
  ): void;
  on(
    event: "input",
    handler: ExtensionHandler<InputEvent, InputEventResult>,
  ): void;
  on(
    event: "tool_call",
    handler: ExtensionHandler<ToolCallEvent, ToolCallEventResult>,
  ): void;
  on(
    event: "tool_result",
    handler: ExtensionHandler<ToolResultEvent, ToolResultEventResult>,
  ): void;
  on(
    event: "before_provider_request",
    handler: ExtensionHandler<BeforeProviderRequestEvent, unknown>,
  ): void;
  registerCommand(
    name: string,
    options: {
      description?: string;
      handler: (args: string, ctx: ExtensionCommandContext) => Promise<void>;
    },
  ): void;
  registerMarkdownTransformer(transformer: MarkdownTransformer): void;
  appendEntry<T>(customType: string, data?: T): void;
}

export interface Span {
  start: number;
  end: number;
  type: string;
  score: number;
  detector: string;
}
