export declare const DEFAULT_INBOX_TARGET: "fixture-inbox";
export declare const PRODUCT_INBOX_TARGET: "fixture-inbox@agentguard.invalid";
export declare const MAX_MESSAGE_BYTES: 32768;
export declare function validateInboxUrl(value: unknown): URL;
export declare function validateInboxTarget(value: unknown): string;
export declare function startFixtureInbox(options: {
  acceptanceRoot: string;
  target?: string;
  port?: number;
}): Promise<
  Readonly<{
    url: string;
    target: string;
    readMessages(): { messageId: string; target: string; text: string }[];
    close(): Promise<void>;
  }>
>;
export declare function deliverInboxMessage(options: {
  inboxUrl: string;
  inboxTarget?: string;
  to: string;
  text: string;
}): Promise<{ messageId: string }>;
