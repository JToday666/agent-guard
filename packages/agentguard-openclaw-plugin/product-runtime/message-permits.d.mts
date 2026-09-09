export interface ProductMessagePermitAuthorization {
  readonly runId: string;
  readonly toolCallId: string;
  readonly sessionKey: string;
  readonly toolName: string;
  readonly argumentsJson: string;
  readonly actionId: string;
  assertCanSend(): void;
  assertReadyToSend(): Promise<void>;
  onMessageDelivered(messageId: string): void;
}
declare const bridgeBrand: unique symbol;
export interface ProductMessagePermitBridge {
  readonly [bridgeBrand]: true;
  authorize(released: ProductMessagePermitAuthorization): void;
  prepareSendPayload(value: unknown): unknown;
  claimSend(value: unknown): Readonly<{
    to: string;
    text: string;
    assertCanSend(): void;
    assertReadyToSend(): Promise<void>;
    delivered(messageId: string): void;
  }>;
  close(): void;
}
export declare function createMessagePermitBridge(options: {
  sessionKey: string;
  inboxTarget?: string;
  accountId?: string;
}): ProductMessagePermitBridge;
export declare function isMessagePermitBridge(
  value: unknown,
): value is ProductMessagePermitBridge;
