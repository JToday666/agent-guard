export declare class FixtureError extends Error {
  readonly code: string;
  constructor(code: string);
}
export declare function requireAcceptanceRoot(value: unknown): string;
export declare function createFixtureMemory(
  root: string,
  options?: { productMode?: boolean },
): Readonly<{
  read(parameters: { key: string }): {
    key: string;
    value: string | null;
    found?: boolean;
  };
  write(parameters: { key: string; value: string }): {
    key: string;
    written: true;
  };
}>;
