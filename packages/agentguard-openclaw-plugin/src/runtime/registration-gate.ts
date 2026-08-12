/**
 * Registration gating for the OpenClaw plugin entry.
 *
 * The gate only describes structural categories of the configuration; its
 * reasons must never contain token values or other secret material.
 */
export type PluginRegistrationGateInput = {
  /**
   * `api.registrationMode` as provided by OpenClaw. It is `undefined` for
   * in-process direct registration (deterministic E2E and unit tests).
   */
  registrationMode: string | undefined;
  /** Raw persisted `adapterToken` from the runtime config source snapshot. */
  persistentAdapterToken: unknown;
  /** `api.pluginConfig.adapterToken` as resolved for this registration. */
  runtimeAdapterToken: unknown;
  /** SecretRef shape check, injected so the gate stays dependency-free. */
  isSecretRef: (value: unknown) => boolean;
};

export type PluginRegistrationDecision = {
  action: "register" | "skip";
  reason: string;
  failClosed: boolean;
};

/**
 * Decide whether `register()` should perform the full registration.
 *
 * - A defined non-`full` registration mode skips silently (discovery, CLI
 *   metadata and setup passes must not read credentials or register hooks).
 * - `full` registration requires the persisted value to be a SecretRef and
 *   the runtime value to be the non-empty resolved string; anything else
 *   fails closed.
 * - An undefined mode keeps the in-process compatibility path, whose token
 *   validation is owned by the caller.
 */
export function evaluatePluginRegistration(
  input: PluginRegistrationGateInput,
): PluginRegistrationDecision {
  const {
    registrationMode,
    persistentAdapterToken,
    runtimeAdapterToken,
    isSecretRef,
  } = input;

  if (registrationMode === undefined) {
    return {
      action: "register",
      reason: "registration mode is undefined; in-process compatibility path",
      failClosed: false,
    };
  }

  if (registrationMode !== "full") {
    return {
      action: "skip",
      reason: `registration mode "${registrationMode}" does not register hooks`,
      failClosed: false,
    };
  }

  if (!isSecretRef(persistentAdapterToken)) {
    return {
      action: "skip",
      reason: "persistent adapterToken is not a SecretRef",
      failClosed: true,
    };
  }

  if (
    typeof runtimeAdapterToken !== "string" ||
    runtimeAdapterToken.trim().length === 0
  ) {
    return {
      action: "skip",
      reason:
        "runtime adapterToken was not resolved to a non-empty secret string",
      failClosed: true,
    };
  }

  return {
    action: "register",
    reason: "persisted SecretRef adapterToken resolved for full registration",
    failClosed: false,
  };
}
