export function isApprovalExpired(value: string | null | undefined, nowMs: number): boolean {
  if (!value) return false;
  const expiresAtMs = Date.parse(value);
  return Number.isFinite(expiresAtMs) && expiresAtMs <= nowMs;
}

export function formatRelativeApprovalExpiry(
  value: string | null | undefined,
  nowMs: number,
): string {
  if (!value) return "到期时间未知";
  const expiresAtMs = Date.parse(value);
  if (!Number.isFinite(expiresAtMs)) return "到期时间未知";
  const minutes = Math.ceil((expiresAtMs - nowMs) / 60_000);
  return minutes <= 0 ? "已过期" : `${minutes} 分钟后过期`;
}
