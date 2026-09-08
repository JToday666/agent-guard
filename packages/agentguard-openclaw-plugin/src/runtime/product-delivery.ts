/** Product receipt confirmation is distinct from a durable local queue entry. */
export type ProductReceiptTransportResult = Readonly<{
  status: "recorded" | "retryable" | "permanent_rejected" | "failed";
  auditId?: string;
  httpStatus?: number;
  errorCode?: string;
}>;

export type ProductReceiptDeliveryResult = Readonly<{
  status: "recorded" | "queued_durable" | "permanent_rejected" | "failed";
  auditId?: string;
  httpStatus?: number;
  errorCode?: string;
}>;

export function productReceiptCompatibilityResponse(
  result: ProductReceiptDeliveryResult,
): {
  ok: boolean;
  audit_id: string;
  delivery_status: ProductReceiptDeliveryResult["status"];
  error?: string;
} {
  return {
    ok: result.status === "recorded",
    audit_id: result.auditId ?? "",
    delivery_status: result.status,
    ...(result.status === "recorded"
      ? {}
      : { error: result.errorCode ?? result.status }),
  };
}
