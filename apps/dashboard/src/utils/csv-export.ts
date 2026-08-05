export type CsvCell = boolean | number | string | null | undefined;

const FORMULA_PREFIX = /^\s*[=+\-@]/u;

export function escapeCsvCell(value: CsvCell): string {
  const normalized = value == null ? "" : String(value).replace(/\0/g, "");
  const safeValue =
    FORMULA_PREFIX.test(normalized) || /^[\t\r\n]/u.test(normalized)
      ? `'${normalized}`
      : normalized;
  return `"${safeValue.replace(/"/g, '""')}"`;
}

export function createCsvDocument(headers: CsvCell[], rows: CsvCell[][]): string {
  return [headers, ...rows].map((row) => row.map(escapeCsvCell).join(",")).join("\r\n");
}

export function downloadCsv(filename: string, headers: CsvCell[], rows: CsvCell[][]): void {
  const csv = createCsvDocument(headers, rows);
  const blob = new Blob(["\uFEFF", csv], {
    type: "text/csv;charset=utf-8",
  });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}
