import assert from "node:assert/strict";
import test from "node:test";

import { createCsvDocument, escapeCsvCell } from "./csv-export.ts";

test("escapes quotes and preserves multiline text", () => {
  assert.equal(escapeCsvCell('a"b\nc'), '"a""b\nc"');
});

test("neutralizes spreadsheet formulas after optional whitespace", () => {
  for (const value of [
    "=2+2",
    "+cmd",
    "-1+2",
    "@SUM(A1:A2)",
    '  =HYPERLINK("https://example.invalid")',
    "\t=cmd",
  ]) {
    assert.equal(escapeCsvCell(value).startsWith("\"'"), true);
  }
});

test("creates a CRLF CSV document with stable empty values", () => {
  assert.equal(
    createCsvDocument(
      ["名称", "值"],
      [
        ["普通", null],
        ["数量", 0],
      ],
    ),
    '"名称","值"\r\n"普通",""\r\n"数量","0"',
  );
});
