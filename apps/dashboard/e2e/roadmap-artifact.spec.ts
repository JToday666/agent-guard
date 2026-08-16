import { expect, test, type Page } from "@playwright/test";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const testDirectory = path.dirname(fileURLToPath(import.meta.url));
const artifactPath = path.resolve(
  testDirectory,
  "../../../docs/06_delivery/roadmap/generated/index.html",
);
const artifactUrl = pathToFileURL(artifactPath).href;

async function openArtifact(page: Page, hash = ""): Promise<void> {
  expect(existsSync(artifactPath), `missing generated roadmap: ${artifactPath}`).toBe(true);
  await page.goto(`${artifactUrl}${hash}`, { waitUntil: "load" });
  await expect(page.getByTestId("roadmap-graph")).toBeVisible();
}

function roadmapNode(page: Page, nodeId: string) {
  return page.locator(`[data-node-id="${nodeId}"]`);
}

test("renders a self-contained graph with distinct four-state colors", async ({ page }) => {
  const consoleErrors: string[] = [];
  const pageErrors: string[] = [];
  const externalRequests: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error") consoleErrors.push(message.text());
  });
  page.on("pageerror", (error) => pageErrors.push(error.message));
  page.on("request", (request) => {
    const protocol = new URL(request.url()).protocol;
    if (!new Set(["file:", "data:", "blob:"]).has(protocol)) {
      externalRequests.push(request.url());
    }
  });

  await openArtifact(page);

  const graph = page.getByTestId("roadmap-graph");
  await expect(graph.locator("svg")).toBeVisible();
  await expect(graph.locator("[data-node-id]").first()).toBeVisible();

  const statuses = ["completed", "in_progress", "ready", "not_ready"];
  const colorSignatures: string[] = [];
  for (const status of statuses) {
    const node = graph.locator(`[data-status="${status}"]`).first();
    await expect(node, `missing ${status} roadmap node`).toBeVisible();
    colorSignatures.push(
      await node.evaluate((element) =>
        Array.from(element.querySelectorAll("rect, circle, ellipse, path, polygon"))
          .map((shape) => {
            const style = getComputedStyle(shape);
            return `${style.fill}|${style.stroke}|${style.color}`;
          })
          .join(";"),
      ),
    );
  }
  expect(new Set(colorSignatures).size).toBe(statuses.length);

  expect(externalRequests).toEqual([]);
  expect(consoleErrors).toEqual([]);
  expect(pageErrors).toEqual([]);
});

test("searches and filters nodes while preserving the derived Ready Queue", async ({ page }) => {
  await openArtifact(page);

  const search = page.getByTestId("roadmap-search");
  await search.fill("CT03R");
  await expect(roadmapNode(page, "CT03R")).toBeVisible();
  await expect(roadmapNode(page, "FE04")).toBeHidden();
  await search.fill("");

  const completedFilter = page.getByTestId("status-filter-completed");
  await expect(completedFilter).toBeChecked();
  await completedFilter.uncheck();
  await expect(roadmapNode(page, "FE04")).toBeHidden();
  await expect(roadmapNode(page, "CT03R")).toBeVisible();
  await completedFilter.check();
  await expect(roadmapNode(page, "FE04")).toBeVisible();

  const readyQueue = page.getByTestId("ready-queue");
  await expect(readyQueue).toBeVisible();
  for (const nodeId of ["RSC-CT01", "CT05", "CT03R"]) {
    await expect(readyQueue.locator(`[data-node-ref="${nodeId}"]`)).toBeVisible();
  }
  await expect(readyQueue.locator('[data-node-ref="FE04"]')).toHaveCount(0);
});

test("opens the evidence drawer from hash, pointer, and keyboard navigation", async ({ page }) => {
  await openArtifact(page, "#node=C10");

  const drawer = page.getByTestId("node-drawer");
  await expect(drawer).toBeVisible();
  await expect(drawer).toContainText("C10");
  expect(decodeURIComponent(new URL(page.url()).hash)).toBe("#node=C10");

  await page.keyboard.press("Escape");
  await expect(drawer).toBeHidden();

  await roadmapNode(page, "FE04").click();
  await expect(drawer).toBeVisible();
  await expect(drawer).toContainText("FE04");
  expect(decodeURIComponent(new URL(page.url()).hash)).toBe("#node=FE04");
  await page.getByTestId("drawer-close").click();
  await expect(drawer).toBeHidden();

  const keyboardNode = roadmapNode(page, "CT03R");
  await keyboardNode.focus();
  await page.keyboard.press("Enter");
  await expect(drawer).toBeVisible();
  await expect(drawer).toContainText("CT03R");
  await page.keyboard.press("Escape");
  await expect(drawer).toBeHidden();

  await keyboardNode.focus();
  await page.keyboard.press("Space");
  await expect(drawer).toBeVisible();
  await expect(drawer).toContainText("CT03R");
});

test("provides functional graph zoom controls without navigation or network", async ({ page }) => {
  const externalRequests: string[] = [];
  page.on("request", (request) => {
    const protocol = new URL(request.url()).protocol;
    if (!new Set(["file:", "data:", "blob:"]).has(protocol)) {
      externalRequests.push(request.url());
    }
  });
  await openArtifact(page);

  const graph = page.getByTestId("roadmap-graph");
  const before = await graph.locator("svg > g").first().getAttribute("transform");
  await page.getByTestId("zoom-in").click();
  const zoomed = await graph.locator("svg > g").first().getAttribute("transform");
  expect(zoomed).not.toBe(before);
  await page.getByTestId("zoom-out").click();
  await page.getByTestId("zoom-reset").click();
  await expect(graph).toBeVisible();
  expect(new URL(page.url()).protocol).toBe("file:");
  expect(externalRequests).toEqual([]);
});
