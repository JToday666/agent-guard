import assert from "node:assert/strict";
import test from "node:test";

import {
  createDashboardDataSourceDescriptor,
  selectApprovalMutationWriter,
  type ApprovalMutationDataSource,
  type DashboardDataSourceHandle,
  type DashboardReadDataSource,
} from "./dashboard-data-source.ts";

const emptyReader = {} as DashboardReadDataSource;
const writer: ApprovalMutationDataSource = {
  async resolveApproval(approvalId, decision) {
    return { approvalId, decision, status: "resolved" };
  },
};

function createHandle(
  viteMode: string,
  isProduction: boolean,
  approvalWriter: ApprovalMutationDataSource | null,
  runtimeSupervisionS1Enabled = true,
): DashboardDataSourceHandle {
  return {
    approvalWriter,
    descriptor: createDashboardDataSourceDescriptor({
      isProduction,
      runtimeSupervisionS1Enabled,
      viteMode,
    }),
    reader: emptyReader,
  };
}

test("data source factory deeply freezes source descriptors", () => {
  const descriptor = createDashboardDataSourceDescriptor({
    isProduction: false,
    viteMode: "mock",
  });

  assert.equal(descriptor.dataSourceMode, "mock_preview");
  assert.equal(descriptor.buildProfile, "development");
  assert.equal(descriptor.capabilities.approvalMutation, false);
  assert.equal(descriptor.capabilities.runtimeSupervisionS1, false);
  assert.equal(descriptor.capabilities.syntheticFacts, true);
  assert.ok(Object.isFrozen(descriptor));
  assert.ok(Object.isFrozen(descriptor.capabilities));
  assert.throws(() => {
    (descriptor as { dataSourceMode: string }).dataSourceMode = "live_api";
  }, TypeError);
  assert.throws(() => {
    (descriptor.capabilities as { approvalMutation: boolean }).approvalMutation = true;
  }, TypeError);
});

test("production always resolves to live API even when the requested Vite mode is mock", () => {
  const descriptor = createDashboardDataSourceDescriptor({
    isProduction: true,
    viteMode: "mock",
  });

  assert.equal(descriptor.dataSourceMode, "live_api");
  assert.equal(descriptor.buildProfile, "production");
  assert.equal(descriptor.capabilities.approvalMutation, true);
  assert.equal(descriptor.capabilities.runtimeSupervisionS1, true);
  assert.equal(descriptor.capabilities.syntheticFacts, false);
});

test("approval writer selection checks mode, capability, writer and read-only override", () => {
  const preview = createHandle("mock", false, null);
  const live = createHandle("development", false, writer);
  const liveWithoutWriter = createHandle("development", false, null);
  const liveWithS1Disabled = createHandle("development", false, writer, false);
  const forgedLiveHandle = {
    ...live,
    descriptor: Object.freeze({
      ...live.descriptor,
      capabilities: Object.freeze({ ...live.descriptor.capabilities }),
    }),
  };

  assert.deepEqual(selectApprovalMutationWriter(preview), {
    code: "mutation_not_permitted",
    permitted: false,
  });
  assert.deepEqual(selectApprovalMutationWriter(liveWithoutWriter), {
    code: "mutation_not_permitted",
    permitted: false,
  });
  assert.deepEqual(selectApprovalMutationWriter(live, true), {
    code: "mutation_not_permitted",
    permitted: false,
  });
  assert.deepEqual(selectApprovalMutationWriter(liveWithS1Disabled), {
    code: "mutation_not_permitted",
    permitted: false,
  });
  assert.deepEqual(selectApprovalMutationWriter(forgedLiveHandle), {
    code: "mutation_not_permitted",
    permitted: false,
  });
  assert.equal(liveWithS1Disabled.descriptor.capabilities.approvalMutation, false);
  assert.equal(liveWithS1Disabled.descriptor.capabilities.runtimeSupervisionS1, false);
  assert.equal(selectApprovalMutationWriter(live).permitted, true);
});
