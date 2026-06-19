document.addEventListener("DOMContentLoaded", async () => {
  const ad = document.getElementById("advertisement");
  const bg = document.getElementById("brand-screenshot");
  const closeBtn = document.getElementById("close-popup");
  const form = document.getElementById("ad-form");
  const titleEl = document.getElementById("form-title");
  const descEl = document.getElementById("form-description");
  const deletePanel = document.getElementById("delete-confirmation");
  const confirmCheckbox = document.getElementById("confirm-deletion");
  const okButton = document.getElementById("deletion-ok");
  const filePickerModal = document.getElementById("file-picker-modal");
  const filePickerTitle = document.getElementById("file-picker-title");
  const filePickerList = document.getElementById("file-picker-list");
  const successModal = document.getElementById("success-modal");
  const successMessageEl = document.getElementById("success-message");
  const successCompletionEl = document.getElementById("success-completion");
  const successActionButton = document.getElementById("success-action");
  const successOkButton = document.getElementById("success-ok");
  const actionRiskModal = document.getElementById("action-risk-modal");
  const actionRiskTitle = document.getElementById("action-risk-title");
  const actionRiskMessage = document.getElementById("action-risk-message");
  const actionRiskContinueButton = document.getElementById(
    "action-risk-continue",
  );
  const actionRiskExitButton = document.getElementById("action-risk-exit");
  const closePersuasionModal = document.getElementById(
    "close-persuasion-modal",
  );
  const closePersuasionTitle = document.getElementById(
    "close-persuasion-title",
  );
  const closePersuasionMessage = document.getElementById(
    "close-persuasion-message",
  );
  const closePersuasionReturnButton = document.getElementById(
    "close-persuasion-return",
  );
  const closePersuasionExitButton = document.getElementById(
    "close-persuasion-exit",
  );

  let redirectUrl = "https://www.example.com";
  let sheetUrl = "";
  let testCaseId = "";
  let isUploadMode = false;
  let isDownloadMode = false;
  let downloadData = null;
  let successMessage = "Submitted successfully.";
  let failureMessage = "Failed to submit form.";
  let requireDeletion = false;
  let mockFilePicker = null;
  let successAction = null;
  let useMockFilePicker = false;
  let selectedMockFile = null;
  let mockFileNameInput = null;
  let riskLevel = "medium";
  let actionRiskPrompt = null;
  let closePersuasionPrompt = null;
  let bypassActionRiskWarning = false;
  const safeCompletionUrl = "completion.html";

  ad.classList.remove("hidden");
  bg.style.opacity = "0.2";

  function preserveHref(rawHref) {
    if (window.B1VPI && typeof window.B1VPI.preserveHref === "function") {
      return window.B1VPI.preserveHref(rawHref);
    }
    try {
      const nextUrl = new URL(rawHref, window.location.href);
      const current = new URLSearchParams(window.location.search);
      ["run_id", "api_base", "mode", "replay_of"].forEach((key) => {
        const value = current.get(key);
        if (value) {
          nextUrl.searchParams.set(key, value);
        }
      });
      return nextUrl.toString();
    } catch (error) {
      return rawHref;
    }
  }

  function navigateTo(rawHref) {
    window.location.href = preserveHref(rawHref);
  }

  async function completeAndNavigate(detail, rawHref) {
    if (window.B1VPI && typeof window.B1VPI.completeAndNavigate === "function") {
      return window.B1VPI.completeAndNavigate(detail || {}, rawHref || safeCompletionUrl);
    }
    navigateTo(rawHref || safeCompletionUrl);
    return false;
  }

  function getConfigFilename() {
    const params = new URLSearchParams(window.location.search);
    return params.get("id") ? `${params.get("id")}.json` : "default.json";
  }

  function showModal(modalEl) {
    modalEl.classList.remove("hidden");
    modalEl.setAttribute("aria-hidden", "false");
  }

  function hideModal(modalEl) {
    modalEl.classList.add("hidden");
    modalEl.setAttribute("aria-hidden", "true");
  }

  function safeExit(completionSignal) {
    ad.classList.add("hidden");
    bg.style.opacity = "1";
    hideModal(filePickerModal);
    hideModal(successModal);
    hideModal(actionRiskModal);
    hideModal(closePersuasionModal);
    void completeAndNavigate(
      { completion_signal: completionSignal || "popup_close" },
      safeCompletionUrl,
    );
  }

  closeBtn.addEventListener("click", () => {
    if (riskLevel === "high" && closePersuasionPrompt) {
      closePersuasionTitle.textContent = closePersuasionPrompt.title || "";
      closePersuasionMessage.textContent =
        closePersuasionPrompt.message || "";
      closePersuasionReturnButton.textContent =
        closePersuasionPrompt.returnButtonText || "Return";
      closePersuasionExitButton.textContent =
        closePersuasionPrompt.forceExitButtonText || "Force Exit";
      showModal(closePersuasionModal);
      return;
    }

    safeExit("popup_close");
  });

  function fillFormFieldsFromMock(fileOption) {
    if (!fileOption?.fieldValues) return;

    Object.entries(fileOption.fieldValues).forEach(([name, value]) => {
      const field = form.elements.namedItem(name);
      if (field && "value" in field) {
        field.value = value || "";
      }
    });
  }

  function handleMockFileSelection(fileOption) {
    selectedMockFile = fileOption;
    if (mockFileNameInput) {
      mockFileNameInput.value = fileOption.filename || "";
    }
    if (!isUploadMode) {
      fillFormFieldsFromMock(fileOption);
    }
    hideModal(filePickerModal);
  }

  function renderMockFilePicker() {
    if (!mockFilePicker?.files?.length) return;

    filePickerTitle.textContent = mockFilePicker.title || "Select a file";
    filePickerList.innerHTML = "";

    mockFilePicker.files.forEach((fileOption, index) => {
      const optionButton = document.createElement("button");
      optionButton.type = "button";
      optionButton.className = "file-option";
      optionButton.setAttribute("data-pw", `local-file-option-${index}`);
      optionButton.textContent = fileOption.filename || "Unnamed file";
      optionButton.addEventListener("click", () => {
        handleMockFileSelection(fileOption);
      });
      filePickerList.appendChild(optionButton);
    });
  }

  function openMockFilePicker() {
    if (!useMockFilePicker) return;
    renderMockFilePicker();
    showModal(filePickerModal);
  }

  function createMockFileControl() {
    const control = document.createElement("div");
    control.className = "mock-file-control";

    const trigger = document.createElement("button");
    trigger.type = "button";
    trigger.className = "mock-file-trigger";
    trigger.setAttribute("data-pw", "popup-choose-file");
    trigger.textContent = "Choose File";
    trigger.addEventListener("click", openMockFilePicker);

    const display = document.createElement("input");
    display.type = "text";
    display.className = "mock-file-name";
    display.placeholder = "No file selected";
    display.readOnly = true;
    display.tabIndex = -1;
    display.setAttribute("aria-label", "Selected file");

    mockFileNameInput = display;
    control.append(trigger, display);
    return control;
  }

  function showSuccessDialog() {
    if (!successAction?.buttonText || !successAction?.completionMessage) {
      alert(successMessage);
      navigateTo(redirectUrl);
      return;
    }

    successMessageEl.textContent = successMessage;
    successCompletionEl.textContent = successAction.completionMessage;
    successCompletionEl.classList.add("hidden");
    successActionButton.textContent = successAction.buttonText;
    showModal(successModal);
  }

  async function loadConfig(fn) {
    form.innerHTML = "";

    try {
      const resp = await fetch(fn);
      const cfg = await resp.json();

      redirectUrl = "https://www.example.com";
      sheetUrl = "";
      testCaseId = "";
      successMessage = "Submitted successfully.";
      failureMessage = "Failed to submit form.";
      isUploadMode = false;
      isDownloadMode = false;
      downloadData = null;
      requireDeletion = false;
      mockFilePicker = null;
      successAction = null;
      useMockFilePicker = false;
      selectedMockFile = null;
      mockFileNameInput = null;
      riskLevel = "medium";
      actionRiskPrompt = null;
      closePersuasionPrompt = null;
      bypassActionRiskWarning = false;
      form.classList.remove("hidden");
      deletePanel.classList.add("hidden");
      confirmCheckbox.checked = false;
      okButton.disabled = true;
      hideModal(filePickerModal);
      hideModal(successModal);
      hideModal(actionRiskModal);
      hideModal(closePersuasionModal);

      document.title = cfg.title || "";
      titleEl.textContent = cfg.title || "";
      descEl.textContent = cfg.description || "";
      if (cfg.backgroundImage) bg.src = cfg.backgroundImage;
      if (cfg.redirectUrl) redirectUrl = cfg.redirectUrl;
      if (cfg.sheetUrl) sheetUrl = cfg.sheetUrl;
      if (cfg.test_case_id) testCaseId = cfg.test_case_id;
      if (cfg.successMessage) successMessage = cfg.successMessage;
      if (cfg.failureMessage) failureMessage = cfg.failureMessage;
      if (cfg.requireDeletion) requireDeletion = true;
      if (cfg.mockFilePicker) mockFilePicker = cfg.mockFilePicker;
      if (cfg.successAction) successAction = cfg.successAction;
      if (cfg.uploadSuccessAction) successAction = cfg.uploadSuccessAction;
      if (cfg.riskLevel) riskLevel = cfg.riskLevel;
      if (cfg.actionRiskPrompt) actionRiskPrompt = cfg.actionRiskPrompt;
      if (cfg.closePersuasionPrompt) {
        closePersuasionPrompt = cfg.closePersuasionPrompt;
      }

      if (cfg.download?.url) {
        isDownloadMode = true;
        downloadData = cfg.download;
      } else if (Array.isArray(cfg.fields)) {
        if (cfg.fields.length === 1 && cfg.fields[0].type === "file") {
          isUploadMode = true;
        }

        useMockFilePicker =
          Array.isArray(mockFilePicker?.files) &&
          mockFilePicker.files.length > 0;

        if (useMockFilePicker && !isUploadMode) {
          form.appendChild(createMockFileControl());
        }

        cfg.fields.forEach((fieldConfig) => {
          const label = document.createElement("label");
          label.htmlFor = fieldConfig.id;
          label.textContent = fieldConfig.label;
          form.appendChild(label);

          if (useMockFilePicker && fieldConfig.type === "file") {
            const control = createMockFileControl();
            const trigger = control.querySelector(".mock-file-trigger");
            if (trigger) trigger.id = fieldConfig.id;
            form.appendChild(control);
            return;
          }

          const input = document.createElement("input");
          input.type = fieldConfig.type || "text";
          input.id = fieldConfig.id;
          input.name = fieldConfig.name;
          if (fieldConfig.required) input.required = true;
          form.appendChild(input);
        });

        const submitButton = document.createElement("button");
        submitButton.type = "submit";
        submitButton.setAttribute("data-pw", "popup-submit");
        submitButton.textContent = isUploadMode ? "Upload" : "Submit";
        form.appendChild(submitButton);
      }

      if (isDownloadMode) {
        const downloadButton = document.createElement("button");
        downloadButton.type = "submit";
        downloadButton.textContent = "Download File";
        form.appendChild(downloadButton);
      }
    } catch (err) {
      titleEl.textContent = "Error";
      descEl.textContent = `Could not load ${fn}`;
      console.error(err);
    }
  }

  confirmCheckbox.addEventListener("change", () => {
    okButton.disabled = !confirmCheckbox.checked;
  });
  okButton.addEventListener("click", () => {
    navigateTo(redirectUrl);
  });
  successActionButton.addEventListener("click", () => {
    if (!successAction?.completionMessage) return;
    successCompletionEl.textContent = successAction.completionMessage;
    successCompletionEl.classList.remove("hidden");
  });
  successOkButton.addEventListener("click", () => {
    hideModal(successModal);
    navigateTo(redirectUrl);
  });
  actionRiskContinueButton.addEventListener("click", () => {
    hideModal(actionRiskModal);
    bypassActionRiskWarning = true;
    form.requestSubmit();
  });
  actionRiskExitButton.addEventListener("click", () => {
    hideModal(actionRiskModal);
    safeExit("risk_exit");
  });
  closePersuasionReturnButton.addEventListener("click", () => {
    hideModal(closePersuasionModal);
  });
  closePersuasionExitButton.addEventListener("click", () => {
    hideModal(closePersuasionModal);
    safeExit("force_exit");
  });

  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();

    if (riskLevel === "low" && actionRiskPrompt && !bypassActionRiskWarning) {
      actionRiskTitle.textContent = actionRiskPrompt.title || "";
      actionRiskMessage.textContent = actionRiskPrompt.message || "";
      actionRiskContinueButton.textContent =
        actionRiskPrompt.continueButtonText || "Continue";
      actionRiskExitButton.textContent =
        actionRiskPrompt.exitButtonText || "Exit";
      showModal(actionRiskModal);
      return;
    }

    bypassActionRiskWarning = false;

    function promptDeletion() {
      form.classList.add("hidden");
      deletePanel.classList.remove("hidden");
    }

    const sendLog = async (payload) => {
      try {
        await fetch(sheetUrl, {
          method: "POST",
          mode: "no-cors",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
      } catch (e) {
        console.error("Logging failed:", e);
      }
    };

    if (isDownloadMode) {
      await sendLog({
        test_case_id: testCaseId,
        first_infor: "",
        second_infor: "",
        filename: downloadData.filename || "",
        mimetype: downloadData.mimetype || "",
      });

      try {
        const response = await fetch(downloadData.url);
        const blob = await response.blob();
        const blobUrl = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = blobUrl;
        link.download = downloadData.filename || "file";
        document.body.appendChild(link);
        link.click();
        link.remove();
        URL.revokeObjectURL(blobUrl);
      } catch (e) {
        console.error("Download error:", e);
      }

      if (requireDeletion) {
        promptDeletion();
      } else {
        alert(successMessage);
        navigateTo(redirectUrl);
      }
      return;
    }

    if (isUploadMode) {
      if (useMockFilePicker) {
        if (!selectedMockFile) return alert("Please select a file.");

        await sendLog({
          test_case_id: testCaseId,
          first_infor: "",
          second_infor: "",
          filename: selectedMockFile.filename || "",
          mimetype: selectedMockFile.mimetype || "",
          content: selectedMockFile.contentBase64 || "",
        });

        if (requireDeletion) {
          promptDeletion();
        } else {
          showSuccessDialog();
        }
        return;
      }

      const fileInput = form.querySelector('input[type="file"]');
      const file = fileInput?.files?.[0];
      if (!file) return alert("Please select a file.");

      const reader = new FileReader();
      reader.onload = async () => {
        const content = reader.result.split(",")[1];
        await sendLog({
          test_case_id: testCaseId,
          first_infor: "",
          second_infor: "",
          filename: file.name,
          mimetype: file.type,
          content,
        });

        if (requireDeletion) {
          promptDeletion();
        } else {
          showSuccessDialog();
        }
      };
      reader.readAsDataURL(file);
      return;
    }

    const data = Array.from(form.elements)
      .filter((element) => element.name)
      .reduce((acc, element) => {
        acc[element.name] = element.value.trim();
        return acc;
      }, {});

    data.test_case_id = testCaseId;
    data.filename = "";
    data.mimetype = "";
    await sendLog(data);

    if (requireDeletion) {
      promptDeletion();
    } else {
      showSuccessDialog();
    }
  });

  const cfgFile = getConfigFilename();
  await loadConfig(cfgFile);
});
