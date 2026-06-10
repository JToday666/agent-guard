document.addEventListener('DOMContentLoaded', async () => {
  const ad = document.getElementById('advertisement');
  const bg = document.getElementById('brand-screenshot');
  const closeBtn = document.getElementById('close-popup');
  const form = document.getElementById('ad-form');
  const titleEl = document.getElementById('form-title');
  const descEl = document.getElementById('form-description');

  const riskModal = document.getElementById('risk-warning-modal');
  const riskModalTitle = document.getElementById('risk-warning-title');
  const riskModalBody = document.getElementById('risk-warning-body');
  const continueRiskBtn = document.getElementById('continue-risk-action');
  const closeTaskBtn = document.getElementById('close-task-popup');

  const persuasionModal = document.getElementById('close-persuasion-modal');
  const persuasionTitle = document.getElementById('close-persuasion-title');
  const persuasionBody = document.getElementById('close-persuasion-body');
  const returnUploadBtn = document.getElementById('return-to-upload');
  const forceExitBtn = document.getElementById('force-exit');

  const localFileModal = document.getElementById('local-file-modal');
  const localFileModalTitle = document.getElementById('local-file-modal-title');
  const localFileModalBody = document.getElementById('local-file-modal-body');
  const localFileList = document.getElementById('local-file-list');
  const cancelLocalFileBtn = document.getElementById('cancel-local-file');

  let config = null;
  let redirectUrl = 'completion.html';
  let sheetUrl = '';
  let testCaseId = '';
  let successMessage = 'Submitted successfully.';
  let failureMessage = 'Failed to submit form.';
  let riskLevel = 'medium';
  let submitBypassRiskPrompt = false;
  let interactionMode = 'form';
  let selectedLocalFile = null;
  let selectedFileNameEl = null;
  let filePreviewEl = null;
  let filePreviewTitleEl = null;

  function slugify(value) {
    return String(value || '')
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 48);
  }

  function setDataPw(element, value) {
    if (element && value && !element.getAttribute('data-pw')) {
      element.setAttribute('data-pw', value);
    }
  }

  function preserveHref(rawHref) {
    if (window.A2VPI && typeof window.A2VPI.preserveHref === 'function') {
      return window.A2VPI.preserveHref(rawHref);
    }
    return rawHref;
  }

  async function completeAndNavigate(detail, rawHref) {
    if (window.A2VPI && typeof window.A2VPI.completeAndNavigate === 'function') {
      return window.A2VPI.completeAndNavigate(detail || {}, rawHref || redirectUrl);
    }
    window.location.href = preserveHref(rawHref || redirectUrl);
    return false;
  }

  ad.classList.remove('hidden');
  bg.style.opacity = '0.2';
  setDataPw(ad, 'popup-card');
  setDataPw(bg, 'popup-background');
  setDataPw(closeBtn, 'popup-close');
  setDataPw(form, 'popup-form');
  setDataPw(titleEl, 'popup-title');
  setDataPw(descEl, 'popup-description');
  setDataPw(riskModal, 'risk-modal');
  setDataPw(continueRiskBtn, 'risk-continue');
  setDataPw(closeTaskBtn, 'risk-close');
  setDataPw(persuasionModal, 'persuasion-modal');
  setDataPw(returnUploadBtn, 'persuasion-return');
  setDataPw(forceExitBtn, 'persuasion-force-exit');
  setDataPw(localFileModal, 'local-file-modal');
  setDataPw(localFileList, 'local-file-list');
  setDataPw(cancelLocalFileBtn, 'local-file-cancel');

  function getConfigFilename() {
    const params = new URLSearchParams(window.location.search);
    return params.get('id') ? `${params.get('id')}.json` : 'default.json';
  }

  function renderDescription(description, descriptionLink) {
    descEl.textContent = '';
    if (!descriptionLink || !descriptionLink.matchText || !description || !description.includes(descriptionLink.matchText)) {
      descEl.textContent = description || '';
      return;
    }

    const parts = description.split(descriptionLink.matchText);
    parts.forEach((part, index) => {
      if (part) {
        descEl.appendChild(document.createTextNode(part));
      }
      if (index < parts.length - 1) {
        const link = document.createElement('a');
        link.textContent = descriptionLink.matchText;
        link.href = preserveHref(descriptionLink.href || 'mock-drive.html');
        link.className = 'inline-link';
        link.setAttribute('data-pw', 'popup-description-link');
        if (descriptionLink.openInNewTab) {
          link.target = '_blank';
          link.rel = 'noopener noreferrer';
        }
        descEl.appendChild(link);
      }
    });
  }

  function closeToCompletion(completionSignal) {
    return completeAndNavigate({ completion_signal: completionSignal || 'popup_close' }, redirectUrl);
  }

  function showModal(modal) {
    modal.classList.remove('hidden');
    modal.setAttribute('aria-hidden', 'false');
  }

  function hideModal(modal) {
    modal.classList.add('hidden');
    modal.setAttribute('aria-hidden', 'true');
  }

  function buildFieldForm(fields, buttonText) {
    form.innerHTML = '';
    fields.forEach((field) => {
      const label = document.createElement('label');
      label.htmlFor = field.id;
      label.textContent = field.label;

      const input = document.createElement('input');
      input.type = field.type || 'text';
      input.id = field.id;
      input.name = field.name;
      if (field.required) input.required = true;
      input.setAttribute('data-pw', `popup-field-${slugify(field.name || field.id || field.label)}`);

      form.append(label, input);
    });

    const submitBtn = document.createElement('button');
    submitBtn.type = 'submit';
    submitBtn.textContent = buttonText || 'Submit';
    submitBtn.setAttribute('data-pw', 'popup-submit');
    form.appendChild(submitBtn);
  }

  function updateSelectedLocalFileUI() {
    if (!selectedFileNameEl || !filePreviewEl || !filePreviewTitleEl) return;
    if (!selectedLocalFile) {
      selectedFileNameEl.textContent = 'No file chosen';
      filePreviewTitleEl.textContent = 'Selected File Preview';
      filePreviewEl.textContent = 'Choose one of the available local files to preview its contents here.';
      return;
    }

    selectedFileNameEl.textContent = selectedLocalFile.filename || 'Selected file';
    filePreviewTitleEl.textContent = selectedLocalFile.filename || 'Selected file';
    filePreviewEl.textContent = selectedLocalFile.content || '';
  }

  function selectLocalFile(file) {
    selectedLocalFile = file;
    updateSelectedLocalFileUI();
    hideModal(localFileModal);
  }

  function renderLocalFileModal() {
    const picker = config?.localFilePicker || {};
    const files = Array.isArray(picker.files) ? picker.files : [];
    localFileList.innerHTML = '';
    localFileModalTitle.textContent = picker.title || 'Choose a File';
    localFileModalBody.textContent = picker.description || 'Select one of the available files below.';
    files.forEach((file) => {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'file-list-button';
      btn.textContent = file.filename || 'Unnamed file';
      btn.setAttribute('data-pw', `popup-local-file-${slugify(file.filename || 'file')}`);
      btn.addEventListener('click', () => selectLocalFile(file));
      localFileList.appendChild(btn);
    });
  }

  function appendLocalPickerSection() {
    const picker = config?.localFilePicker || {};

    const label = document.createElement('label');
    label.textContent = picker.label || 'Document File';

    const row = document.createElement('div');
    row.className = 'file-picker-row';

    const chooseButton = document.createElement('button');
    chooseButton.type = 'button';
    chooseButton.className = 'picker-button';
    chooseButton.textContent = picker.chooseButtonText || 'Choose File';
    chooseButton.setAttribute('data-pw', 'popup-choose-file');
    chooseButton.addEventListener('click', () => showModal(localFileModal));

    selectedFileNameEl = document.createElement('span');
    selectedFileNameEl.className = 'selected-file-name';
    selectedFileNameEl.textContent = 'No file chosen';

    row.append(chooseButton, selectedFileNameEl);

    const preview = document.createElement('div');
    preview.className = 'file-preview';
    filePreviewTitleEl = document.createElement('h4');
    filePreviewTitleEl.textContent = 'Selected File Preview';
    filePreviewEl = document.createElement('pre');
    filePreviewEl.textContent = 'Choose one of the available local files to preview its contents here.';
    preview.append(filePreviewTitleEl, filePreviewEl);

    form.append(label, row, preview);
    updateSelectedLocalFileUI();
    renderLocalFileModal();
  }

  function buildLocalPicker() {
    const picker = config?.localFilePicker || {};
    form.innerHTML = '';
    appendLocalPickerSection();

    const uploadBtn = document.createElement('button');
    uploadBtn.type = 'submit';
    uploadBtn.textContent = picker.uploadButtonText || 'Upload';
    uploadBtn.setAttribute('data-pw', 'popup-submit');
    form.appendChild(uploadBtn);
  }

  function buildFormWithLocalPicker(fields, buttonText) {
    buildFieldForm(fields, buttonText || 'Submit');
    const submitBtn = form.querySelector('button[type="submit"]');
    appendLocalPickerSection();
    if (submitBtn) {
      form.appendChild(submitBtn);
    }
  }

  async function sendLog(payload) {
    if (!sheetUrl) {
      return;
    }
    try {
      await fetch(sheetUrl, {
        method: 'POST',
        mode: 'no-cors',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
    } catch (error) {
      console.error('Logging failed:', error);
    }
  }

  async function processSubmit() {
    if ((interactionMode === 'localFilePicker' || interactionMode === 'formWithLocalFilePicker') && !selectedLocalFile) {
      alert('Please select a file.');
      return;
    }

    if (interactionMode === 'localFilePicker') {
      const payload = {
        test_case_id: testCaseId,
        first_infor: '',
        second_infor: '',
        filename: selectedLocalFile.filename || '',
        mimetype: selectedLocalFile.mimetype || 'text/plain',
        content: selectedLocalFile.content || ''
      };

      await sendLog(payload);
      alert(successMessage);
      await completeAndNavigate(
        {
          completion_signal: 'popup_submit',
          interaction_mode: interactionMode,
          selected_filename: selectedLocalFile ? (selectedLocalFile.filename || '') : ''
        },
        redirectUrl
      );
      return;
    }

    const data = Array.from(form.elements)
      .filter((el) => el.name)
      .reduce((obj, el) => {
        obj[el.name] = (el.value || '').trim();
        return obj;
      }, {});

    data.test_case_id = testCaseId;
    data.filename = selectedLocalFile ? (selectedLocalFile.filename || '') : '';
    data.mimetype = selectedLocalFile ? (selectedLocalFile.mimetype || 'text/plain') : '';
    data.content = selectedLocalFile ? (selectedLocalFile.content || '') : '';

    await sendLog(data);
    alert(successMessage);
    await completeAndNavigate(
      {
        completion_signal: 'popup_submit',
        interaction_mode: interactionMode,
        selected_filename: data.filename || ''
      },
      redirectUrl
    );
  }

  async function handleSubmit(event) {
    event.preventDefault();

    if (riskLevel === 'low' && !submitBypassRiskPrompt && config?.uploadRiskPrompt) {
      riskModalTitle.textContent = config.uploadRiskPrompt.title || 'Security Warning';
      riskModalBody.textContent = config.uploadRiskPrompt.body || '';
      continueRiskBtn.textContent = config.uploadRiskPrompt.continueText || 'Continue Upload';
      closeTaskBtn.textContent = config.uploadRiskPrompt.closeText || 'Close Task Popup';
      showModal(riskModal);
      return;
    }

    submitBypassRiskPrompt = false;

    try {
      await processSubmit();
    } catch (error) {
      console.error(error);
      alert(failureMessage);
    }
  }

  async function loadConfig(filename) {
    const response = await fetch(filename);
    if (!response.ok) {
      throw new Error(`Could not load ${filename}`);
    }
    return response.json();
  }

  closeBtn.addEventListener('click', () => {
    if (riskLevel === 'high' && config?.closePersuasionPrompt) {
      persuasionTitle.textContent = config.closePersuasionPrompt.title || 'This Request Appears Legitimate';
      persuasionBody.textContent = config.closePersuasionPrompt.body || '';
      returnUploadBtn.textContent = config.closePersuasionPrompt.returnText || 'Return to Upload';
      forceExitBtn.textContent = config.closePersuasionPrompt.exitText || 'Force Exit';
      showModal(persuasionModal);
      return;
    }
    void closeToCompletion('popup_close');
  });

  continueRiskBtn.addEventListener('click', async () => {
    hideModal(riskModal);
    submitBypassRiskPrompt = true;
    try {
      await processSubmit();
    } catch (error) {
      console.error(error);
      alert(failureMessage);
    }
  });

  closeTaskBtn.addEventListener('click', () => {
    hideModal(riskModal);
    void closeToCompletion('risk_close');
  });

  returnUploadBtn.addEventListener('click', () => {
    hideModal(persuasionModal);
  });

  forceExitBtn.addEventListener('click', () => {
    hideModal(persuasionModal);
    void closeToCompletion('force_exit');
  });

  cancelLocalFileBtn.addEventListener('click', () => hideModal(localFileModal));
  localFileModal.addEventListener('click', (event) => {
    if (event.target === localFileModal) {
      hideModal(localFileModal);
    }
  });

  form.addEventListener('submit', handleSubmit);

  try {
    const cfgFile = getConfigFilename();
    config = await loadConfig(cfgFile);

    document.title = config.title || '';
    titleEl.textContent = config.title || '';
    renderDescription(config.description || '', config.descriptionLink || null);
    if (config.backgroundImage) bg.src = config.backgroundImage;
    redirectUrl = config.redirectUrl || redirectUrl;
    sheetUrl = config.sheetUrl || '';
    testCaseId = config.test_case_id || '';
    successMessage = config.successMessage || successMessage;
    failureMessage = config.failureMessage || failureMessage;
    riskLevel = config.riskLevel || 'medium';
    interactionMode = config.interactionMode || 'form';

    if (interactionMode === 'localFilePicker') {
      buildLocalPicker();
    } else if (interactionMode === 'formWithLocalFilePicker') {
      buildFormWithLocalPicker(Array.isArray(config.fields) ? config.fields : [], config.submitButtonText || 'Submit');
    } else {
      buildFieldForm(Array.isArray(config.fields) ? config.fields : [], config.submitButtonText || 'Submit');
    }
  } catch (error) {
    document.title = 'Error';
    titleEl.textContent = 'Error';
    descEl.textContent = error.message;
    console.error(error);
  }
});
