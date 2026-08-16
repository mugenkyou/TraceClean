/**
 * TraceClean Web UI Client Scripts
 */

document.addEventListener('DOMContentLoaded', () => {
  initDropzone();
  initFormSubmissions();
  initCollapsibles();
});

const MAX_BYTES = 256 * 1024 * 1024; // 256 MB

function initDropzone() {
  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('file-input');
  if (!dropzone || !fileInput) return;

  ['dragenter', 'dragover'].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.add('dragover');
    }, false);
  });

  ['dragleave', 'drop'].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.remove('dragover');
    }, false);
  });

  dropzone.addEventListener('drop', (e) => {
    const dt = e.dataTransfer;
    const files = dt.files;
    if (files && files.length > 0) {
      fileInput.files = files;
      handleFileSelected(files[0]);
    }
  });

  dropzone.addEventListener('click', (e) => {
    // Avoid triggering fileInput twice if click was on browse button or child
    if (e.target !== fileInput) {
      fileInput.click();
    }
  });

  fileInput.addEventListener('change', () => {
    if (fileInput.files && fileInput.files.length > 0) {
      handleFileSelected(fileInput.files[0]);
    }
  });
}

function handleFileSelected(file) {
  const errorAlert = document.getElementById('client-error');
  if (errorAlert) errorAlert.style.display = 'none';

  if (file.size > MAX_BYTES) {
    showClientError(`File is too large (${(file.size / (1024 * 1024)).toFixed(1)} MB). Maximum allowed size is 256 MB.`);
    return;
  }

  // Update UI title to show file name and submit form automatically
  const dropTitle = document.getElementById('dropzone-title');
  if (dropTitle) {
    dropTitle.textContent = `Selected: ${file.name} (${formatBytes(file.size)})`;
  }

  const uploadForm = document.getElementById('upload-form');
  if (uploadForm) {
    showLoading('Analyzing file provenance & metadata...');
    uploadForm.submit();
  }
}

function showClientError(msg) {
  let errorAlert = document.getElementById('client-error');
  if (!errorAlert) {
    errorAlert = document.createElement('div');
    errorAlert.id = 'client-error';
    errorAlert.className = 'warning-banner';
    errorAlert.style.borderColor = 'var(--status-danger)';
    errorAlert.style.color = 'var(--status-danger)';
    errorAlert.style.background = 'var(--status-danger-bg)';
    errorAlert.style.marginTop = '1rem';
    
    const container = document.querySelector('.upload-card');
    if (container) container.appendChild(errorAlert);
  }
  errorAlert.innerHTML = `<strong>Error:</strong> ${msg}`;
  errorAlert.style.display = 'flex';
}

function initFormSubmissions() {
  const cleanForm = document.getElementById('clean-form');
  if (cleanForm) {
    cleanForm.addEventListener('submit', () => {
      showLoading('Cleaning provenance signals & metadata...');
    });
  }
}

function showLoading(message = 'Processing...') {
  const overlay = document.getElementById('loading-overlay');
  const text = document.getElementById('loading-text');
  if (overlay) {
    if (text) text.textContent = message;
    overlay.style.display = 'flex';
  }
}

function initCollapsibles() {
  const toggles = document.querySelectorAll('.details-toggle');
  toggles.forEach(toggle => {
    toggle.addEventListener('click', () => {
      const targetId = toggle.getAttribute('data-target');
      const target = document.getElementById(targetId);
      if (target) {
        const isHidden = target.style.display === 'none' || !target.style.display;
        target.style.display = isHidden ? 'block' : 'none';
        toggle.querySelector('.toggle-icon').textContent = isHidden ? '▲' : '▼';
      }
    });
  });
}

function formatBytes(bytes, decimals = 2) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}
