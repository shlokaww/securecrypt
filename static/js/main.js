(() => {
  'use strict';

  const notify = (message, type = 'success', duration = 3000) => {
    const box = document.createElement('div');
    box.className = `alert alert-${type === 'success' ? 'success' : 'danger'} alert-dismissible`;
    box.setAttribute('role', 'status');
    box.append(document.createTextNode(message));

    const close = document.createElement('button');
    close.type = 'button';
    close.className = 'btn-close';
    close.setAttribute('aria-label', 'Close');
    close.addEventListener('click', () => box.remove());
    box.append(close);

    document.querySelector('#notifications')?.append(box);
    const visibleDuration = type === 'success' ? Math.max(3000, duration) : duration;
    window.setTimeout(() => box.remove(), visibleDuration);
  };

  const initPasswordToggle = () => {
    document.querySelectorAll('[data-password-toggle]').forEach((button) => {
      button.addEventListener('click', () => {
        const input = document.getElementById(button.dataset.passwordToggle);
        if (!input) return;
        input.type = input.type === 'password' ? 'text' : 'password';
        button.textContent = input.type === 'password' ? 'Show' : 'Hide';
      });
    });
  };

  const initDragDrop = () => {
    document.querySelectorAll('input[type="file"]').forEach((input) => {
      const dropzone = input.closest('.dropzone');
      if (!dropzone) return;

      dropzone.addEventListener('dragover', (event) => {
        event.preventDefault();
        dropzone.classList.add('dragover');
      });
      dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
      dropzone.addEventListener('drop', (event) => {
        event.preventDefault();
        dropzone.classList.remove('dragover');
        if (!event.dataTransfer?.files.length) return;
        const transfer = new DataTransfer();
        transfer.items.add(event.dataTransfer.files[0]);
        input.files = transfer.files;
      });
    });
  };

  const submitWithSpinner = () => {
    document.querySelectorAll('form[data-api]').forEach((form) => {
      form.addEventListener('submit', async (event) => {
        event.preventDefault();

        // Snapshot values before disabling controls; disabled fields are omitted
        // from FormData, which would otherwise send an empty request.
        const isFileOperation = form.dataset.mode === 'file';
        const formData = new FormData(form);
        const requestOptions = isFileOperation
          ? { method: 'POST', body: formData }
          : {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(Object.fromEntries(formData)),
            };

        const controls = [...form.elements];
        controls.forEach((control) => { control.disabled = true; });
        const spinner = form.querySelector('.spinner-border');
        spinner?.classList.remove('d-none');

        try {
          const response = await fetch(form.dataset.api, requestOptions);
          if (isFileOperation) {
            if (!response.ok) {
              const data = await response.json();
              throw new Error(data.error || 'Operation failed');
            }

            const blob = await response.blob();
            const disposition = response.headers.get('Content-Disposition') || '';
            const match = disposition.match(/filename\*=UTF-8''([^;]+)|filename="?([^";]+)"?/i);
            const link = form.parentElement.querySelector('[data-download]');
            link.href = URL.createObjectURL(blob);
            link.download = decodeURIComponent(match?.[1] || match?.[2] || 'securecrypt-output');
            link.classList.remove('d-none');
          } else {
            const data = await response.json();
            if (!response.ok) throw new Error(data.error || 'Operation failed');

            if (form.dataset.mode === 'text-encrypt') {
              const result = form.parentElement.querySelector('.result');
              result.querySelector('textarea').value = data.payload;
              result.classList.remove('d-none');
            } else {
              const result = form.parentElement.querySelector('.result-text');
              result.textContent = data.plaintext;
              result.classList.remove('d-none');
            }
          }
          notify('Operation completed successfully.');
        } catch (error) {
          notify(error.message || 'Operation failed.', 'error', 5000);
        } finally {
          controls.forEach((control) => { control.disabled = false; });
          spinner?.classList.add('d-none');
        }
      });
    });
  };

  const initCopyButton = () => {
    document.addEventListener('click', (event) => {
      if (!event.target.matches('[data-copy]')) return;
      const area = event.target.closest('.result').querySelector('textarea');
      navigator.clipboard.writeText(area.value).then(() => {
        const confirmation = event.target.parentElement.querySelector('.copy-confirm');
        confirmation.classList.remove('d-none');
        window.setTimeout(() => confirmation.classList.add('d-none'), 2000);
      }).catch(() => notify('Could not copy to clipboard.', 'error'));
    });
  };

  document.addEventListener('DOMContentLoaded', () => {
    initPasswordToggle();
    initDragDrop();
    submitWithSpinner();
    initCopyButton();
  });
})();
