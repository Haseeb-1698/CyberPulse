document.addEventListener('DOMContentLoaded', function () {
  const uploadForm = document.getElementById('upload-form');
  const fileInput = document.getElementById('file-input');
  const loadingOverlay = document.getElementById('loading-overlay');
  const stageText = document.getElementById('stage-text');
  const progressBar = document.getElementById('progress-bar');

  if (!uploadForm || !fileInput || !loadingOverlay || !stageText || !progressBar) {
    console.error('Required form elements not found');
    return;
  }

  uploadForm.addEventListener('submit', function (e) {
    e.preventDefault();
    if (!fileInput.files.length) {
      alert('Please select an XML file');
      return;
    }

    const formData = new FormData(uploadForm);
    loadingOverlay.style.display = 'flex';
    stageText.textContent = 'Initializing...';
    progressBar.style.width = '0%';

    fetch('/start', {
      method: 'POST',
      body: formData
    })
    .then(response => {
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      return response.json();
    })
    .then(data => {
      if (data.error) {
        throw new Error(data.error);
      }
      pollStatus(data.job_id);
    })
    .catch(error => {
      loadingOverlay.style.display = 'none';
      alert('Error starting job: ' + error.message);
    });
  });

  function pollStatus(jobId) {
    let retryCount = 0;
    const maxRetries = 3;
    const pollInterval = 2000; // 2 seconds

    function checkStatus() {
      fetch(`/status/${jobId}`)
        .then(response => response.json())
        .then(data => {
          if (data.error) {
            throw new Error(data.error);
          }

          // Update progress
          if (progressBar) {
            progressBar.style.width = `${data.progress}%`;
          }
          if (stageText) {
            stageText.textContent = data.stage;
          }

          if (data.done) {
            if (data.stage.startsWith('Error')) {
              alert(`Processing failed: ${data.stage}`);
              if (loadingOverlay) {
                loadingOverlay.style.display = 'none';
              }
            } else {
              // Check for redirect
              if (data.redirect) {
                window.location.href = data.redirect;
              } else {
                // Fallback to results page if no redirect specified
                window.location.href = `/results?job_id=${jobId}`;
              }
            }
          } else {
            // Continue polling
            setTimeout(checkStatus, pollInterval);
          }
        })
        .catch(error => {
          console.error('Error checking status:', error);
          retryCount++;
          
          if (retryCount < maxRetries) {
            // Retry after a delay
            setTimeout(checkStatus, pollInterval);
          } else {
            alert('Failed to check processing status. Please try again.');
            if (loadingOverlay) {
              loadingOverlay.style.display = 'none';
            }
          }
        });
    }

    checkStatus();
  }
});