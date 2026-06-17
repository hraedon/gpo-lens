(function () {
    var dropZone = document.getElementById('drop-zone');
    var fileInput = document.getElementById('file-input');
    var form = document.getElementById('ingest-form');
    var browseBtn = document.getElementById('browse-btn');
    if (!dropZone || !fileInput || !form) {
        return;
    }

    if (browseBtn) {
        browseBtn.addEventListener('click', function () {
            fileInput.click();
        });
    }
    dropZone.addEventListener('dragover', function (e) {
        e.preventDefault();
        dropZone.style.borderColor = '#666';
    });
    dropZone.addEventListener('dragleave', function (e) {
        e.preventDefault();
        dropZone.style.borderColor = '#ccc';
    });
    dropZone.addEventListener('drop', function (e) {
        e.preventDefault();
        dropZone.style.borderColor = '#ccc';
        if (e.dataTransfer.files.length) {
            fileInput.files = e.dataTransfer.files;
            form.submit();
        }
    });
    fileInput.addEventListener('change', function () {
        if (fileInput.files.length) {
            form.submit();
        }
    });
})();
