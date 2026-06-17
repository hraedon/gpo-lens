(function () {
    var dropZone = document.getElementById('drop-zone');
    var fileInput = document.getElementById('file-input');
    var form = document.getElementById('ingest-form');
    var browseBtn = document.getElementById('browse-btn');
    if (!dropZone || !fileInput || !form) {
        return;
    }

    function browse() { fileInput.click(); }
    dropZone.addEventListener('click', browse);
    if (browseBtn) {
        browseBtn.addEventListener('click', function (e) { e.stopPropagation(); browse(); });
    }
    dropZone.addEventListener('dragover', function (e) {
        e.preventDefault();
        dropZone.classList.add('over');
    });
    dropZone.addEventListener('dragleave', function (e) {
        e.preventDefault();
        dropZone.classList.remove('over');
    });
    dropZone.addEventListener('drop', function (e) {
        e.preventDefault();
        dropZone.classList.remove('over');
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
