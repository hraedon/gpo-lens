(function () {
    var dropZone = document.getElementById('drop-zone');
    var fileInput = document.getElementById('file-input');
    if (!dropZone || !fileInput) return;
    var form = dropZone.closest('form');
    if (!form) return;

    function browse() { fileInput.click(); }

    function isZip(file) {
        return file.name.toLowerCase().endsWith('.zip');
    }

    dropZone.addEventListener('click', browse);
    var browseBtn = document.getElementById('browse-btn');
    if (browseBtn) browseBtn.addEventListener('click', function (e) { e.stopPropagation(); browse(); });
    dropZone.addEventListener('dragover', function (e) { e.preventDefault(); dropZone.classList.add('over'); });
    dropZone.addEventListener('dragleave', function (e) { e.preventDefault(); dropZone.classList.remove('over'); });
    dropZone.addEventListener('drop', function (e) {
        e.preventDefault();
        dropZone.classList.remove('over');
        if (e.dataTransfer.files.length) {
            var file = e.dataTransfer.files[0];
            if (!isZip(file)) return;
            fileInput.files = e.dataTransfer.files;
            onFileSelected();
        }
    });
    fileInput.addEventListener('change', function () { if (fileInput.files.length) onFileSelected(); });

    function onFileSelected() {
        var overlay = document.getElementById('confirm-overlay');
        if (overlay) {
            overlay.style.display = 'flex';
            var proceed = document.getElementById('confirm-proceed');
            if (proceed) proceed.focus();
            return;
        }
        form.submit();
    }

    var confirmProceed = document.getElementById('confirm-proceed');
    var confirmCancel = document.getElementById('confirm-cancel');
    if (confirmProceed) confirmProceed.addEventListener('click', function () { form.submit(); });
    if (confirmCancel) confirmCancel.addEventListener('click', function () {
        document.getElementById('confirm-overlay').style.display = 'none';
        fileInput.value = '';
    });

    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') {
            var overlay = document.getElementById('confirm-overlay');
            if (overlay && overlay.style.display === 'flex') {
                overlay.style.display = 'none';
                fileInput.value = '';
            }
        }
    });

    form.addEventListener('submit', function () { dropZone.classList.add('loading'); });
})();
