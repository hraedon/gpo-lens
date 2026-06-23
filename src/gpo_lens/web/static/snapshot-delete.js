// Confirm before deleting an imported snapshot. Kept as an external script
// because the CSP forbids inline JS (no onsubmit= handlers in the template).
(function () {
    var forms = document.querySelectorAll('form.js-confirm-delete');
    for (var i = 0; i < forms.length; i++) {
        forms[i].addEventListener('submit', function (e) {
            var label = this.getAttribute('data-label') || 'this import';
            if (!window.confirm('Delete snapshot ' + label + '? This cannot be undone.')) {
                e.preventDefault();
            }
        });
    }
})();
