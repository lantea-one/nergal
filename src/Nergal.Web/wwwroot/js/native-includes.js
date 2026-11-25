// Reorder explicit uploaded dependencies without changing their membership or editing source.
for (const group of document.querySelectorAll('.native-include-order')) {
    const rows = group.querySelector('.native-include-rows');
    const relabel = () => [...rows.children].forEach((row, i) => {
        row.querySelector('select').setAttribute('aria-label', `${group.dataset.includeLabel} file ${i + 1}`);
    });
    group.addEventListener('click', event => {
        const move = event.target.closest('[data-include-move]');
        if (move) {
            const row = move.closest('.native-include-row');
            if (move.dataset.includeMove === 'up') {
                const previous = row.previousElementSibling;
                if (previous) rows.insertBefore(row, previous);
            } else {
                const next = row.nextElementSibling;
                if (next) rows.insertBefore(next, row);
            }
            relabel();
            move.focus();
        }
        if (event.target.closest('[data-include-add]') && rows.children.length < 32) {
            const row = rows.children[0].cloneNode(true);
            row.querySelector('select').value = '00000000-0000-0000-0000-000000000000';
            rows.append(row);
            relabel();
            row.querySelector('select').focus();
        }
    });
}
