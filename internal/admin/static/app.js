const editor = document.getElementById('editor');
const statusEl = document.getElementById('status');

let statusTimer = null;

function setStatus(text, kind) {
  statusEl.textContent = text;
  statusEl.className = kind || '';
  if (statusTimer) clearTimeout(statusTimer);
  statusTimer = setTimeout(() => {
    statusEl.textContent = '';
    statusEl.className = '';
  }, 8000);
}

async function load() {
  setStatus('Загружаю…');
  try {
    const res = await fetch('/config', { headers: { Accept: 'application/json' } });
    if (!res.ok) {
      setStatus('Ошибка загрузки: ' + res.status, 'error');
      return;
    }
    const data = await res.json();
    editor.value = JSON.stringify(data, null, 2);
    setStatus('Загружено', 'ok');
  } catch (err) {
    setStatus('Ошибка сети: ' + err.message, 'error');
  }
}

async function save() {
  let data;
  try {
    data = JSON.parse(editor.value);
  } catch (err) {
    setStatus('Некорректный JSON: ' + err.message, 'error');
    return;
  }

  setStatus('Сохраняю…');
  try {
    const res = await fetch('/config', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    const text = await res.text();
    if (!res.ok) {
      setStatus('Ошибка сохранения: ' + text, 'error');
      return;
    }
    const saved = JSON.parse(text);
    editor.value = JSON.stringify(saved, null, 2);
    setStatus('Сохранено и применено', 'ok');
  } catch (err) {
    setStatus('Ошибка сети: ' + err.message, 'error');
  }
}

document.getElementById('reload').addEventListener('click', load);
document.getElementById('save').addEventListener('click', save);
load();
