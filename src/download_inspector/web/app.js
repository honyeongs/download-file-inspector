import {$, size, visibleName, renderReport, renderMembers, selectTab} from './render.js';

let file = null;
let report = null;
let controller = null;
let generation = 0;
function busy(value) {
  $('inspect').disabled = value || !file;
  $('cancel').hidden = !value;
  $('file').disabled = value;
  $('expected').disabled = value;
}
function choose(selected) {
  generation++;
  controller?.abort();
  controller = null;
  file = selected || null;
  report = null;
  $('results').hidden = true;
  $('file-name').textContent = file ? visibleName(file.name) : '파일 선택';
  $('file-size').textContent = file ? size(file.size) : '선택된 파일 없음';
  $('message').textContent = '검사 대기';
  if (file && file.size > 64 * 1024 * 1024) {
    file = null;
    $('message').textContent = '64 MiB 이하 파일만 검사할 수 있습니다.';
  }
  busy(false);
}
$('file').addEventListener('change', (event) => choose(event.target.files[0]));
for (const name of ['dragenter', 'dragover', 'dragleave', 'drop']) {
  $('drop-zone').addEventListener(name, (event) => {
    event.preventDefault();
    $('drop-zone').classList.toggle('dragging', name === 'dragenter' || name === 'dragover');
    if (name === 'drop') {
      $('file').value = '';
      choose(event.dataTransfer.files[0]);
    }
  });
}
$('inspect-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!file || controller) return;
  const current = ++generation;
  const expected = $('expected').value.trim();
  if (expected && !/^[0-9a-fA-F]{64}$/.test(expected)) {
    $('message').textContent = 'SHA-256은 64자리 16진수여야 합니다.';
    return;
  }
  controller = new AbortController();
  const activeController = controller;
  report = null;
  $('results').hidden = true;
  busy(true);
  $('message').textContent = '검사 중';
  try {
    const headers = {'Content-Type': 'application/octet-stream', 'X-File-Name': encodeURIComponent(file.name)};
    if (expected) headers['X-Expected-SHA256'] = expected;
    const response = await fetch('/api/inspect', {method: 'POST', headers, body: file, signal: activeController.signal});
    const data = await response.json();
    if (current !== generation) return;
    if (!response.ok) throw new Error(data.error || '검사 실패');
    report = data;
    renderReport(report);
    selectTab('findings');
    $('message').textContent = '검사 완료';
  } catch (error) {
    if (current === generation) $('message').textContent = error.name === 'AbortError' ? '검사 취소됨' : error.message;
  } finally {
    if (controller === activeController) controller = null;
    if (current === generation) busy(false);
  }
});
$('cancel').addEventListener('click', () => controller?.abort());
$('reset').addEventListener('click', () => {
  $('file').value = '';
  $('expected').value = '';
  choose(null);
  controller = null;
  $('file').focus();
});
$('search').addEventListener('input', () => report && renderMembers(report));
document.querySelectorAll('[data-tab]').forEach((button) => button.addEventListener('click', () => selectTab(button.dataset.tab)));
$('export').addEventListener('click', () => {
  if (!report) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], {type: 'application/json'}));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = 'inspection-report.json';
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
