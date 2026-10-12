export const $ = (id) => document.getElementById(id);
export const visibleName = (value) => String(value).replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
export function size(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}
const integrity = {match: '기준값 일치', mismatch: '기준값 불일치', not_provided: '판단 불가 · 기준값 없음'};
const risk = {high: '높음', medium: '주의', low: '낮음', info: '정보', no_indicators: '발견된 징후 없음'};
const archiveStatus = {metadata_checked: '메타데이터 확인', invalid: '손상 또는 불일치', unsupported: '지원 범위 밖', limit_exceeded: '검사 한도 초과', not_applicable: 'ZIP 아님'};
const labels = {
  ZIP_PATH_ESCAPE: '경로 탈출', ZIP_WINDOWS_STREAM: 'Windows 경로·스트림', ZIP_AMBIGUOUS_PATH: '모호한 파일명', NAME_CONTROL: '파일명 제어 문자', EXECUTABLE_NAME: '실행 파일·스크립트', DISGUISED_EXECUTABLE: '위장 확장자', MACRO_DOCUMENT: '매크로 문서', NESTED_ARCHIVE: '중첩 압축 · 내부 미검사', ZIP_DUPLICATE: '중복 파일명', ZIP_NAME_COLLISION: '파일명 충돌', ZIP_ENCRYPTED: '암호화 · 내용 미검사', ZIP_SPECIAL_FILE: '심볼릭 링크·특수 파일', ZIP_COMPRESSION_UNSUPPORTED: '지원하지 않는 압축 방식', ZIP_EXPANSION: '과도한 크기·압축률', ZIP_TOTAL_EXPANSION: '과도한 전체 압축률', ZIP_OVERLAP: '압축 데이터 영역 겹침', ZIP_PREFIX: 'ZIP 앞부분 추가 데이터', ZIP_INCOMPLETE: 'ZIP 검사 미완료', ZIP_INVALID: 'ZIP 구조 불일치', HASH_MISMATCH: 'SHA-256 기준값 불일치', EXECUTABLE_SIGNATURE: '실행 파일 시그니처', TYPE_MISMATCH: '확장자·파일 형식 불일치',
};
function text(tag, value, className) {
  const element = document.createElement(tag);
  element.textContent = value;
  if (className) element.className = className;
  return element;
}
export function renderMembers(report) {
  const query = $('search').value.toLocaleLowerCase();
  const matches = report.archive.members.filter((m) => visibleName(m.name).toLocaleLowerCase().includes(query));
  $('members').replaceChildren();
  for (const member of matches.slice(0, 200)) {
    const row = document.createElement('tr');
    [visibleName(member.name), size(member.size_bytes), size(member.compressed_bytes), member.encrypted ? '예' : '아니오'].forEach((v) => row.append(text('td', v)));
    $('members').append(row);
  }
  $('member-summary').textContent = `${Math.min(matches.length, 200)} / ${matches.length}개`;
  $('no-members').hidden = matches.length > 0;
}
export function renderReport(report) {
  $('results').hidden = false;
  $('integrity').textContent = integrity[report.integrity.status];
  $('integrity').dataset.level = report.integrity.status === 'mismatch' ? 'high' : 'neutral';
  $('risk').textContent = risk[report.assessment.risk];
  $('risk').dataset.level = report.assessment.risk;
  $('archive-status').textContent = archiveStatus[report.archive.status];
  $('result-name').textContent = visibleName(report.file.name);
  $('result-type').textContent = `${size(report.file.size_bytes)} / ${report.file.detected_type}`;
  $('digest').textContent = report.file.sha256;
  $('finding-count').textContent = report.finding_count;
  $('member-count').textContent = report.archive.entries;
  $('findings').replaceChildren();
  if (!report.findings.length) $('findings').append(text('p', '발견된 위험 징후 없음 · 안전성은 확인되지 않음', 'empty'));
  for (const finding of report.findings) {
    const row = text('article', '', 'finding');
    const badge = text('span', risk[finding.severity], 'badge');
    badge.dataset.level = finding.severity;
    const body = text('div', '');
    body.append(text('strong', labels[finding.code] || finding.code));
    if (finding.member) body.append(text('p', visibleName(finding.member), 'filename'));
    body.append(text('p', finding.message, 'muted'));
    row.append(badge, body);
    $('findings').append(row);
  }
  if (report.findings_truncated) $('findings').append(text('p', `표시 한도: ${report.findings.length} / ${report.finding_count}개`, 'muted'));
  $('json-panel').textContent = JSON.stringify(report, null, 2);
  $('search').value = '';
  renderMembers(report);
}
export function selectTab(name) {
  for (const tab of ['findings', 'members', 'json']) {
    $(`${tab}-panel`).hidden = tab !== name;
    document.querySelector(`[data-tab="${tab}"]`).setAttribute('aria-pressed', String(tab === name));
  }
}
