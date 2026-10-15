import {esc, formatNumber, afterRender} from './ui.js';

const registry = new Map();
const HEIGHT = 240;
const PAD = {top: 14, right: 14, bottom: 26, left: 40};
const COLUMN_HEIGHT = 280, COLUMN_BOTTOM = 78;
const time = new Intl.DateTimeFormat('ru-RU', {hour: '2-digit', minute: '2-digit', hour12: false});
const day = new Intl.DateTimeFormat('ru-RU', {day: '2-digit', month: '2-digit'});
const full = new Intl.DateTimeFormat('ru-RU', {day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false});

export function chartHost(id, config) {
  registry.set(id, config);
  return `<div class="chart" data-chart="${esc(id)}" role="img" aria-label="${esc(config.label)}"><div class="chart-tip" hidden></div></div>` +
    (config.series ? `<ul class="chart-legend">${config.series.map(s => `<li><span class="swatch ${esc(s.tone)}"></span>${esc(s.label)}</li>`).join('')}</ul>` : '');
}

const SLICES = 8;
export function donut(rows, {label, caption = '', other, names = value => value}) {
  const sorted = rows.filter(row => row.count > 0).sort((a, b) => b.count - a.count);
  const total = sorted.reduce((sum, row) => sum + row.count, 0);
  const parts = sorted.slice(0, sorted.length > SLICES ? SLICES - 1 : SLICES).map(row => ({name: names(row.label), count: row.count}));
  const rest = total - parts.reduce((sum, part) => sum + part.count, 0);
  if (rest > 0) parts.push({name: other, count: rest});
  let offset = 0;
  const slices = parts.map((part, index) => {
    const share = part.count / total * 100;
    const slice = `<circle class="donut-slice slice-${index}" cx="21" cy="21" r="15.9155" stroke-dasharray="${share.toFixed(3)} ${(100 - share).toFixed(3)}" ` +
      `stroke-dashoffset="${(25 - offset).toFixed(3)}"><title>${esc(part.name)}: ${formatNumber(part.count)}</title></circle>`;
    offset += share;
    return slice;
  }).join('');
  const percent = count => { const value = Math.round(count / total * 100); return value ? `${value}%` : '<1%'; };
  return `<div class="donut" role="img" aria-label="${esc(label)}"><svg viewBox="0 0 42 42" aria-hidden="true"><circle class="donut-track" cx="21" cy="21" r="15.9155"/>${slices}` +
    `<text class="donut-total" x="21" y="21.5">${formatNumber(total)}</text><text class="donut-caption" x="21" y="26.5">${esc(caption)}</text></svg>` +
    `<ul class="donut-legend">${parts.map((part, index) => `<li><span class="swatch slice-${index}"></span><span class="donut-name">${esc(part.name)}</span>` +
      `<b>${formatNumber(part.count)}</b><small>${esc(percent(part.count))}</small></li>`).join('')}</ul></div>`;
}
export const updateChart = (id, config) => {
  registry.set(id, config);
  const host = document.querySelector(`[data-chart="${CSS.escape(id)}"]`);
  if (host) draw(host);
};

function niceMax(value) {
  if (value <= 4) return 4;
  const power = 10 ** Math.floor(Math.log10(value));
  return [1, 2, 2.5, 5, 10].map(step => step * power).find(step => step >= value) || value;
}
function axisLabel(timestamp, bucketSeconds) {
  const date = new Date(timestamp);
  if (bucketSeconds >= 86400) return day.format(date);
  return bucketSeconds >= 3600 ? `${day.format(date)} ${time.format(date)}` : time.format(date);
}
const gridLines = (width, innerH, max) => [0, 0.25, 0.5, 0.75, 1].map(part => {
  const level = PAD.top + innerH - part * innerH;
  return `<line class="chart-grid" x1="${PAD.left}" x2="${width - PAD.right}" y1="${level}" y2="${level}"/>` +
    `<text class="chart-axis" x="${PAD.left - 8}" y="${level + 4}" text-anchor="end">${formatNumber(Math.round(max * part))}</text>`;
}).join('');
const stackSum = (bucket, series) => series.reduce((sum, s) => sum + (bucket[s.key] || 0), 0);

function drawColumns(host, config) {
  const width = Math.max(host.clientWidth, 280);
  const {items} = config;
  const innerW = width - PAD.left - PAD.right, innerH = COLUMN_HEIGHT - PAD.top - COLUMN_BOTTOM;
  const max = niceMax(Math.max(1, ...items.map(item => item.count)));
  const slot = innerW / Math.max(items.length, 1);
  const y = value => PAD.top + innerH - value / max * innerH;
  const columns = items.map((item, index) => {
    const center = PAD.left + (index + 0.5) * slot, size = Math.max(4, Math.min(slot * 0.62, 56));
    const column = `<rect class="chart-column" x="${(center - size / 2).toFixed(1)}" y="${y(item.count).toFixed(1)}" width="${size.toFixed(1)}" ` +
      `height="${(PAD.top + innerH - y(item.count)).toFixed(1)}" rx="3"><title>${esc(item.label)}: ${formatNumber(item.count)}</title></rect>` +
      `<text class="chart-value" x="${center.toFixed(1)}" y="${(y(item.count) - 5).toFixed(1)}" text-anchor="middle">${formatNumber(item.count)}</text>` +
      `<text class="chart-axis" text-anchor="end" transform="translate(${center.toFixed(1)} ${PAD.top + innerH + 12}) rotate(-35)">${esc(item.label)}</text>`;
    return item.href ? `<a href="${esc(item.href)}">${column}</a>` : column;
  }).join('');
  const markup = `<svg viewBox="0 0 ${width} ${COLUMN_HEIGHT}" width="${width}" height="${COLUMN_HEIGHT}">${gridLines(width, innerH, max)}${columns}</svg>`;
  const svg = host.querySelector('svg');
  if (svg) svg.outerHTML = markup; else host.insertAdjacentHTML('afterbegin', markup);
  host.geometry = {width};
}

function draw(host) {
  const config = registry.get(host.dataset.chart);
  if (!config) return;
  if (config.kind === 'columns') return drawColumns(host, config);
  const width = Math.max(host.clientWidth, 280);
  const {buckets, series} = config;
  const stacked = config.kind === 'bars';
  const innerW = width - PAD.left - PAD.right, innerH = HEIGHT - PAD.top - PAD.bottom;
  const max = niceMax(Math.max(1, ...buckets.map(b => stacked ? stackSum(b, series) : Math.max(...series.map(s => b[s.key] || 0)))));
  const slot = innerW / Math.max(buckets.length, 1);
  const x = stacked ? index => PAD.left + (index + 0.5) * slot
    : index => PAD.left + (buckets.length > 1 ? index / (buckets.length - 1) : 0.5) * innerW;
  const y = value => PAD.top + innerH - value / max * innerH;
  const grid = gridLines(width, innerH, max);
  const ticks = Math.min(6, buckets.length);
  const labels = Array.from({length: ticks}, (_, i) => Math.round(i * (buckets.length - 1) / Math.max(ticks - 1, 1))).map((index, i) =>
    `<text class="chart-axis" x="${x(index)}" y="${HEIGHT - 6}" text-anchor="${i === 0 ? 'start' : i === ticks - 1 ? 'end' : 'middle'}">${esc(axisLabel(buckets[index].timestamp, config.bucketSeconds))}</text>`).join('');
  const size = Math.max(1, slot * 0.72);
  const lines = stacked ? buckets.map((b, i) => {
    let base = 0;
    return series.map(s => {
      const value = b[s.key] || 0;
      if (!value) return '';
      const top = y(base + value), bottom = y(base);
      base += value;
      return `<rect class="chart-bar ${esc(s.tone)}" x="${(x(i) - size / 2).toFixed(1)}" y="${top.toFixed(1)}" width="${size.toFixed(1)}" height="${(bottom - top).toFixed(1)}"/>`;
    }).join('');
  }).join('') : series.map(s => {
    const points = buckets.map((b, i) => `${x(i).toFixed(1)},${y(b[s.key] || 0).toFixed(1)}`);
    const area = s.fill ? `<path class="chart-area ${esc(s.tone)}" d="M${x(0)},${y(0)} L${points.join(' L')} L${x(buckets.length - 1)},${y(0)} Z"/>` : '';
    return `${area}<polyline class="chart-line ${esc(s.tone)}" points="${points.join(' ')}"/>`;
  }).join('');
  const svg = host.querySelector('svg');
  const markup = `<svg viewBox="0 0 ${width} ${HEIGHT}" width="${width}" height="${HEIGHT}" aria-hidden="true">` +
    `<defs><linearGradient id="chart-fill" x1="0" y1="0" x2="0" y2="1"><stop class="chart-fill-stop" offset="0" stop-color="#c9363b" stop-opacity="0.22"/><stop class="chart-fill-stop" offset="1" stop-color="#c9363b" stop-opacity="0"/></linearGradient></defs>` +
    `${grid}${labels}${lines}<line class="chart-cursor" y1="${PAD.top}" y2="${PAD.top + innerH}" x1="0" x2="0" visibility="hidden"/>` +
    `<g class="chart-points"></g></svg>`;
  if (svg) svg.outerHTML = markup; else host.insertAdjacentHTML('afterbegin', markup);
  host.geometry = {x, y, width, innerW, stacked};
}

function showTip(host, clientX) {
  const config = registry.get(host.dataset.chart);
  if (!config || config.kind === 'columns' || !host.geometry) return;
  const {x, y, width, innerW, stacked} = host.geometry;
  const box = host.getBoundingClientRect();
  const ratio = Math.min(Math.max((clientX - box.left - PAD.left) / innerW, 0), 1);
  const count = config.buckets.length;
  const index = stacked ? Math.min(count - 1, Math.floor(ratio * count)) : Math.round(ratio * (count - 1));
  const bucket = config.buckets[index];
  const cursor = host.querySelector('.chart-cursor');
  cursor.setAttribute('x1', x(index));
  cursor.setAttribute('x2', x(index));
  cursor.setAttribute('visibility', 'visible');
  host.querySelector('.chart-points').innerHTML = stacked ? '' : config.series.map(s =>
    `<circle class="chart-point ${esc(s.tone)}" cx="${x(index)}" cy="${y(bucket[s.key] || 0)}" r="3.5"/>`).join('');
  const tip = host.querySelector('.chart-tip');
  tip.innerHTML = `<strong>${esc(full.format(new Date(bucket.timestamp)))}</strong>` +
    (config.totalLabel ? `<span>${esc(config.totalLabel)}<b>${formatNumber(stackSum(bucket, config.series))}</b></span>` : '') +
    config.series.map(s => `<span><i class="swatch ${esc(s.tone)}"></i>${esc(s.label)}<b>${formatNumber(bucket[s.key] || 0)}</b></span>`).join('');
  tip.hidden = false;
  const left = x(index) > width / 2 ? x(index) - tip.offsetWidth - 14 : x(index) + 14;
  tip.style.left = `${Math.max(left, 4)}px`;
  tip.style.top = `${PAD.top}px`;
}
function hideTip(host) {
  const tip = host.querySelector('.chart-tip');
  if (tip) tip.hidden = true;
  host.querySelector('.chart-cursor')?.setAttribute('visibility', 'hidden');
  const points = host.querySelector('.chart-points');
  if (points) points.innerHTML = '';
}

let frame = 0;
const observer = new ResizeObserver(entries => {
  for (const entry of entries) if (entry.target.isConnected && Math.abs((entry.target.geometry?.width || 0) - entry.contentRect.width) > 2) draw(entry.target);
});
afterRender(rootNode => {
  for (const host of rootNode.querySelectorAll('[data-chart]')) {
    if (host.dataset.ready) continue;
    host.dataset.ready = '1';
    draw(host);
    observer.observe(host);
    host.addEventListener('pointermove', event => {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(() => showTip(host, event.clientX));
    });
    host.addEventListener('pointerleave', () => { cancelAnimationFrame(frame); hideTip(host); });
  }
});
