import {t, tk, esc, prefs} from './ui.js';

const COLS = 24, ROWS = 18;
const TAPS = 5, TAP_GAP = 1200;
const BEST_KEY = 'honeyforge.snake.best';
const GLYPHS = 'アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワン0123456789';
const DIRS = {
  ArrowUp: [0, -1], KeyW: [0, -1], ArrowDown: [0, 1], KeyS: [0, 1],
  ArrowLeft: [-1, 0], KeyA: [-1, 0], ArrowRight: [1, 0], KeyD: [1, 0],
};
const PAD = [['up', 'ArrowUp', '▲'], ['left', 'ArrowLeft', '◀'], ['down', 'ArrowDown', '▼'], ['right', 'ArrowRight', '▶']];
const glyph = () => GLYPHS[Math.floor(Math.random() * GLYPHS.length)];
const calm = () => prefs.reducedEffects || matchMedia('(prefers-reduced-motion: reduce)').matches;

function readBest() {
  try { return Number(localStorage.getItem(BEST_KEY)) || 0; } catch { return 0; }
}
function saveBest(value) {
  try { localStorage.setItem(BEST_KEY, String(value)); } catch {   }
}

let taps = 0, lastTap = 0, playing = false;
document.addEventListener('click', event => {
  const logo = event.target.closest?.('.brand-mark');
  if (!logo) return;
  const now = Date.now();
  taps = now - lastTap < TAP_GAP ? taps + 1 : 1;
  lastTap = now;
  logo.classList.remove('tapped');
  void logo.offsetWidth;
  logo.classList.add('tapped');
  if (taps >= TAPS && !playing) {
    taps = 0;
    openGame();
  }
});

function openGame() {
  playing = true;
  const dialog = document.createElement('dialog');
  dialog.className = 'matrix-game';
  dialog.setAttribute('aria-label', t('snake.title'));
  dialog.innerHTML = `<header><div><h2>${esc(t('snake.title'))}</h2><p>${esc(t('snake.found'))}</p></div>` +
    `<div class="matrix-score"><span>${esc(t('snake.score'))} <b data-score>0</b></span><span>${esc(t('snake.best'))} <b data-best>0</b></span></div>` +
    `<button type="button" class="matrix-close" data-close aria-label="${esc(t('snake.close'))}">×</button></header>` +
    `<canvas tabindex="0" aria-label="${esc(t('snake.board'))}"></canvas><p class="sr-only" data-status aria-live="polite"></p>` +
    `<div class="matrix-pad">${PAD.map(([name, code, arrow]) =>
      `<button type="button" data-dir="${code}" aria-label="${esc(tk('snake', name))}">${arrow}</button>`).join('')}</div>` +
    `<p class="matrix-help">${esc(t('snake.help'))}</p>`;
  document.body.append(dialog);

  const canvas = dialog.querySelector('canvas');
  const ctx = canvas.getContext('2d');
  const scoreNode = dialog.querySelector('[data-score]');
  const bestNode = dialog.querySelector('[data-best]');
  const statusNode = dialog.querySelector('[data-status]');
  let cell = 20;

  function size() {
    cell = Math.max(10, Math.floor(Math.min((innerWidth - 64) / COLS, (innerHeight - 280) / ROWS, 26)));
    const ratio = window.devicePixelRatio || 1;
    canvas.width = COLS * cell * ratio;
    canvas.height = ROWS * cell * ratio;
    canvas.style.setProperty('width', `${COLS * cell}px`);
    canvas.style.setProperty('height', `${ROWS * cell}px`);
    ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
  }

  const newDrop = anywhere => ({
    y: anywhere ? Math.random() * ROWS * 2 - ROWS : -Math.random() * ROWS,
    speed: 0.05 + Math.random() * 0.12,
    length: 6 + Math.floor(Math.random() * 12),
    chars: Array.from({length: ROWS}, glyph),
  });
  const rain = Array.from({length: COLS}, () => newDrop(true));

  const game = {snake: [], dir: [1, 0], queue: [], food: null, score: 0, best: readBest(), state: 'ready'};
  function show() {
    scoreNode.textContent = game.score;
    bestNode.textContent = game.best;
    statusNode.textContent = game.state === 'ready' ? t('snake.ready') : game.state === 'paused' ? t('snake.paused')
      : game.state === 'over' ? t('snake.over', {score: game.score}) : '';
  }
  function placeFood() {
    const free = [];
    for (let x = 0; x < COLS; x++)
      for (let y = 0; y < ROWS; y++)
        if (!game.snake.some(part => part.x === x && part.y === y)) free.push({x, y});
    game.food = free[Math.floor(Math.random() * free.length)] || null;
  }
  function reset() {
    const y = Math.floor(ROWS / 2);
    game.snake = [8, 7, 6].map(x => ({x, y, ch: glyph()}));
    game.dir = [1, 0];
    game.queue = [];
    game.score = 0;
    game.state = 'ready';
    placeFood();
    show();
  }
  function turn(code) {
    const dir = DIRS[code];
    if (!dir || game.state === 'over') return;
    if (game.state !== 'running') { game.state = 'running'; show(); }
    const previous = game.queue.at(-1) || game.dir;
    if ((dir[0] === -previous[0] && dir[1] === -previous[1]) || (dir[0] === previous[0] && dir[1] === previous[1])) return;
    if (game.queue.length < 3) game.queue.push(dir);
  }
  function advance() {
    if (game.queue.length) game.dir = game.queue.shift();
    const head = game.snake[0];
    const next = {x: (head.x + game.dir[0] + COLS) % COLS, y: (head.y + game.dir[1] + ROWS) % ROWS, ch: glyph()};
    const eating = game.food && next.x === game.food.x && next.y === game.food.y;
    const body = eating ? game.snake : game.snake.slice(0, -1);
    if (body.some(part => part.x === next.x && part.y === next.y)) {
      game.state = 'over';
      show();
      return;
    }
    game.snake = [next, ...body];
    if (!eating) return;
    game.score += 1;
    if (game.score > game.best) { game.best = game.score; saveBest(game.best); }
    placeFood();
    if (!game.food) game.state = 'over';
    show();
  }
  const interval = () => Math.max(55, 150 - game.score * 5);

  function banner(title, hint) {
    const w = COLS * cell, h = ROWS * cell;
    ctx.fillStyle = 'rgba(0, 0, 0, 0.62)';
    ctx.fillRect(0, 0, w, h);
    ctx.shadowColor = '#00ff41';
    ctx.shadowBlur = 12;
    ctx.fillStyle = '#00ff41';
    ctx.font = `600 ${Math.round(cell * 1.15)}px "Cascadia Mono", Consolas, "Courier New", monospace`;
    ctx.fillText(title, w / 2, h / 2 - cell * 0.7);
    ctx.shadowBlur = 0;
    ctx.fillStyle = '#9dffb0';
    ctx.font = `${Math.round(cell * 0.62)}px "Cascadia Mono", Consolas, "Courier New", monospace`;
    ctx.fillText(hint, w / 2, h / 2 + cell * 0.8);
  }
  function render(now, elapsed) {
    const w = COLS * cell, h = ROWS * cell;
    const still = calm();
    ctx.shadowBlur = 0;
    ctx.fillStyle = '#000';
    ctx.fillRect(0, 0, w, h);
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.font = `${Math.floor(cell * 0.8)}px "MS Gothic", "Cascadia Mono", Consolas, monospace`;
    rain.forEach((drop, column) => {
      if (!still) {
        drop.y += drop.speed * elapsed / 16;
        if (Math.random() < 0.05) drop.chars[Math.floor(Math.random() * ROWS)] = glyph();
      }
      const top = Math.floor(drop.y);
      for (let k = 0; k < drop.length; k++) {
        const row = top - k;
        if (row < 0 || row >= ROWS) continue;
        const alpha = (1 - k / drop.length) * (k === 0 ? 0.5 : 0.24);
        ctx.fillStyle = k === 0 ? `rgba(190, 255, 200, ${alpha})` : `rgba(0, 255, 65, ${alpha})`;
        ctx.fillText(drop.chars[row], column * cell + cell / 2, row * cell + cell / 2);
      }
      if (top - drop.length > ROWS) rain[column] = newDrop(false);
    });

    if (game.food) {
      const pulse = still ? 1 : 0.8 + 0.2 * Math.sin(now / 160);
      ctx.save();
      ctx.translate(game.food.x * cell + cell / 2, game.food.y * cell + cell / 2);
      ctx.rotate(-Math.PI / 4);
      ctx.shadowColor = '#ff2a2a';
      ctx.shadowBlur = 14 * pulse;
      ctx.fillStyle = '#e3262e';
      ctx.beginPath();
      if (ctx.roundRect) ctx.roundRect(-cell * 0.4, -cell * 0.19, cell * 0.8, cell * 0.38, cell * 0.19);
      else ctx.rect(-cell * 0.4, -cell * 0.19, cell * 0.8, cell * 0.38);
      ctx.fill();
      ctx.shadowBlur = 0;
      ctx.fillStyle = 'rgba(255, 255, 255, 0.45)';
      ctx.fillRect(-cell * 0.26, -cell * 0.11, cell * 0.3, cell * 0.06);
      ctx.restore();
    }

    if (!still && game.state === 'running' && Math.random() < 0.15)
      game.snake[Math.floor(Math.random() * game.snake.length)].ch = glyph();
    game.snake.forEach((part, index) => {
      ctx.shadowBlur = 0;
      ctx.fillStyle = 'rgba(0, 34, 10, 0.9)';
      ctx.fillRect(part.x * cell + 1, part.y * cell + 1, cell - 2, cell - 2);
      ctx.shadowColor = '#00ff41';
      ctx.shadowBlur = index === 0 ? 14 : 6;
      ctx.fillStyle = index === 0 ? '#eaffea' : `rgba(0, 255, 65, ${1 - index / (game.snake.length + 4) * 0.6})`;
      ctx.fillText(part.ch, part.x * cell + cell / 2, part.y * cell + cell / 2);
    });
    ctx.shadowBlur = 0;

    if (game.state === 'ready') banner(t('snake.readyTitle'), t('snake.ready'));
    else if (game.state === 'paused') banner(t('snake.pausedTitle'), t('snake.paused'));
    else if (game.state === 'over') banner(t('snake.overTitle'), t('snake.over', {score: game.score}));
  }

  let frame = 0, previous = 0, pending = 0;
  function loop(now) {
    frame = requestAnimationFrame(loop);
    const elapsed = Math.min(now - (previous || now), 100);
    previous = now;
    if (game.state === 'running') {
      pending += elapsed;
      while (pending >= interval() && game.state === 'running') {
        pending -= interval();
        advance();
      }
    } else pending = 0;
    render(now, elapsed);
  }

  dialog.addEventListener('keydown', event => {
    if (DIRS[event.code]) {
      event.preventDefault();
      turn(event.code);
    } else if (event.code === 'Space' || event.code === 'Enter') {
      event.preventDefault();
      if (game.state === 'over') reset();
      else if (event.code === 'Space' && game.state === 'running') { game.state = 'paused'; show(); }
      else if (event.code === 'Space' && game.state === 'paused') { game.state = 'running'; show(); }
    }
  });
  let swipe = null;
  canvas.addEventListener('pointerdown', event => {
    swipe = {x: event.clientX, y: event.clientY};
    canvas.focus();
  });
  canvas.addEventListener('pointerup', event => {
    if (!swipe) return;
    const dx = event.clientX - swipe.x, dy = event.clientY - swipe.y;
    swipe = null;
    if (game.state === 'over') return reset();
    if (Math.max(Math.abs(dx), Math.abs(dy)) < 24) return;
    turn(Math.abs(dx) > Math.abs(dy) ? (dx > 0 ? 'ArrowRight' : 'ArrowLeft') : (dy > 0 ? 'ArrowDown' : 'ArrowUp'));
  });
  for (const control of dialog.querySelectorAll('[data-dir]'))
    control.addEventListener('click', () => {
      if (game.state === 'over') reset();
      turn(control.dataset.dir);
    });
  const hidden = () => {
    if (document.hidden && game.state === 'running') { game.state = 'paused'; show(); }
  };
  dialog.querySelector('[data-close]').addEventListener('click', () => dialog.close());
  dialog.addEventListener('close', () => {
    cancelAnimationFrame(frame);
    removeEventListener('resize', size);
    document.removeEventListener('visibilitychange', hidden);
    dialog.remove();
    playing = false;
  });
  addEventListener('resize', size);
  document.addEventListener('visibilitychange', hidden);

  size();
  reset();
  dialog.showModal();
  canvas.focus();
  frame = requestAnimationFrame(loop);
}
