import {esc, formatNumber, formatDate, plural, t, afterRender} from './ui.js';

const LAND = [
  [[-168,66],[-162,70],[-156,71],[-141,70],[-128,70],[-115,69],[-108,68],[-95,72],[-85,70],[-82,67],[-88,64],[-94,61],[-92,57],[-82,55],[-79,51],[-79,58],[-77,62],[-70,62],[-65,60],[-61,56],[-56,52],[-60,50],[-66,50],[-65,45],[-70,43],[-74,40],[-76,35],[-81,31],[-80,25],[-82,29],[-85,30],[-90,29],[-94,29],[-97,26],[-97,21],[-94,18],[-91,19],[-90,21],[-87,21],[-88,16],[-84,15],[-83,10],[-80,9],[-78,8],[-80,7],[-85,10],[-88,13],[-92,15],[-96,16],[-101,17],[-105,20],[-108,25],[-112,29],[-115,32],[-117,33],[-121,35],[-124,40],[-124,47],[-128,51],[-133,55],[-137,59],[-146,61],[-152,59],[-158,57],[-163,55],[-162,59],[-166,61],[-164,64]],
  [[-73,78],[-60,82],[-35,83],[-20,80],[-20,74],[-25,70],[-40,65],[-43,60],[-50,62],[-54,67],[-58,74],[-68,76]],
  [[-90,73],[-78,74],[-68,70],[-62,66],[-66,62],[-74,64],[-82,68]],
  [[-120,72],[-105,73],[-100,70],[-110,68],[-118,70]],
  [[-90,77],[-75,78],[-65,82],[-80,83],[-92,80]],
  [[-84,22],[-80,23],[-75,20],[-78,20]], [[-74,19.5],[-69,19.5],[-69,18],[-74,18]],
  [[-78,8],[-72,12],[-64,10],[-60,8],[-52,5],[-50,0],[-44,-2],[-35,-6],[-35,-9],[-39,-14],[-40,-21],[-48,-26],[-53,-34],[-58,-38],[-65,-41],[-65,-46],[-69,-51],[-68,-55],[-74,-52],[-75,-46],[-73,-37],[-71,-30],[-70,-18],[-76,-14],[-81,-6],[-80,-2],[-78,2],[-77,7]],
  [[-9,37],[-9.5,43],[-2,43.5],[-1.5,46],[-4.5,48.5],[-1,49],[2,51],[4,52.5],[7,53.5],[8.5,57],[6,58],[5,62],[12,66],[15,69],[25,71],[31,70],[41,67],[45,68],[54,68.5],[60,69],[68,69],[70,73],[80,73],[87,75],[100,77],[105,78],[113,74],[130,71],[140,73],[150,71],[160,70],[170,70],[180,69],[180,65],[178,62],[170,60],[163,58],[162,55],[156,51],[156,57],[160,61],[155,59],[143,59],[135,55],[141,53],[140,48],[135,44],[130,42.5],[128,39.5],[129,36],[126.5,34.5],[126,37],[125,39.5],[121,39],[118,38.5],[122,37],[119,35],[122,31],[121,28],[118,24],[113,22],[109,21.5],[106,20],[107,17],[109,13],[107,10.5],[105,9],[103,10.5],[100,13.5],[99,10],[101,6],[103.5,1.5],[101,3],[98,8],[98,16],[94,17],[92,21],[90,22],[87,21],[85,19],[80,15],[80,10],[77.5,8],[76,11],[73,17],[72.5,21],[70,21],[67,24],[62,25],[57,25.5],[56,27],[52,27.5],[50,30],[48,30],[48,29],[50,26.5],[51.5,25],[52,24],[54.5,24.5],[56.3,26],[56.5,24],[59.5,22.5],[58,20],[55,17],[52,16],[45,13],[43.5,12.7],[42.5,16],[39,21],[36,26],[35,28],[34.5,29.5],[34.5,31.5],[35.5,34],[36,36.5],[32,36.5],[30,36.5],[27.5,37],[26.5,39.5],[29,41],[26,41],[24,40.5],[23.5,38],[22.5,36.5],[21,38],[19.5,41.5],[18,43],[14,45],[13.5,45.5],[12.3,44.5],[14,42.5],[16,41.5],[18.5,40],[17,39],[16,38],[15.7,40],[12.5,42],[10.5,43.5],[9,44.5],[7.5,43.7],[3.5,43.3],[3,42],[0.5,40.5],[-0.5,38],[-2,36.7],[-5.5,36]],
  [[-180,69],[-170,66],[-173,64],[-180,65]],
  [[-5.5,50],[1.5,51],[0,53],[-1.5,55],[-2,57.5],[-5,58.5],[-6,56.5],[-3,54],[-4.5,53],[-5,51.7]],
  [[-10,52],[-6,52],[-6,55],[-8,55.3],[-10,54]],
  [[-24,65.5],[-22,64],[-14,64.5],[-14,66],[-18,66.5],[-23,66.3]],
  [[11,79],[20,80.5],[27,80],[22,77.5],[15,77]], [[52,71],[57,74],[68,77],[60,75.5],[55,72.5]],
  [[-6,35.8],[-1,35],[10,37],[11,33.5],[15,32.5],[20,31],[25,32],[32,31.3],[34,28],[35.5,24],[37,21],[39,15.5],[43,12],[51,12],[50,9],[46,3],[41,-2],[39,-6],[40.5,-11],[40,-16],[35,-20],[35.5,-24],[32.5,-26],[30,-31],[26,-34],[20,-34.8],[18,-33],[15,-27],[12,-18],[13.5,-12],[12,-6],[9,-1],[9.5,4],[5,5],[1,6],[-4,5],[-8,4.5],[-13,8],[-17,12],[-17,15],[-16.5,21],[-13,27],[-10,30],[-9.5,32.5]],
  [[49.5,-12],[50.5,-16],[47.5,-25],[44,-25],[43.5,-21],[44,-16],[47,-14]],
  [[114,-22],[113.5,-26],[115,-34],[118,-35],[124,-33],[129,-31.5],[134,-33],[137.5,-33],[138,-35.5],[141,-38],[146,-39],[150,-37.5],[153,-31],[153,-25],[149,-21],[146,-19],[145.5,-15],[142.5,-11],[141,-13],[141,-17],[136,-15],[136,-12],[131,-12],[129,-15],[126,-14],[122,-18],[117,-20.5]],
  [[145,-41],[148,-41],[148,-43.5],[146,-43.5]],
  [[173,-35],[178,-38],[176,-41],[173,-39.5]], [[172.5,-41],[174,-42],[171,-45],[168.5,-46.5],[167,-45.5]],
  [[131,-1],[138,-2],[145,-5],[150.5,-10],[147,-9.5],[143,-8.5],[138,-8],[134,-4]],
  [[109,1.5],[115,7],[119,5],[117,0],[116,-4],[111,-3]],
  [[95.5,5.5],[98,4],[103.5,-1.5],[106,-5.5],[102,-5],[98,0]],
  [[105.5,-6],[110,-6.5],[114.5,-7.5],[114,-8.5],[106,-7.5]],
  [[119,1],[125,1.5],[123,-1],[122.5,-5],[120,-5.5],[119.5,-2]],
  [[120,18.5],[122.5,18],[124,13],[121,13.5]], [[122,8],[126.5,9],[126,6],[124,6]],
  [[130,31.5],[132,34],[135.5,35.5],[137,37],[140,40],[141.5,41.5],[142,39],[141,36],[138,34.5],[135,33.5],[131.5,31.5]],
  [[140,42],[142,45.5],[145.5,43.5],[143,42]], [[142,46],[143,50],[143,54],[142,52],[141.8,48]],
  [[120.2,23],[121.5,25.2],[122,24],[121,22]], [[80,9.5],[81.8,8],[81.5,6.2],[80,6]],
];
const WATER = [
  [[11,54.5],[14,54.5],[19,55],[21,56],[21,58],[23.5,59.3],[29,59.8],[29,60.3],[23,60],[21.5,61],[21.5,63],[25,65.3],[22,65.7],[18,62],[17,59],[16.5,56.5],[13,55.5]],
  [[28,41.5],[28.5,45],[31,46.5],[34,46],[37,47],[39,46],[41.5,42],[38,41],[33,42],[30,41]],
  [[47,44],[51,47],[53,45],[53,41],[54,39],[53,37],[50,37],[49,40],[47,42]],
];

const WIDTH = 1000, TOP = 84, BOTTOM = -58, STEP = 2.5;
const HEIGHT = WIDTH * (TOP - BOTTOM) / 360;
const px = longitude => (longitude + 180) / 360 * WIDTH;
const py = latitude => (TOP - latitude) / (TOP - BOTTOM) * HEIGHT;

function inside(polygon, x, y) {
  let hit = false;
  for (let i = 0, j = polygon.length - 1; i < polygon.length; j = i++) {
    const [xi, yi] = polygon[i], [xj, yj] = polygon[j];
    if ((yi > y) !== (yj > y) && x < (xj - xi) * (y - yi) / (yj - yi) + xi) hit = !hit;
  }
  return hit;
}
let landPath = null;
function land() {
  if (landPath) return landPath;
  const dots = [];
  for (let latitude = TOP - STEP / 2; latitude > BOTTOM; latitude -= STEP)
    for (let longitude = -180 + STEP / 2; longitude < 180; longitude += STEP)
      if (LAND.some(shape => inside(shape, longitude, latitude)) && !WATER.some(shape => inside(shape, longitude, latitude)))
        dots.push(`M${px(longitude).toFixed(1)} ${py(latitude).toFixed(1)}h.01`);
  landPath = dots.join('');
  return landPath;
}
function graticule() {
  const lines = [];
  for (let longitude = -150; longitude <= 150; longitude += 30) lines.push(`M${px(longitude)} 0V${HEIGHT}`);
  for (let latitude = 60; latitude >= -30; latitude -= 30) lines.push(`M0 ${py(latitude)}H${WIDTH}`);
  return lines.join('');
}

export function worldMap(markers) {
  const peak = Math.max(1, ...markers.map(marker => marker.events));
  const points = markers.filter(marker => marker.latitude <= TOP && marker.latitude >= BOTTOM).map((marker, index) => {
    const radius = 4 + Math.sqrt(marker.events / peak) * 9;
    const place = marker.city ? `${marker.city}, ${marker.country}` : marker.country;
    const text = t('geo.markerLabel', {place, events: plural('counts.events', marker.events)});
    return `<g class="map-marker" tabindex="0" role="img" aria-label="${esc(text)}" data-marker="${index}">` +
      `<circle class="map-halo" cx="${px(marker.longitude).toFixed(1)}" cy="${py(marker.latitude).toFixed(1)}" r="${(radius * 2).toFixed(1)}"/>` +
      `<circle class="map-point" cx="${px(marker.longitude).toFixed(1)}" cy="${py(marker.latitude).toFixed(1)}" r="${radius.toFixed(1)}"/></g>`;
  }).join('');
  return `<div class="world-map" data-map><svg viewBox="0 0 ${WIDTH} ${HEIGHT.toFixed(0)}" role="group" aria-label="${esc(t('geo.mapLabel'))}">` +
    `<path class="map-grid" d="${graticule()}"/><path class="map-land" d="${land()}"/>${points}</svg><div class="chart-tip" hidden></div></div>`;
}

let current = [];
export const setMarkers = markers => { current = markers; };
function tip(host, group) {
  const marker = current[Number(group.dataset.marker)];
  if (!marker) return;
  const box = host.getBoundingClientRect(), point = group.querySelector('.map-point').getBoundingClientRect();
  const node = host.querySelector('.chart-tip');
  node.innerHTML = `<strong>${esc(marker.city ? `${marker.city}, ${marker.country}` : marker.country)}</strong>` +
    `<span>${esc(t('geo.tipEvents'))}<b>${formatNumber(marker.events)}</b></span>` +
    `<span>${esc(t('geo.tipSources'))}<b>${formatNumber(marker.unique_ips)}</b></span>` +
    `<span>${esc(t('geo.tipHoneypots'))}<b>${formatNumber(marker.honeypots)}</b></span>` +
    `<span>${esc(t('geo.tipLast'))}<b>${esc(formatDate(marker.last_seen))}</b></span>`;
  node.hidden = false;
  const left = point.left - box.left + point.width + 10;
  node.style.left = `${Math.min(Math.max(left, 4), Math.max(box.width - node.offsetWidth - 4, 4))}px`;
  node.style.top = `${Math.max(point.top - box.top - 10, 4)}px`;
}
afterRender(rootNode => {
  for (const host of rootNode.querySelectorAll('[data-map]')) {
    if (host.dataset.ready) continue;
    host.dataset.ready = '1';
    const hide = () => { host.querySelector('.chart-tip').hidden = true; };
    host.addEventListener('pointerover', event => { const group = event.target.closest('.map-marker'); if (group) tip(host, group); });
    host.addEventListener('pointerout', event => { if (event.target.closest('.map-marker')) hide(); });
    host.addEventListener('focusin', event => { const group = event.target.closest('.map-marker'); if (group) tip(host, group); });
    host.addEventListener('focusout', hide);
  }
});
