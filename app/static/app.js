/* Honeypot dashboard client.
 *
 * The page arrives fully rendered (tables, feeds, cards); this script adds the
 * map, the day pager, the hourly timeline, click-a-name-to-find-it, and live
 * updates. Live updates replace the old 30s full-page reload: every 30s the
 * page is re-fetched in the background (a cheap 304 until generate.py writes a
 * new one) and only the sections that changed are swapped in, so nothing
 * blanks, scroll positions survive, and the map keeps its view.
 *
 * Strings in the data file are HTML-escaped server-side and inserted as markup.
 */
(function () {
  'use strict';

  var POLL_MS = 30000;
  var LIVE_WINDOW_MIN = 90;   // "active now" = last attempt within this many minutes
  var MAX_PULSES = 40;
  var MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  var COLOR_TRIED = '#ff4444', COLOR_IN = '#ffb000';

  function $(id) { return document.getElementById(id); }
  function readConfig(doc) { return JSON.parse(doc.getElementById('hpd-config').textContent); }
  function storage(key, value) {
    try {
      if (arguments.length === 1) return localStorage.getItem(key);
      if (value === null) localStorage.removeItem(key); else localStorage.setItem(key, value);
    } catch (e) { return null; }
  }

  var cfg = readConfig(document);

  // ---- dates (day keys are the server's local "YYYY-MM-DD") ----
  function parseDay(key) { var p = key.split('-'); return new Date(+p[0], +p[1] - 1, +p[2]); }
  function dayKey(d) {
    return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
  }
  function shiftDay(key, n) { var d = parseDay(key); d.setDate(d.getDate() + n); return dayKey(d); }
  function fmtDay(key) { var d = parseDay(key); return MONTHS[d.getMonth()] + ' ' + d.getDate() + ', ' + d.getFullYear(); }

  // ---- state ----
  var data = null;            // decoded data file
  var byIp = {};              // ip -> record
  var byDay = {};             // day -> [[record, count], ...]
  var dayHours = {};          // day -> [24 counts]
  var minDay = cfg.today;
  // Selected day: null follows "today" (also across midnight); a key pins a day.
  storage('hpd_dayOffset', null);   // superseded by hpd_day
  var pinnedDay = storage('hpd_day');
  var selectedIp = null, pendingSelect = null;

  function currentDay() {
    var d = pinnedDay || cfg.today;
    if (d > cfg.today) d = cfg.today;
    if (d < minDay) d = minDay;
    return d;
  }

  // ---- map ----
  var map = null, canvas = null, svg = null;
  var dotLayer = null, pulseLayer = null, selectLayer = null;
  var popup = null, popupIp = null;

  function initMap() {
    map = L.map('map', {
      center: [20, 0], zoom: 2, minZoom: 2,
      maxBounds: [[-85, -180], [85, 180]], maxBoundsViscosity: 1.0,
      worldCopyJump: false
    });
    // Esri "World Dark Gray Base" — free, no API key, attribution required.
    L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}', {
      maxZoom: 18, maxNativeZoom: 16,
      attribution: 'Tiles &copy; Esri &mdash; Esri, HERE, Garmin, &copy; OpenStreetMap contributors'
    }).addTo(map);
    // One canvas draws every dot (hundreds of SVG nodes animated per frame was
    // the old bottleneck); SVG only for the few CSS-animated rings.
    // The rings live in their own pane under the dots with pointer events off,
    // or the SVG layer would sit over the canvas and swallow its clicks.
    map.createPane('rings');
    map.getPane('rings').style.zIndex = 390;
    map.getPane('rings').style.pointerEvents = 'none';
    // padding 1 = one extra screen in every direction, and the dots are redrawn
    // during a drag (Leaflet only redraws on release), so fast drags don't
    // show clipped or missing dots. A few hundred dots redraw in well under 1ms.
    canvas = L.canvas({ padding: 1 });
    svg = L.svg({ padding: 1, pane: 'rings' });
    var redrawQueued = false;
    map.on('move', function () {
      if (redrawQueued) return;
      redrawQueued = true;
      requestAnimationFrame(function () {
        redrawQueued = false;
        if (canvas._map) canvas._update();   // Leaflet's own reposition+redraw
      });
    });
    pulseLayer = L.layerGroup().addTo(map);
    dotLayer = L.layerGroup().addTo(map);
    selectLayer = L.layerGroup().addTo(map);
    popup = L.popup({ maxWidth: 320, autoPanPadding: [30, 30] });
    map.on('popupclose', function () { popupIp = null; });
    if (window.ResizeObserver) {
      new ResizeObserver(function () { map.invalidateSize(); }).observe($('map'));
    }
    if (!(window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches)) requestAnimationFrame(breathe);
  }

  // Every dot breathes slowly on its own phase and tempo (seeded from its IP),
  // so the map shimmers instead of pulsing in unison. One full redraw of the
  // dot canvas per frame, capped near 30 fps; rAF pauses it in hidden tabs.
  var BREATHE_MS = 33, lastBreath = 0;
  function seed(ip) {   // FNV-1a hash -> [0, 1)
    var h = 2166136261;
    for (var i = 0; i < ip.length; i++) { h ^= ip.charCodeAt(i); h = Math.imul(h, 16777619); }
    return (h >>> 0) / 4294967296;
  }
  function breathe(now) {
    requestAnimationFrame(breathe);
    if (now - lastBreath < BREATHE_MS || !canvas._map) return;
    lastBreath = now;
    var t = now / 1000;
    dotLayer.eachLayer(function (dot) {
      var b = 0.5 + 0.5 * Math.sin(t * dot.tempo + dot.phase);   // 0..1
      dot.options.fillOpacity = 0.3 + 0.4 * b;
      dot.options.opacity = 0.6 + 0.35 * b;
    });
    canvas._redraw();
  }

  function decode(d) {
    var c = d.markers, S = c.strings, recs = new Array(c.ip.length);
    byIp = {}; byDay = {}; dayHours = {};
    for (var i = 0; i < c.ip.length; i++) {
      var daily = {}, hours = {}, days = [], flat = c.daily[i];
      for (var j = 0; j < flat.length; j += 3) {
        var day = c.days[flat[j]];
        daily[day] = flat[j + 1];
        hours[day] = flat[j + 2];   // bit h set = attempts in local hour h
        days.push(day);
      }
      var rec = recs[i] = {
        ip: c.ip[i], nick: c.nick[i], lat: c.lat[i], lon: c.lon[i],
        city: S[c.city[i]], country: S[c.country[i]], isp: S[c.isp[i]],
        creds: c.creds[i], why: c.why ? S[c.why[i]] : '',
        n: c.n ? c.n[i] : 0, ok: c.ok ? c.ok[i] : 0, last: c.last ? c.last[i] : 0,
        daily: daily, hours: hours, days: days.sort()
      };
      byIp[rec.ip] = rec;
      for (var k = 0; k < days.length; k++) (byDay[days[k]] = byDay[days[k]] || []).push([rec, daily[days[k]]]);
    }
    for (var t = 0; t < d.timelineLabels.length; t++) {
      var label = d.timelineLabels[t], dk = label.substring(0, 10), hr = parseInt(label.substring(11, 13), 10);
      if (!dayHours[dk]) dayHours[dk] = new Array(24).fill(0);
      if (hr >= 0 && hr < 24) dayHours[dk][hr] += d.timelineData[t];
    }
    d.strings = S;
    return d;
  }

  function radius(count) { return Math.max(4, Math.min(22, 3 + 2.2 * Math.sqrt(count))); }

  function drawDay(day) {
    if (!map || !data) return;
    dotLayer.clearLayers();
    pulseLayer.clearLayers();
    var rows = byDay[day] || [], dayTotal = rows.length;
    if (hourFilter !== null) rows = rows.filter(function (r) { return (r[0].hours[day] >> hourFilter) & 1; });
    // Small dots on top of big ones, so every dot stays clickable.
    rows.sort(function (a, b) { return b[1] - a[1]; });
    var nowMin = cfg.generated / 60, pulses = 0;
    for (var i = 0; i < rows.length; i++) {
      var rec = rows[i][0], count = rows[i][1], color = rec.ok ? COLOR_IN : COLOR_TRIED;
      var dot = L.circleMarker([rec.lat, rec.lon], {
        renderer: canvas, radius: radius(count),
        color: color, weight: 1.5, opacity: 0.9, fillColor: color, fillOpacity: 0.55
      });
      dot.rec = rec;
      var s0 = seed(rec.ip);
      dot.phase = s0 * 2 * Math.PI;
      dot.tempo = 2 * Math.PI / (2.6 + 1.8 * ((s0 * 7.31) % 1));   // one breath every 2.6-4.4 s
      dot.on('click', onDotClick);
      dotLayer.addLayer(dot);
    }
    if (day === cfg.today) {
      var live = rows.filter(function (r) { return r[0].last && nowMin - r[0].last <= LIVE_WINDOW_MIN; })
        .sort(function (a, b) { return b[0].last - a[0].last; });
      for (var p = 0; p < live.length && pulses < MAX_PULSES; p++, pulses++) {
        var r = live[p][0];
        pulseLayer.addLayer(L.circleMarker([r.lat, r.lon], {
          renderer: svg, radius: radius(live[p][1]), interactive: false, pane: 'rings',
          color: r.ok ? COLOR_IN : COLOR_TRIED, weight: 2, fill: false, className: 'hp-pulse'
        }));
      }
    }
    var label = (day === cfg.today ? 'Today · ' : '') + fmtDay(day);
    $('dayLabel').textContent = label + (hourFilter !== null ? ' · ' + hourRange(hourFilter) : '');
    $('dayLabel').title = rows.length + ' attacking IPs';
    $('timelineDayLabel').textContent = label + ' · ' + dayTotal.toLocaleString() + ' IPs';
    $('dayPrev').disabled = day <= minDay;
    $('dayNext').disabled = day >= cfg.today;
    drawSelection();
  }

  // ---- hour filter: click an hour bar to show only the attackers active then ----
  var hourFilter = null;
  function hourRange(hr) { var p = function (n) { return String(n % 24).padStart(2, '0') + ':00'; }; return p(hr) + '–' + p(hr + 1); }
  function setHour(hr) {
    hourFilter = hourFilter === hr ? null : hr;   // the same bar again shows the whole day
    drawDay(currentDay());
    drawTimeline(currentDay());
    if (hourFilter === null) { note(''); return; }
    $('map').scrollIntoView({ behavior: 'smooth', block: 'center' });
    var n = (byDay[currentDay()] || []).filter(function (r) { return (r[0].hours[currentDay()] >> hourFilter) & 1; }).length;
    note(hourRange(hourFilter) + ' · ' + n.toLocaleString() + ' attacker' + (n === 1 ? '' : 's') + ' · click the bar again for the whole day', 6000);
  }

  function onDotClick(e) { selectedIp = e.target.rec.ip; drawSelection(); openPopup(e.target.rec); }

  function drawSelection() {
    if (!selectLayer) return;
    selectLayer.clearLayers();
    var rec = selectedIp && byIp[selectedIp];
    if (!rec) return;
    var count = rec.daily[currentDay()];
    if (!count) return;
    selectLayer.addLayer(L.circleMarker([rec.lat, rec.lon], {
      renderer: svg, radius: radius(count) + 5, interactive: false, pane: 'rings',
      color: '#00ff41', weight: 2.5, fill: false, className: 'hp-select'
    }));
  }

  function popupHtml(rec) {
    var day = currentDay(), today = rec.daily[day] || 0, S = data.strings;
    var where = (rec.city ? rec.city + ', ' : '') + rec.country;
    var creds = rec.creds.map(function (k) { return S[k]; }).join('<br>');
    var last = rec.days[rec.days.length - 1];
    return '<div class="pop">' +
      '<div class="pop-nick">' + rec.nick + '</div>' +
      (rec.why ? '<div class="pop-why">named for ' + rec.why + '</div>' : '') +
      '<div class="pop-ip">' + rec.ip + '</div>' +
      '<div><span class="l">Location:</span> ' + where + '</div>' +
      '<div><span class="l">ISP:</span> ' + rec.isp + '</div>' +
      '<div><span class="l">Attempts:</span> <strong>' + today.toLocaleString() + '</strong> this day · ' +
        rec.n.toLocaleString() + ' total</div>' +
      '<div><span class="l">Active:</span> ' + rec.days.length + ' day' + (rec.days.length === 1 ? '' : 's') +
        (last && last !== day ? ' · last ' + fmtDay(last) : '') + '</div>' +
      (rec.ok ? '<div class="pop-in">✓ got in</div>' : '') +
      (creds ? '<div class="l">Creds tried:</div><div class="pop-creds">' + creds + '</div>' : '') +
      '</div>';
  }

  function openPopup(rec) {
    popupIp = rec.ip;
    popup.setLatLng([rec.lat, rec.lon]).setContent(popupHtml(rec)).openOn(map);
  }

  var noteTimer = null;
  function note(text, ms) {
    var el = $('mapNote');
    el.textContent = text;
    el.hidden = !text;
    clearTimeout(noteTimer);
    if (text && ms) noteTimer = setTimeout(function () { el.hidden = true; }, ms);
  }

  function setDay(day, persist) {
    hourFilter = null;
    pinnedDay = day >= cfg.today ? null : day;
    if (persist !== false) storage('hpd_day', pinnedDay);
    drawDay(currentDay());
    drawTimeline(currentDay());
  }

  // Click a name anywhere -> scroll to the map, switch to a day the attacker
  // was active (if the current day isn't one), fly there and open its popup.
  function selectAttacker(ip, label) {
    $('map').scrollIntoView({ behavior: 'smooth', block: 'center' });
    if (!data || !map) { pendingSelect = [ip, label]; note('loading attackers…'); return; }
    var rec = byIp[ip];
    if (!rec) { note('No map location on record for ' + (label || ip), 3500); return; }
    selectedIp = ip;
    if (!rec.daily[currentDay()]) {
      var last = rec.days[rec.days.length - 1];
      setDay(last);
      note(last === cfg.today ? 'Switched to today, when ' + rec.nick + ' was active'
        : 'Showing ' + fmtDay(last) + ', the last day ' + rec.nick + ' was active', 3500);
    } else {
      drawSelection();
    }
    map.closePopup();
    var target = L.latLng(rec.lat, rec.lon);
    var zoom = Math.max(map.getZoom(), 5);
    map.once('moveend', function () { openPopup(rec); });
    if (map.getCenter().distanceTo(target) < 1 && map.getZoom() === zoom) map.fire('moveend');
    else map.flyTo(target, zoom, { duration: 0.8 });
  }

  // ---- hourly timeline (inline SVG; Chart.js was 200 KB for this) ----
  function drawTimeline(day) {
    var hours = (day === cfg.today && !dayHours[day]) ? cfg.todayHours : (dayHours[day] || new Array(24).fill(0));
    var W = 480, H = 170, L0 = 34, B = 20, T = 8, max = Math.max.apply(null, hours);
    var nice = niceMax(max), bw = (W - L0) / 24, out = [];
    out.push('<svg viewBox="0 0 ' + W + ' ' + H + '" role="img" aria-label="Login attempts per hour">');
    for (var g = 0; g <= 4; g++) {
      var y = T + (H - B - T) * (1 - g / 4), v = Math.round(nice * g / 4);
      out.push('<line class="grid-line" x1="' + L0 + '" x2="' + W + '" y1="' + y + '" y2="' + y + '"/>');
      out.push('<text x="' + (L0 - 5) + '" y="' + (y + 3) + '" text-anchor="end">' + compact(v) + '</text>');
    }
    var nowHour = day === cfg.today ? new Date(cfg.generated * 1000).getHours() : -1;
    for (var h = 0; h < 24; h++) {
      var bh = nice ? (H - B - T) * hours[h] / nice : 0, x = L0 + h * bw + 1.5;
      out.push('<rect class="bar' + (h === nowHour ? ' now' : '') + (h === hourFilter ? ' sel' : '') + '"' +
        (hours[h] ? ' data-hour="' + h + '"' : '') + ' x="' + x.toFixed(1) + '" y="' + (H - B - bh).toFixed(1) +
        '" width="' + (bw - 3).toFixed(1) + '" height="' + Math.max(bh, hours[h] ? 1 : 0).toFixed(1) + '"><title>' +
        String(h).padStart(2, '0') + ':00 — ' + hours[h].toLocaleString() + ' attempts' +
        (hours[h] ? ' · click to show these attackers' : '') + '</title></rect>');
      if (h % 3 === 0) out.push('<text x="' + (x + bw / 2 - 1.5).toFixed(1) + '" y="' + (H - 5) + '" text-anchor="middle">' + String(h).padStart(2, '0') + '</text>');
    }
    out.push('</svg>');
    $('timeline').innerHTML = out.join('');
  }
  // Axis top = 4 × a round step (1, 2, 2.5, 5 × 10^k; 2.5 only where whole), so every gridline label is
  // a round number (not 13 / 25 / 38 / 50).
  function niceMax(v) {
    if (v <= 4) return 4;
    var raw = v / 4, p = Math.pow(10, Math.floor(Math.log10(raw))), m = raw / p;
    return (m <= 1 ? 1 : m <= 2 ? 2 : (m <= 2.5 && p >= 10) ? 2.5 : m <= 5 ? 5 : 10) * p * 4;
  }
  function compact(v) { return v >= 1000 ? (v / 1000).toFixed(v % 1000 ? 1 : 0) + 'k' : String(v); }

  // ---- "Successful Logins": only the first groups are in the page; the rest
  // come from the data file and are appended as the panel nears its end. ----
  var terminalRest = [];
  function appendTerminal() {
    var el = $('terminalLog');
    if (!terminalRest.length || el.scrollTop + el.clientHeight < el.scrollHeight - 800) return;
    el.insertAdjacentHTML('beforeend', terminalRest.splice(0, 40).join(''));
  }

  // ---- live updates ----
  var lastOk = Date.now(), offline = false;
  function updateStatus() {
    var el = $('liveStatus'), mins = Math.max(0, Math.round((Date.now() / 1000 - cfg.generated) / 60));
    el.classList.toggle('offline', offline);
    $('updatedAgo').textContent = offline ? 'offline · retrying' :
      'updated ' + (mins < 1 ? 'just now' : mins < 60 ? mins + 'm ago' :
        new Date(cfg.generated * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
  }

  function poll() {
    if (document.hidden) return;
    fetch(location.pathname + location.search, { cache: 'no-cache', credentials: 'same-origin' })
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.text(); })
      .then(function (text) {
        offline = false; lastOk = Date.now();
        var m = text.match(/"version":"([0-9a-f]+)"/);
        if (m && m[1] === cfg.version) return;
        return applyPage(new DOMParser().parseFromString(text, 'text/html'));
      })
      .catch(function () { offline = true; })
      .then(updateStatus);
  }

  function applyPage(doc) {
    var next = readConfig(doc);
    var dataReady = next.dataUrl === cfg.dataUrl ? Promise.resolve(null) :
      fetch(next.dataUrl).then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); });
    return dataReady.then(function (fresh) {
      document.querySelectorAll('[data-live]').forEach(function (el) {
        var src = doc.getElementById(el.id);
        if (!src || src.innerHTML === el.innerHTML) return;
        // Don't yank the login log out from under someone reading it.
        if (el.dataset.live === 'terminal' && el.scrollTop > 0) return;
        var top = el.scrollTop;
        el.innerHTML = src.innerHTML;
        el.scrollTop = top;
        if (el.dataset.live === 'terminal' && fresh) terminalRest = (fresh.terminal || []).slice();
      });
      cfg = next;
      if (fresh) loadData(fresh, true);
      else { drawDay(currentDay()); drawTimeline(currentDay()); }
    });
  }

  function loadData(d, isUpdate) {
    data = decode(d);
    minDay = d.minDay && d.minDay < cfg.today ? d.minDay : cfg.today;
    if (!isUpdate) terminalRest = d.terminal || [];
    drawDay(currentDay());
    drawTimeline(currentDay());
    if (popupIp && byIp[popupIp] && map.hasLayer(popup)) popup.setContent(popupHtml(byIp[popupIp]));
    if (!isUpdate) {
      note('');
      appendTerminal();
      if (pendingSelect) { selectAttacker(pendingSelect[0], pendingSelect[1]); pendingSelect = null; }
    }
  }

  // ---- wiring ----
  function start() {
    drawTimeline(currentDay());
    $('dayLabel').textContent = (currentDay() === cfg.today ? 'Today · ' : '') + fmtDay(currentDay());
    updateStatus();

    document.addEventListener('click', function (e) {
      var t = e.target.closest('[data-ip]');
      if (t) { selectAttacker(t.getAttribute('data-ip'), t.textContent.trim()); return; }
      var hb = e.target.closest('[data-hour]');
      if (hb) { if (data) setHour(+hb.getAttribute('data-hour')); return; }
      var d = e.target.closest('[data-day]');
      if (d) {
        setDay(d.getAttribute('data-day'));
        $('map').scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    });
    $('dayPrev').addEventListener('click', function () { setDay(shiftDay(currentDay(), -1)); });
    $('dayNext').addEventListener('click', function () { setDay(shiftDay(currentDay(), 1)); });
    $('terminalLog').addEventListener('scroll', appendTerminal, { passive: true });

    if (window.L) initMap();
    else note('map library failed to load');

    window.hpdData.then(function (d) { loadData(d, false); })
      .catch(function (err) { console.error('Failed to load dashboard data:', err); note('could not load map data'); });

    setInterval(poll, POLL_MS);
    setInterval(updateStatus, POLL_MS);
    document.addEventListener('visibilitychange', function () {
      if (!document.hidden && Date.now() - lastOk > POLL_MS) poll();
    });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();
})();
