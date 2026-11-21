// Reconnaissance "lecture d'origine" : compare le fichier importe aux references d'usine (refs/).
// Tourne dans le navigateur, rien n'est envoye.
//
// - Zone 0x00000-0x0FFFF (boot, VIN, ISN) : propre a chaque voiture, jamais comparee.
// - Zone programme 0x10000-0x6FFFF : sur un SW "strict" (430069 : 15 lectures, une seule empreinte),
//   un programme different prouve un patch. Sur les autres SW, plusieurs variantes d'usine peuvent
//   exister : seul un patch reconnu (EWS / Immo OFF) prouve une retouche.
//   Lecture partielle (programme vide, FF) : on ne juge que la calibration.
// - Calibration 0x70000-0x7FFFF : doit etre identique a l'une des variantes d'usine connues.
//   Sinon : on cherche la variante la plus proche et on liste les cartographies qui different.
//
// Statuts :
//   stock       calibration identique a une reference d'usine, programme d'origine ou non contredit.
//               (programChecked=false : programme non verifiable -> partiel ou variante non repertoriee)
//   modified    programme patche : fichier deja retouche, a coup sur.
//   cal_unknown calibration absente de la base : soit modifiee, soit variante d'usine non
//               repertoriee. Les cartographies differentes sont listees (+ estimation, voir plus bas).
//   no_ref      aucune reference pour ce SW : estimation seulement.

import { readMap, parseEquation } from './ms43.js';

let refsPromise = null;
const loadRefs = () => (refsPromise ??= fetch('refs/origin.json')
  .then((r) => (r.ok ? r.json() : null))
  .catch(() => null));

const calCache = new Map();
function loadCal(path) {
  if (!calCache.has(path)) {
    calCache.set(path, fetch(`refs/${path}`)
      .then((r) => (r.ok ? r.arrayBuffer() : null))
      .then((b) => (b ? new Uint8Array(b) : null))
      .catch(() => null));
  }
  return calCache.get(path);
}

async function sha256Hex(view) {
  const digest = await crypto.subtle.digest('SHA-256', view);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

// Lecture partielle : zone 0x10000-0x5FFFF quasi entierement a FF (programme non lu).
function isBlankProgram(bytes) {
  let ff = 0, n = 0;
  for (let i = 0x10000; i < 0x60000; i += 64) { n++; if (bytes[i] === 0xff) ff++; }
  return ff / n > 0.9;
}

const hexOf = (bytes, offset, length) =>
  [...bytes.subarray(offset, offset + length)].map((b) => b.toString(16).padStart(2, '0')).join('');

export async function checkOrigin(bytes, software) {
  const refs = await loadRefs();
  const ref = refs?.software?.[software];
  if (!ref) return { status: 'no_ref' };

  const [progStart, progLen] = refs.program;
  const [calStart, calLen] = refs.calibration;
  const programHash = await sha256Hex(bytes.subarray(progStart, progStart + progLen));
  const calHash = await sha256Hex(bytes.subarray(calStart, calStart + calLen));
  // Patchs programme reconnus (ex. EWS / Immo OFF).
  const signatures = (ref.signatures || [])
    .filter((s) => s.bytes.every(([o, hex]) => hexOf(bytes, o, hex.length / 2) === hex))
    .map((s) => s.name);

  // programOk : true = programme d'usine connu ; false = programme retouche (certain) ;
  // null = non verifiable (lecture partielle, ou SW avec variantes d'usine non repertoriees).
  const partial = isBlankProgram(bytes);
  let programOk;
  if (signatures.length) programOk = false;
  else if (partial) programOk = null;
  else if ((ref.program_sha256 || []).includes(programHash)) programOk = true;
  else programOk = ref.program_strict ? false : null;

  const exact = ref.stocks.find((s) => s.cal_sha256 === calHash);
  if (programOk !== false && exact) {
    return { status: 'stock', match: exact, programOk, programChecked: programOk === true, partial, signatures: [] };
  }

  // Calibration non reconnue telle quelle : reference d'usine la plus proche (moins d'octets differents).
  let nearest = null;
  if (!exact) {
    const cals = await Promise.all(ref.stocks.map((s) => loadCal(s.cal)));
    const cal = bytes.subarray(calStart, calStart + calLen);
    ref.stocks.forEach((stock, i) => {
      const r = cals[i];
      if (!r || r.length !== calLen) return;
      let count = 0;
      for (let k = 0; k < calLen; k++) if (cal[k] !== r[k]) count++;
      if (!nearest || count < nearest.count) nearest = { stock, index: i, count };
    });
    if (nearest) {
      const r = cals[nearest.index];
      nearest.offsets = [];
      for (let k = 0; k < calLen; k++) if (cal[k] !== r[k]) nearest.offsets.push(calStart + k);
    }
  }

  return {
    status: programOk === false ? 'modified' : 'cal_unknown',
    programOk,
    partial,
    signatures,
    match: exact || null,          // calibration d'usine reconnue mais programme patche
    nearest: nearest && { label: nearest.stock.label, engine: nearest.stock.engine, count: nearest.count, offsets: nearest.offsets },
  };
}

// --- Estimation quand la calibration n'est pas reconnue telle quelle ---
// On compare, en valeurs physiques et par nom de carto, les tables d'avance (ip_iga_*), de temps
// d'injection (ip_ti_*, ip_tib*) et de caracteristique injecteurs (t_ti_as_*) aux lectures d'usine
// du meme SW si on en a (refSw), sinon du 430069, en gardant la variante la plus ressemblante.
// Ce n'est qu'une ESTIMATION : une variante d'usine non repertoriee peut avoir des tables differentes.
const KEY_MAPS = /^(ip_iga_|t_ti_as|ip_ti_|ip_tib)/;
// Tables typiquement retouchees en prepa (injecteurs, carburant de base, avance, demarrage a froid).
const TUNE_MAPS = /^(t_ti_as_\d|ip_tib__|ip_iga_ron_(91|98)|ip_ti_cst__|ip_ti_tco_\d_pl_ivvt|ip_iga_tco_\d_pl_ivvt|ip_ti_pvs__)/;
const EST_REF_SW = '430069';

export async function estimateOrigin(bytes, def, refDef, refSw = EST_REF_SW) {
  const refs = await loadRefs();
  const ref = refs?.software?.[refSw];
  if (!ref) return null;
  const [calStart, calLen] = refs.calibration;
  const images = (await Promise.all(ref.stocks.map((s) => loadCal(s.cal)))).map((c) => {
    if (!c || c.length !== calLen) return null;
    const img = new Uint8Array(calStart + calLen);
    img.set(c, calStart);
    return img;
  });

  // Paires (carto du fichier, carto 430069) de meme nom et de meme taille.
  const pairs = [];
  for (const r of refDef.maps) {
    if (!KEY_MAPS.test(r.title) || !parseEquation(r.equation)) continue;
    const m = def.maps.find((x) => x.title === r.title);
    if (!m || m.rows * m.cols !== r.rows * r.cols || !parseEquation(m.equation)) continue;
    try { pairs.push({ title: r.title, units: r.units, values: readMap(bytes, m), ref: r }); } catch { /* adresse hors fichier */ }
  }
  if (!pairs.length) return null;

  let best = null;
  ref.stocks.forEach((stock, i) => {
    const img = images[i];
    if (!img) return;
    let same = 0;
    const diffs = [];
    for (const p of pairs) {
      const w = readMap(img, p.ref);
      const d = p.values.map((x, k) => x - w[k]).filter((x) => Math.abs(x) > 1e-6);
      if (!d.length) { same++; continue; }
      const up = d.filter((x) => x > 0).length;
      diffs.push({
        title: p.title, units: p.units, cells: d.length, total: w.length, up, down: d.length - up,
        mean: d.reduce((s, x) => s + x, 0) / d.length,
      });
    }
    if (!best || same > best.same) best = { label: stock.label, same, diffs };
  });
  if (!best) return null;

  const compared = pairs.length;
  const ratio = best.same / compared;
  // "Facon prepa" : table de prepa dont TOUTES les cases modifiees vont dans le meme sens.
  const tuneLike = best.diffs.filter((d) => TUNE_MAPS.test(d.title) && d.cells >= 3 && (d.up === d.cells || d.down === d.cells));
  let verdict;
  if (compared < 20 || ratio < 0.6) verdict = 'unclear';       // calibration trop differente (autre moteur, Alpina...)
  else if (tuneLike.length) verdict = 'likely_modified';
  else if (ratio >= 0.85) verdict = 'likely_stock';
  else verdict = 'unclear';
  return { verdict, refSw, nearest: best.label, same: best.same, compared, diffs: best.diffs, tuneLike: tuneLike.map((d) => d.title) };
}

// Noms des cartographies (def XDF) touchees par les octets differents ; "outside" = octets hors cartographie.
export function changedMaps(def, offsets) {
  const maps = def.maps
    .map((m) => ({ title: m.title, start: m.file_offset, end: m.file_offset + m.rows * m.cols * (m.bits / 8) }))
    .sort((a, b) => a.start - b.start);
  const titles = new Set();
  let outside = 0;
  for (const o of offsets) {
    let hit = false;
    for (const m of maps) {
      if (m.start > o) break;
      if (o < m.end) { titles.add(m.title); hit = true; }
    }
    if (!hit) outside++;
  }
  return { titles: [...titles], outside };
}
