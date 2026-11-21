// Reconnaissance "lecture d'origine" : compare le fichier importe aux references d'usine (refs/).
// Tourne dans le navigateur, rien n'est envoye.
//
// - Zone 0x00000-0x0FFFF (boot, VIN, ISN) : propre a chaque voiture, jamais comparee.
// - Zone programme 0x10000-0x6FFFF : identique sur toutes les lectures d'usine d'un meme SW.
//   Si elle differe, le code a ete patche (EWS off, coupure allumage, boot...) -> fichier modifie.
// - Calibration 0x70000-0x7FFFF : doit etre identique a l'une des variantes d'usine connues.
//   Sinon : on cherche la variante la plus proche et on liste les cartographies qui different.
//
// Statuts :
//   stock       programme + calibration identiques a une reference d'usine.
//   modified    programme modifie (patch) : fichier deja retouche, a coup sur.
//   cal_unknown programme d'origine mais calibration absente de la base : soit modifiee,
//               soit variante d'usine non repertoriee. Les cartographies differentes sont listees.
//   no_ref      aucune reference pour ce SW : verification impossible.

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
  const programOk = ref.program_sha256.includes(programHash);

  // Patchs programme reconnus (ex. EWS / Immo OFF).
  const signatures = (ref.signatures || [])
    .filter((s) => s.bytes.every(([o, hex]) => hexOf(bytes, o, hex.length / 2) === hex))
    .map((s) => s.name);

  const exact = ref.stocks.find((s) => s.cal_sha256 === calHash);
  if (programOk && exact) return { status: 'stock', match: exact, programOk, signatures: [] };

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
    status: programOk ? 'cal_unknown' : 'modified',
    programOk,
    signatures,
    match: exact || null,          // calibration d'usine reconnue mais programme patche
    nearest: nearest && { label: nearest.stock.label, engine: nearest.stock.engine, count: nearest.count, offsets: nearest.offsets },
  };
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
