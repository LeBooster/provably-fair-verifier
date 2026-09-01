#!/usr/bin/env node
/**
 * Independent verifier of LeBooster draws. Replays pf-v1 and pf-v2.
 *
 * One single file, no dependency: only `node:crypto`, which provides SHA-256 and
 * HMAC-SHA-256. It can be read in full before being run, that is the point. The
 * program contacts no server and writes nothing: it reads a proof file, redoes the
 * computation, and prints every step.
 *
 * Usage :
 *   node verify-lebooster.mjs preuve.json
 *   node verify-lebooster.mjs preuve.json --json     (sortie machine)
 *   node verify-lebooster.mjs --self-test            (vecteurs de référence)
 *
 * Exit code: 0 if the proof is valid, 1 otherwise.
 *
 * This file is the literal transcription of the production algorithm
 * (`packages/shared/src/provably-fair` in the LeBooster repository). A test of the
 * repository replays the `kat.json` vectors through THIS file and compares against
 * the production engine: the two cannot diverge without breaking CI.
 */

import { createHash, createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

// ---------------------------------------------------------------------------
// 1. Primitives cryptographiques (PF §2.2, §2.3)
// ---------------------------------------------------------------------------

/** 2^32, upper bound of a 32-bit integer draw. */
const MAX_U32 = 4294967296;

const hexToBytes = (hex) => Buffer.from(hex, 'hex');
const bytesToHex = (bytes) => Buffer.from(bytes).toString('hex');

/** commit = hex(SHA-256(server_seed)), the commitment published BEFORE the opening. */
const computeCommit = (serverSeedHex) =>
  createHash('sha256').update(hexToBytes(serverSeedHex)).digest('hex');

/**
 * draw = HMAC-SHA-256(key = server_seed, message = "client_seed:nonce").
 *
 * The key is the server seed DECODED from hexadecimal (raw bytes). The client seed
 * is an opaque string used as-is, never re-encoded. The nonce is serialized in
 * decimal, separated by a colon.
 */
const computeDraw = (serverSeedHex, clientSeed, nonce) =>
  createHmac('sha256', hexToBytes(serverSeedHex)).update(`${clientSeed}:${nonce}`, 'utf8').digest();

/**
 * Deterministic re-expansion of the draw into independent streams:
 * stream(draw, label, i) = HMAC-SHA-256(key = draw, message = "label:i").
 * The draw digest acts as the key; `label` and `i` separate the usages.
 */
const streamBytes = (draw, label, i) =>
  createHmac('sha256', draw).update(`${label}:${i}`, 'utf8').digest();

/** Unsigned 32-bit integer, big-endian, read at the given offset. */
const u32BE = (bytes, offset = 0) =>
  ((bytes[offset] << 24) |
    (bytes[offset + 1] << 16) |
    (bytes[offset + 2] << 8) |
    bytes[offset + 3]) >>>
  0;

/** The first 32 bits mapped into [0, 1). */
const float01 = (bytes, offset = 0) => u32BE(bytes, offset) / MAX_U32;

/** hex(SHA-256(canonical serialization of the frozen pool)), rarity keys sorted. */
const poolDigest = (pools) => {
  const canonical = {};
  for (const rarity of Object.keys(pools).sort()) canonical[rarity] = pools[rarity];
  return createHash('sha256').update(JSON.stringify(canonical), 'utf8').digest('hex');
};

// ---------------------------------------------------------------------------
// 2. Rarity scale (PF-BAREME)
// ---------------------------------------------------------------------------

/** NFD -> diacritics stripped -> lowercase -> whitespace collapsed. */
const normalizeRarity = (rarity) =>
  rarity
    .normalize('NFD')
    .replace(new RegExp('[\\u0300-\\u036f]', 'g'), '')
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .trim();

/** Normalized alias -> rank. An unknown rarity is worth 0. */
const buildRankLookup = (rarityScale) => {
  const lookup = new Map();
  for (const entry of rarityScale) {
    for (const alias of entry.aliases) lookup.set(normalizeRarity(alias), entry.rank);
  }
  return lookup;
};

const rankOf = (rarity, lookup) => lookup.get(normalizeRarity(rarity)) ?? 0;

// ---------------------------------------------------------------------------
// 3. Anti-malchance (PF-06)
// ---------------------------------------------------------------------------

/**
 * Evaluated once per opening, on the highest-index slot.
 * It never downgrades a rarity: it resets the counter when the natural draw already
 * reaches the guarantee, or forces the guaranteed band at the threshold.
 */
const applyPity = (drawnRarity, pity, isPitySlot, lookup) => {
  if (!isPitySlot) return { rarity: drawnRarity, counterAfter: pity.counter, triggered: false };

  const drawnRank = rankOf(drawnRarity, lookup);
  const guaranteedRank = rankOf(pity.guaranteedRarity, lookup);

  if (drawnRank >= guaranteedRank)
    return { rarity: drawnRarity, counterAfter: 0, triggered: false };
  if (pity.counter + 1 >= pity.threshold)
    return { rarity: pity.guaranteedRarity, counterAfter: 0, triggered: true };
  return { rarity: drawnRarity, counterAfter: pity.counter + 1, triggered: false };
};

// ---------------------------------------------------------------------------
// 4. Full replay, step by step (PF §6.4)
// ---------------------------------------------------------------------------

/** Beyond that, we consider the sampling broken rather than looping forever. */
/** Versions que ce script sait rejouer. Rien ne doit en sortir : les tirages passés en dépendent. */
const SUPPORTED_ALGO_VERSIONS = ['pf-v1', 'pf-v2'];

const MAX_REJECTION_ATTEMPTS = 32;

function explain(proof, snapshots, claimedCards) {
  const steps = { commit: null, draw: null, pool: null, slots: [], mappingOk: null };

  const computedCommit = computeCommit(proof.serverSeed);
  steps.commit = {
    formula: 'commit = hex(SHA-256(server_seed))',
    computed: computedCommit,
    expected: proof.commit,
    ok: computedCommit === proof.commit,
  };

  const drawBytes = computeDraw(proof.serverSeed, proof.clientSeed, proof.nonce);
  const drawHex = bytesToHex(drawBytes);
  steps.draw = {
    formula: 'draw = hex(HMAC-SHA-256(clé = server_seed, message = "client_seed:nonce"))',
    message: `${proof.clientSeed}:${proof.nonce}`,
    computed: drawHex,
    expected: proof.draw ?? null,
    ok: proof.draw === undefined || proof.draw === null ? true : drawHex === proof.draw,
  };

  const { packRules, pity } = snapshots;

  if (proof.poolDigest) {
    const computed = poolDigest(packRules.pools);
    steps.pool = {
      formula: 'pool_digest = hex(SHA-256(pool ordonné, clés de rareté triées))',
      computed,
      expected: proof.poolDigest,
      ok: computed === proof.poolDigest,
    };
  }

  const lookup = buildRankLookup(packRules.rankBareme);
  // pf-v1 tire sans remise et consomme le pool ; pf-v2 tire avec remise et lit le pool figé.
  // Une preuve sans version est une preuve d'avant le versionnement, donc pf-v1.
  const withReplacement = (proof.algoVersion ?? 'pf-v1') === 'pf-v2';
  const remaining = {};
  if (!withReplacement)
    for (const rarity of Object.keys(packRules.pools))
      remaining[rarity] = [...packRules.pools[rarity]];

  // The EVALUATION order is ascending slot.index, distinct from the display order.
  const slots = [...packRules.slots].sort((a, b) => a.index - b.index);
  if (new Set(slots.map((s) => s.index)).size !== slots.length) {
    throw new Error('les slot.index doivent être uniques (PF-07)');
  }
  const highestIndex = slots.length > 0 ? slots[slots.length - 1].index : null;
  const claimedBySlot = new Map((claimedCards ?? []).map((c) => [c.slot, c]));
  let mappingMatches = (claimedCards ?? []).length === slots.length;

  slots.forEach((slot, evalPos) => {
    // 4.1 - Rarity substream: stream(draw, "rarity", evalPos).
    const rarityBytes = streamBytes(drawBytes, 'rarity', evalPos);
    const u32r = u32BE(rarityBytes, 0);
    const r = float01(rarityBytes, 0);

    // 4.2 - Cumulative distribution over the odds, in snapshot order.
    const totalWeight = slot.odds.reduce((s, o) => s + o.weight, 0);
    let running = 0;
    let drawnRarity = slot.odds[slot.odds.length - 1]?.rarity ?? '';
    let picked = false;
    const cdf = slot.odds.map((o) => {
      running += totalWeight > 0 ? o.weight / totalWeight : 0;
      const selected = !picked && r < running;
      if (selected) {
        drawnRarity = o.rarity;
        picked = true;
      }
      return { rarity: o.rarity, weight: o.weight, cumulative: running, selected };
    });

    // 4.3 - Pity, only on the highest-index slot.
    const isPitySlot = slot.index === highestIndex;
    const outcome = applyPity(drawnRarity, pity, isPitySlot, lookup);
    const finalRarity = outcome.rarity;

    // 4.4 - Tirage de la carte par rejection sampling. La borne de rejet se calcule sur la
    // taille du pool lu, qui diffère entre les deux versions : c'est ce qui les rend
    // incompatibles et impose de rejouer une preuve avec sa propre version.
    const poolBefore = withReplacement
      ? [...(packRules.pools[finalRarity] ?? [])]
      : [...(remaining[finalRarity] ?? [])];
    const n = poolBefore.length;
    if (n === 0)
      throw new Error(`pool épuisé pour la rareté « ${finalRarity} » (evalPos ${evalPos})`);
    const rejectionLimit = Math.floor(MAX_U32 / n) * n;
    const attempts = [];
    let chosenIndex = -1;
    for (let i = 0; i < MAX_REJECTION_ATTEMPTS; i++) {
      const v = u32BE(streamBytes(drawBytes, `card:${evalPos}`, i), 0);
      const accepted = v < rejectionLimit;
      attempts.push({ i, u32: v, accepted });
      if (accepted) {
        chosenIndex = v % n;
        break;
      }
    }
    if (chosenIndex < 0) throw new Error(`échantillonnage sans issue au slot ${slot.index}`);
    const cardId = poolBefore[chosenIndex];
    if (!withReplacement) remaining[finalRarity].splice(chosenIndex, 1);

    const claimed = claimedBySlot.get(slot.index) ?? null;
    const ok = claimed !== null && claimed.rarity === finalRarity && claimed.cardId === cardId;
    if (!ok) mappingMatches = false;

    steps.slots.push({
      slotIndex: slot.index,
      evalPos,
      rarity: {
        substream: `rarity:${evalPos}`,
        substreamHex: bytesToHex(rarityBytes),
        u32: u32r,
        r,
        totalWeight,
        cdf,
        drawnRarity,
      },
      pity: {
        isPitySlot,
        triggered: outcome.triggered,
        finalRarity,
        counterAfter: outcome.counterAfter,
      },
      card: { rarity: finalRarity, poolBefore, n, rejectionLimit, attempts, chosenIndex, cardId },
      claimedRarity: claimed?.rarity ?? null,
      claimedCardId: claimed?.cardId ?? null,
      ok,
    });
  });

  steps.mappingOk = (claimedCards ?? []).length === 0 ? null : mappingMatches;
  steps.allOk =
    steps.commit.ok && steps.draw.ok && (steps.pool?.ok ?? true) && steps.mappingOk !== false;
  return steps;
}

// ---------------------------------------------------------------------------
// 5. Affichage
// ---------------------------------------------------------------------------

const mark = (ok) => (ok ? '✓' : '✗');

function render(steps, proof) {
  const out = [];
  const p = (s = '') => out.push(s);
  // Dynamic numbering: the pool digest is only checked when the proof carries it.
  let stepNo = 0;
  const title = (label) => `ÉTAPE ${++stepNo} — ${label}`;

  p('══════════════════════════════════════════════════════════════════');
  p(`  VÉRIFICATION D'UN TIRAGE LEBOOSTER — algo ${proof.algoVersion ?? 'pf-v1'}`);
  p('══════════════════════════════════════════════════════════════════');
  p();
  p(title("L'engagement pris avant l'ouverture"));
  p(`  ${steps.commit.formula}`);
  p(`  graine serveur : ${proof.serverSeed}`);
  p(`  recalculé      : ${steps.commit.computed}`);
  p(`  publié         : ${steps.commit.expected}`);
  p(
    `  ${mark(steps.commit.ok)} ${steps.commit.ok ? "identiques : la graine n'a pas été changée après coup." : "DIFFÉRENTS : la graine révélée n'est pas celle engagée."}`
  );
  p();
  p(title('Le tirage'));
  p(`  ${steps.draw.formula}`);
  p(`  message   : "${steps.draw.message}"`);
  p(`  recalculé : ${steps.draw.computed}`);
  if (steps.draw.expected) p(`  publié    : ${steps.draw.expected}`);
  p(
    `  ${mark(steps.draw.ok)} ${steps.draw.ok ? 'le tirage dérive bien des deux graines et du nonce.' : 'DIFFÉRENT du tirage publié.'}`
  );

  if (steps.pool) {
    p();
    p(title('Le pool figé'));
    p(`  ${steps.pool.formula}`);
    p(`  recalculé : ${steps.pool.computed}`);
    p(`  publié    : ${steps.pool.expected}`);
    p(
      `  ${mark(steps.pool.ok)} ${steps.pool.ok ? 'le pool fourni est bien celui figé au tirage.' : "le pool ne correspond pas à l'empreinte publiée."}`
    );
  }

  p();
  p(title('Du tirage aux cartes, slot par slot'));
  p("  (ordre d'évaluation : slot.index croissant, sans remise)");

  for (const s of steps.slots) {
    p();
    p(
      `  ┌─ slot ${s.slotIndex} (position d'évaluation ${s.evalPos}) ${'─'.repeat(Math.max(0, 40 - String(s.slotIndex).length))}`
    );
    p(`  │ a. sous-flux « ${s.rarity.substream} » = HMAC-SHA-256(draw, "${s.rarity.substream}")`);
    p(`  │    ${s.rarity.substreamHex}`);
    p(`  │    4 premiers octets → u32 = ${s.rarity.u32}`);
    p(`  │    r = ${s.rarity.u32} / 2^32 = ${s.rarity.r.toFixed(10)}`);
    p('  │');
    p(`  │ b. bande de rareté (poids total ${s.rarity.totalWeight})`);
    for (const row of s.rarity.cdf) {
      p(
        `  │    ${row.selected ? '→' : ' '} ${row.rarity.padEnd(26)} poids ${String(row.weight).padStart(6)}  cumul < ${row.cumulative.toFixed(10)}${row.selected ? '  ← r tombe ici' : ''}`
      );
    }
    p(`  │    bande tirée : ${s.rarity.drawnRarity}`);
    p('  │');
    p(`  │ c. anti-malchance : ${s.pity.isPitySlot ? 'slot évalué' : 'non évalué sur ce slot'}`);
    if (s.pity.isPitySlot) {
      p(
        `  │    ${s.pity.triggered ? 'seuil atteint → bande garantie forcée' : 'pas de forçage, tirage naturel conservé'}`
      );
      p(`  │    compteur après cette ouverture : ${s.pity.counterAfter}`);
    }
    p(`  │    rareté retenue : ${s.pity.finalRarity}`);
    p('  │');
    p(
      `  │ d. carte tirée dans le pool restant de « ${s.card.rarity} » (${s.card.n} carte${s.card.n > 1 ? 's' : ''})`
    );
    p(
      `  │    borne anti-biais = floor(2^32 / ${s.card.n}) × ${s.card.n} = ${s.card.rejectionLimit}`
    );
    for (const a of s.card.attempts) {
      p(
        `  │    essai ${a.i} : HMAC(draw, "card:${s.evalPos}:${a.i}") → u32 = ${String(a.u32).padStart(10)} ${a.accepted ? '< borne → accepté' : '≥ borne → rejeté, on rejoue'}`
      );
    }
    p(
      `  │    index = ${s.card.attempts[s.card.attempts.length - 1].u32} mod ${s.card.n} = ${s.card.chosenIndex}`
    );
    p(`  │    pool avant : [${s.card.poolBefore.join(', ')}]`);
    p(`  │    carte      : ${s.card.cardId}`);
    if (s.claimedCardId !== null) {
      p('  │');
      p(`  │ ${mark(s.ok)} annoncé par LeBooster : ${s.claimedRarity} / ${s.claimedCardId}`);
    }
    p(`  └${'─'.repeat(58)}`);
  }

  p();
  p('══════════════════════════════════════════════════════════════════');
  p(`  ${mark(steps.commit.ok)} engagement    ${steps.commit.ok ? 'conforme' : 'NON CONFORME'}`);
  p(`  ${mark(steps.draw.ok)} tirage        ${steps.draw.ok ? 'conforme' : 'NON CONFORME'}`);
  if (steps.pool)
    p(`  ${mark(steps.pool.ok)} pool figé     ${steps.pool.ok ? 'conforme' : 'NON CONFORME'}`);
  if (steps.mappingOk !== null)
    p(
      `  ${mark(steps.mappingOk)} cartes        ${steps.mappingOk ? 'identiques à celles annoncées' : 'DIFFÉRENTES de celles annoncées'}`
    );
  p();
  p(`  ${steps.allOk ? '✓ TIRAGE VÉRIFIÉ' : '✗ VÉRIFICATION EN ÉCHEC'}`);
  p('══════════════════════════════════════════════════════════════════');
  return out.join('\n');
}

// ---------------------------------------------------------------------------
// 6. Self-test on the reference vectors
// ---------------------------------------------------------------------------

function selfTest() {
  const here = dirname(fileURLToPath(import.meta.url));
  const vectors = JSON.parse(readFileSync(join(here, 'kat.json'), 'utf8'));
  let failures = 0;

  for (const v of vectors) {
    const proof = {
      commit: v.expected.commit,
      serverSeed: v.input.serverSeedHex,
      clientSeed: v.input.clientSeed,
      nonce: v.input.nonce,
      draw: v.expected.draw,
    };
    const snapshots = { packRules: v.input.packRules, pity: v.input.pity };
    let ok = false;
    let detail = '';
    try {
      const steps = explain({ ...proof, algoVersion: v.algoVersion }, snapshots, v.expected.cards);
      ok = steps.allOk;
      if (!ok) detail = `commit=${steps.commit.ok} draw=${steps.draw.ok} cartes=${steps.mappingOk}`;
    } catch (e) {
      detail = e.message;
    }
    if (!ok) failures++;
    console.log(`  ${mark(ok)} ${v.name.padEnd(22)} ${detail}`);
  }

  console.log();
  if (failures === 0) {
    console.log(`✓ ${vectors.length} vecteurs de référence reproduits à l'identique.`);
    return 0;
  }
  console.log(`✗ ${failures} vecteur(s) en échec.`);
  return 1;
}

// ---------------------------------------------------------------------------
// 7. Entry point
// ---------------------------------------------------------------------------

const USAGE = `Vérificateur de tirage LeBooster (pf-v1, pf-v2)

  node verify-lebooster.mjs <preuve.json>     vérifie une preuve, détail complet
  node verify-lebooster.mjs <preuve.json> --json   même chose, en JSON
  node verify-lebooster.mjs --self-test       rejoue les vecteurs de référence

La preuve se télécharge depuis le détail de ton ouverture, sur lebooster.fr.
Aucune connexion réseau n'est faite : tout le calcul tourne sur ta machine.`;

function main(argv) {
  const args = argv.slice(2);
  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    console.log(USAGE);
    return args.length === 0 ? 1 : 0;
  }
  if (args.includes('--self-test')) return selfTest();

  const path = args.find((a) => !a.startsWith('--'));
  if (!path) {
    console.error('Aucun fichier de preuve fourni.\n');
    console.error(USAGE);
    return 1;
  }

  let payload;
  try {
    payload = JSON.parse(readFileSync(path, 'utf8'));
  } catch (e) {
    console.error(`Impossible de lire « ${path} » : ${e.message}`);
    return 1;
  }

  const { proof, snapshots, cards } = payload;
  if (!proof || !snapshots?.packRules || !snapshots?.pity) {
    console.error('Fichier incomplet : il faut { proof, snapshots: { packRules, pity }, cards }.');
    return 1;
  }
  if (payload.algoVersion && !SUPPORTED_ALGO_VERSIONS.includes(payload.algoVersion)) {
    console.error(
      `Ce vérificateur implémente ${SUPPORTED_ALGO_VERSIONS.join(', ')} ; ` +
        `la preuve annonce « ${payload.algoVersion} ».`
    );
    return 1;
  }

  let steps;
  try {
    // The version travels with the proof from here on, so the report names the algorithm that
    // was actually replayed rather than the one this build happens to prefer.
    proof.algoVersion = payload.algoVersion ?? 'pf-v1';
    steps = explain(proof, snapshots, cards ?? []);
  } catch (e) {
    console.error(`Rejeu impossible : ${e.message}`);
    return 1;
  }

  console.log(args.includes('--json') ? JSON.stringify(steps, null, 2) : render(steps, proof));
  return steps.allOk ? 0 : 1;
}

process.exit(main(process.argv));
