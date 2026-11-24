#!/usr/bin/env node
/*
 * Regenerates public/vendor/emoji.json from the latest `unicode-emoji-json` data.
 *   npm run update-emoji
 * Every emoji keeps its Unicode Emoji version, so the app can choose (Settings -> Look -> Emoji)
 * how new the emoji in the picker may be. No app code changes are needed for new emoji.
 */
'use strict';
const fs = require('fs');
const path = require('path');
let src;
try { src = require.resolve('unicode-emoji-json/data-by-group.json'); }
catch { console.error('Run: npm i --no-save unicode-emoji-json@latest   (npm run update-emoji does this for you)'); process.exit(1); }
const groups = JSON.parse(fs.readFileSync(src, 'utf8'));
const out = groups.map((g) => [g.name, g.emojis.map((e) => [e.emoji, e.name, e.skin_tone_support ? 1 : 0, +e.emoji_version])]);
const file = path.join(__dirname, '..', 'public', 'vendor', 'emoji.json');
fs.writeFileSync(file, JSON.stringify(out));
const all = out.flatMap((g) => g[1]);
const max = Math.max(...all.map((e) => e[3]));
console.log(`emoji.json: ${all.length} emoji, newest Emoji ${max.toFixed(1)} -> ${path.relative(process.cwd(), file)}`);
