/* ════════════════════════════════════════════════════════════════════
   STRATA COMMUNITY LAB — Prototype pollution through a deep merge (CWE-1321).
   A preferences endpoint deep-merges your JSON body into a fresh object.
   A key named __proto__ is not a slot on that object — it is the object
   every plain object inherits from. Write through it, and a property you
   never had appears on every object in the process, including the one
   the admin check reads.
   Engine: a symbolic model of the classic recursive merge, driven by real
   JSON.parse (which keeps "__proto__" as an own key). Nothing is merged
   into the page's own prototype — the effect is simulated.
   Ships with a defender edition.
   ════════════════════════════════════════════════════════════════════ */

const HOSTP = "shop.aperture.lab";

function ppIsObj(v){ return v !== null && typeof v === "object" && !Array.isArray(v); }

/* Read an own data property without ever touching the __proto__ accessor. */
function ppOwn(o, k){
  const d = Object.getOwnPropertyDescriptor(o, k);
  return d ? d.value : undefined;
}

/* Model merge(target = {}, source = body) the way the vulnerable code runs it,
   tracking WHERE each assignment lands instead of performing it:
     plain object  ["__proto__"]   → Object.prototype
     plain object  ["constructor"] → Object (inherited), whose ["prototype"] → Object.prototype
   opt.drop / opt.anyDepth model key-denylist patches; opt.frozen models
   Object.freeze(Object.prototype), under which writes to it are ignored. */
function ppMerge(raw, opt){
  opt = opt || {};
  const out = { valid:false, isObj:false, error:null, polluted:[], benign:[], path:null, stripped:[] };
  let body;
  try { body = JSON.parse(raw); }
  catch (_){ out.error = "Body isn't valid JSON."; return out; }
  out.valid = true;
  if (!ppIsObj(body)){ out.error = "The endpoint expects a JSON object."; return out; }
  out.isObj = true;
  const drop = opt.drop || [];
  let steps = 0;
  (function walk(loc, src, depth, route){
    if (depth > 16) return;
    for (const k of Object.keys(src)){
      if (++steps > 400) return;
      if (drop.includes(k) && (opt.anyDepth || depth === 0)){ out.stripped.push(k); continue; }
      const v = ppOwn(src, k);
      if (loc === "Object.prototype"){
        if (!opt.frozen){ out.polluted.push({ key:k, value:v }); out.path = out.path || route; }
        if (ppIsObj(v)) walk("Object.prototype." + k, v, depth + 1, route);
        continue;
      }
      let next = null, r = route;
      if (loc === "Object"){
        if (k === "prototype"){ next = "Object.prototype"; r = route || "constructor.prototype"; }
      } else if (k === "__proto__"){ next = "Object.prototype"; r = route || "__proto__"; }
      else if (k === "constructor"){ next = "Object"; }
      if (ppIsObj(v)) walk(next || (loc + "." + k), v, depth + 1, r);
      else if (loc === "config" && next === null) out.benign.push({ key:k, value:v });
    }
  })("config", body, 0, null);
  return out;
}

/* The app's gate is `if (user.isAdmin)` — JavaScript truthiness, so the
   string "false" passes it. role must equal "admin" exactly. */
function ppAdmin(r){
  return r.polluted.some(p =>
    (p.key === "isAdmin" && !!p.value) ||
    (p.key === "role" && p.value === "admin"));
}

function ppFmt(v){
  let s;
  try { s = JSON.stringify(v); } catch (_){ s = String(v); }
  return clip(s === undefined ? String(v) : s, 40);
}

function ppKeys(list){
  return list.map(p => `<b>${esc(p.key)}</b>`).join(", ");
}

/* Shared shape for every defender option: re-run the real engine unpatched
   and patched, then report honestly on this exact input. */
function ppApply(q, opt, at, holdWhy, failWhy){
  const base = ppMerge(String(q).trim());
  if (!base.isObj)
    return { blocked:false, at:null, why:"Not a JSON object — rejected with 400 before any merge, same as before the patch." };
  if (!base.polluted.length)
    return { blocked:false, at:null, why:"An ordinary preference — merged and saved exactly as before." };
  const pat = ppMerge(String(q).trim(), opt);
  if (!pat.polluted.length) return { blocked:true, at, why:holdWhy };
  return { blocked:false, at:5,
    why:`${failWhy} Still landed on <code>Object.prototype</code>: ${ppKeys(pat.polluted)} via <code>${esc(pat.path || "?")}</code>.` };
}

STRATA.registerLab({
  id: "prototype-pollution",
  code: "A08",
  cat: "Software & Data Integrity",
  title: "A preferences merge that writes to every object in the app",
  difficulty: "Practitioner",
  severity: ["HIGH", "8.1"],

  goal: "The settings page deep-merges your JSON into a fresh object. Make the app treat <b>every</b> visitor as an admin — without ever sending an <code>isAdmin</code> for your own account.",

  notes:`<code>merge(prefs, req.body)</code> walks every key you send. For a plain object, <code>target["__proto__"]</code> is not an empty slot — it is <code>Object.prototype</code>, the object every <code>{}</code> in the process inherits from. So <code>{"__proto__":{"isAdmin":true}}</code> writes <code>isAdmin</code> onto all of them, and a later <code>if (user.isAdmin)</code> on an unrelated object finds it by inheritance. <code>JSON.parse</code> keeps <code>"__proto__"</code> as an ordinary own key, which is why a JSON body is enough to carry it. Blocking the string <code>__proto__</code> is not the fix: <code>constructor.prototype</code> reaches the same object. <b>The fix:</b> skip <code>__proto__</code>, <code>constructor</code> and <code>prototype</code> at every depth of the merge — or merge into <code>Object.create(null)</code> / a <code>Map</code>, and <code>Object.freeze(Object.prototype)</code> at startup as a backstop.`,

  layers: [
    { code:"L0", title:"Surface",   meta:"the settings page" },
    { code:"L1", title:"Client",    meta:"fetch PUT" },
    { code:"L2", title:"Request",   meta:"PUT /api/preferences" },
    { code:"L3", title:"Edge",      meta:"reverse proxy" },
    { code:"L4", title:"Server",    meta:"server.js" },
    { code:"L5", title:"Prototype", meta:"where the write lands" },
    { code:"L6", title:"Objects",   meta:"who inherits it" }
  ],
  boundary: 4,
  boundaryLabel: "The merge",
  boundaryTone: "breach",

  wire: { type:"json-body",
    build: q => `PUT /api/preferences HTTP/1.1\nHost: ${HOSTP}\nContent-Type: application/json\n\n${String(q)}\n`,
    parse: raw => {
      const lines = String(raw).replace(/\r/g, "").split("\n");
      const blank = lines.findIndex(l => l.trim() === "");
      if (blank < 0) return { error:"No blank line — the JSON body goes after the headers." };
      return { q: lines.slice(blank + 1).join("\n").replace(/\n+$/, "") };
    }
  },
  consoleLabel: "Request bodies",
  defaultQ: '{"theme":"dark"}',

  presets: [
    { q:'{"theme":"dark"}',                               label:"Honest preference" },
    { q:'{"theme":"light","fontSize":14}',                label:"Two preferences" },
    { q:'{"theme":"dark",}',                              label:"Malformed JSON" },
    { q:'{"__proto__":{"polluted":"yes"}}',               label:"Reach the prototype", spoiler:true },
    { q:'{"__proto__":{"isAdmin":true}}',                 label:"Everyone is admin",   spoiler:true },
    { q:'{"constructor":{"prototype":{"isAdmin":true}}}', label:"The other door",      spoiler:true }
  ],

  analyze(q){
    const typed = String(q);          // the live box echoes your bytes exactly
    const val = typed.trim();
    const r = ppMerge(val);
    const admin = ppAdmin(r);
    const adminVia = r.polluted.find(p => (p.key === "isAdmin" && !!p.value) || (p.key === "role" && p.value === "admin")) || null;
    return {
      typed, val,
      valid: r.valid, isObj: r.isObj, error: r.error,
      polluted: r.polluted, benign: r.benign, path: r.path,
      reached: r.polluted.length > 0,
      admin, adminVia, solved: admin
    };
  },
  solved: a => a.solved,

  layerState(i, a){
    if (!a.isObj) return ["present","present","present","present","present","absent","absent"][i];
    return ["present","present","present","present","present",
            a.reached ? "promoted" : "present",
            a.admin ? "boundary" : a.reached ? "promoted" : "clean"][i];
  },

  render: {
    0: a => {
      let panel;
      if (!a.isObj)
        panel = `<div class="loginerr">400 Bad Request — ${esc(a.error || "")}</div>`;
      else if (a.admin)
        panel = `<div class="ownerbad">⚠ Saved. The navigation now shows an <b>Admin</b> panel — for you, and for every visitor served by this process. Nobody granted it.</div>`;
      else if (a.reached)
        panel = `<div class="ownerbad">⚠ Saved — and every object in the server now has ${ppKeys(a.polluted)}. Nothing on the page reads ${a.polluted.length === 1 ? "it" : "them"} yet.</div>`;
      else if (a.benign.length)
        panel = `<div class="ownerok">✓ Preferences saved: ${a.benign.map(p => `<b>${esc(p.key)}</b> = ${esc(ppFmt(p.value))}`).join(", ")}.</div>`;
      else
        panel = `<div class="loginerr">Nothing to save — that object has no preferences in it.</div>`;
      const body = `<h1 class="s-h">Preferences</h1>
        <p class="s-sub">signed in as <b>guest</b> · settings are saved as JSON</p>
        ${field("preferences", a.typed, "Save", '{"theme":"dark"}')}
        <div style="margin-top:12px">${panel}</div>`;
      return `<div class="applayer">${siteFrame({ path:"/settings", search:false, body })}</div>`;
    },

    1: a => `<pre class="src">${codeLines([
        { t:`<span class="kw">await</span> fetch(<span class="str">"/api/preferences"</span>, {` },
        { t:`  method: <span class="str">"PUT"</span>,` },
        { t:`  headers: { <span class="str">"Content-Type"</span>: <span class="str">"application/json"</span> },` },
        { t:`  body: ${taint(clip(a.val, 60))}`, hot:true },
        { t:`});` }
      ])}</pre>${note("", "Layer 1 · the form sends what you typed",
        "The settings box is the request body. The client has no opinion about which keys an object may have — neither does JSON.")}`,

    2: a => `<pre class="src">${codeLines([
        { t:`<span class="kw">PUT</span> /api/preferences <span class="kw">HTTP/1.1</span>` },
        { t:`<span class="kw">Host:</span> ${HOSTP}` },
        { t:`<span class="kw">Content-Type:</span> application/json` },
        { t:`` },
        { t:taint(clip(a.val, 80)), hot:true }
      ])}</pre>${note("", "Layer 2 · a legal body",
        a.isObj
          ? "Well-formed JSON. <code>\"__proto__\"</code> is as valid a key as <code>\"theme\"</code> — the JSON grammar has no reserved words for object keys."
          : "The body doesn't parse as a JSON object, so the server will reject it before the merge runs.")}`,

    3: a => note("", "Layer 3 · nothing to see",
      "The proxy forwards a small, well-formed JSON body to an authenticated endpoint. A rule that greps bodies for <code>__proto__</code> is exactly the blocklist the defender edition takes apart: <code>constructor.prototype</code> never spells it."),

    4: a => `<pre class="src">${codeLines([
        { t:`app.put(<span class="str">"/api/preferences"</span>, (req, res) => {` },
        { t:`  <span class="kw">const</span> prefs = {};` },
        { t:`  merge(prefs, req.body);`, hot:true },
        { t:`  savePrefs(req.user, prefs); res.sendStatus(<span class="str">204</span>);` },
        { t:`});` },
        { t:`` },
        { t:`<span class="kw">function</span> merge(target, source) {` },
        { t:`  <span class="kw">for</span> (<span class="kw">const</span> key <span class="kw">of</span> Object.keys(source)) {` },
        { t:`    <span class="kw">if</span> (isObject(source[key])) {` },
        { t:`      <span class="kw">if</span> (!target[key]) target[key] = {};` },
        { t:`      merge(target[key], source[key]);   <span class="cm">// target["__proto__"] is Object.prototype</span>`, hot:true },
        { t:`    } <span class="kw">else</span> target[key] = source[key];`, hot:a.reached },
        { t:`  }` },
        { t:`}` },
        { t:`<span class="cm">// fix: if (key === "__proto__" || key === "constructor" || key === "prototype") continue;</span>` }
      ])}</pre>${note("warn", "Layer 4 · a key is not always a slot",
        "<code>target[key]</code> reads through the prototype chain. For most keys that finds nothing and a fresh <code>{}</code> is created; for <code>__proto__</code> it finds the one object every plain object shares, and the recursion writes straight into it.")}`,

    5: a => explain("Where did each write land?",
        a.reached
          ? `The merge followed <code>${esc(a.path || "")}</code> out of your object and assigned onto <code>Object.prototype</code>. Your preferences object is untouched — the damage is on the object it inherits from.`
          : "Every key you sent became an own property of your fresh <code>prefs</code> object. That is the whole intended behavior of the endpoint.")
      + kv([
          ["Parsed as", a.isObj ? "a JSON object" : esc(a.error || "—"), a.isObj ? "" : "bad"],
          ["Route out", a.path ? `<span class="mono">${esc(a.path)}</span>` : "none", a.reached ? "bad" : ""],
          ["Your own keys", a.benign.length ? a.benign.map(p => esc(p.key)).join(", ") : "—", ""],
          ...a.polluted.slice(0, 5).map(p => [
            `Object.prototype.${esc(clip(p.key, 18))}`, taint(ppFmt(p.value)), "hot"]),
          ["Object.prototype", a.reached ? `<b style="color:var(--breach)">modified</b>` : "pristine", a.reached ? "bad" : "good"]
        ]),

    6: a => {
      const inh = a.polluted.find(p => p.key === "isAdmin");
      const role = a.polluted.find(p => p.key === "role");
      const src = `<pre class="src">${codeLines([
          { t:`<span class="cm">// middleware.js — runs on every request, for every visitor</span>` },
          { t:`<span class="kw">const</span> user = { name: <span class="str">"guest"</span> };   <span class="cm">// no isAdmin of its own</span>` },
          { t:`<span class="kw">if</span> (user.isAdmin || user.role === <span class="str">"admin"</span>) showAdminPanel();`, hot:true }
        ])}</pre>`;
      const rows = kv([
        ["user has own isAdmin", "no", ""],
        ["user.isAdmin (inherited)", inh ? taint(ppFmt(inh.value)) : "undefined", inh ? "hot" : ""],
        ["user.role (inherited)", role ? taint(ppFmt(role.value)) : "undefined", role ? "hot" : ""],
        ["Admin panel", a.admin ? "<b>shown to everyone</b>" : "hidden", a.admin ? "bad" : "good"]
      ]);
      if (a.admin) return src + rows + note("warn", "Layer 6 · the check read a property nobody set",
        `<code>user</code> is a different object from your preferences, built on a different request. It has no <code>${esc(a.adminVia ? a.adminVia.key : "isAdmin")}</code> of its own, so the lookup walked up to <code>Object.prototype</code> and found yours.${inh && typeof inh.value === "string" ? " Truthiness did the rest — any non-empty string passes <code>if</code>, including <code>\"false\"</code>." : ""}`);
      if (a.reached) return src + rows + note("", "Layer 6 · polluted, not yet exploited",
        "Every object in the process now inherits your keys. The pollution is real; the impact depends on finding a property some check trusts. Look at the line above.");
      return src + rows + note("", "Layer 6 · the baseline",
        "The guest object has no <code>isAdmin</code>, and neither does anything it inherits from. The panel stays hidden. This is what you are about to change.");
    }
  },

  trace(a){
    const S = i => this.layerState(i, a);
    return [
      { h:"L0 · Surface",   state:S(0), b:`Body <em>${esc(clip(a.val, 28))}</em>.` },
      { h:"L1 · Client",    state:S(1), b:"Sent as a JSON body." },
      { h:"L2 · Request",   state:S(2), b:a.isObj ? "Valid JSON object." : "Not a JSON object." },
      { h:"L3 · Edge",      state:S(3), b:"Forwarded untouched." },
      { h:"L4 · Server",    state:S(4), b:a.isObj ? "merge(prefs, req.body)." : "400 before the merge." },
      { h:"L5 · Prototype", state:S(5), b:a.reached ? `<strong>Wrote to Object.prototype via ${esc(a.path || "")}.</strong>` : "Writes stayed on your object." },
      { h:"L6 · Objects",   state:S(6), b:a.admin ? "<strong>Every user is admin.</strong>" : a.reached ? "Inherited everywhere, unused." : "Nothing inherited." }
    ];
  },

  verdict(a){
    return [
      ["Body", a.isObj ? "JSON object" : "rejected", a.isObj ? "" : "bad"],
      ["Object.prototype", a.reached ? `polluted (${a.polluted.length})` : "pristine", a.reached ? "bad" : ""],
      ["Admin gate", a.admin ? "open for everyone" : "closed", a.admin ? "bad" : ""],
      ["Lab", a.solved ? "Solved" : "Not solved", a.solved ? "good" : ""]
    ];
  },

  challenge: { steps: [
    { id:"honest", label:"Save an honest preference",
      test: a => a.isObj && !a.reached && a.benign.length > 0,
      hints:["The endpoint takes a JSON object of settings — send one."],
      reveal:'{"theme":"dark"}' },
    { id:"reach", label:"Write to Object.prototype",
      test: a => a.reached,
      hints:["Watch Layer 4: target[key] is read before it is written. Which key reads something that already exists on every object?",
             "Every plain object has a __proto__ — and JSON.parse keeps it as an ordinary key.",
             "Nest any property under a top-level \"__proto__\" key."],
      reveal:'{"__proto__":{"polluted":"yes"}}' },
    { id:"escalate", label:"Open the admin panel for everyone",
      test: a => a.admin,
      hints:["Layer 6 shows the check the app trusts — and the object it runs on has no such property of its own.",
             "Pollute the exact property that check reads, with a value that passes it.",
             "Put isAdmin: true on the prototype."],
      reveal:'{"__proto__":{"isAdmin":true}}' }
  ]},

  card: {
    sig: ["a","a","a","a","a","x","a"],
    blurb:"A preferences endpoint deep-merges your JSON. One key isn't a slot — it's the object every object inherits from, and the admin check reads it too."
  },

  defense: {
    blurb:"The attack never touches the admin check — it changes what every object inherits. Patch the merge so no key can walk out of the object it was sent for, and watch the obvious blocklist fall to <code>constructor.prototype</code>.",
    vectors: [
      { q:'{"__proto__":{"isAdmin":true}}',                 label:"top-level __proto__" },
      { q:'{"prefs":{"__proto__":{"isAdmin":true}}}',       label:"nested __proto__" },
      { q:'{"constructor":{"prototype":{"isAdmin":true}}}', label:"constructor.prototype" }
    ],
    options: [
      { id:"reject-top-proto", label:"Reject bodies with a top-level __proto__ key",
        code:'if (Object.hasOwn(req.body, "__proto__")) return res.sendStatus(400);',
        apply(q){ return ppApply(q, { drop:["__proto__"], anyDepth:false }, 4,
          "The only route in this body was a top-level <code>__proto__</code>, and it was rejected.",
          "The check looks at one key, at one depth. The merge recurses; the attacker nests."); } },

      { id:"strip-proto", label:"Strip __proto__ keys at every depth",
        code:'if (key === "__proto__") continue;   // inside merge()',
        apply(q){ return ppApply(q, { drop:["__proto__"], anyDepth:true }, 4,
          "Every <code>__proto__</code> key was skipped inside the merge, at every depth.",
          "Closer — but <code>__proto__</code> is one of two doors. <code>target.constructor.prototype</code> is the same object and never spells the blocked word."); } },

      { id:"skip-all", label:"Skip __proto__, constructor and prototype in merge()",
        code:'if (key === "__proto__" || key === "constructor" || key === "prototype") continue;',
        apply(q){ return ppApply(q, { drop:["__proto__","constructor","prototype"], anyDepth:true }, 4,
          "The merge refuses every key that can reach a prototype, at every depth. Ordinary preferences merge exactly as before. (Merging into <code>Object.create(null)</code> or a <code>Map</code> removes the chain entirely — the stronger form of the same idea.)",
          "A key-level denylist must cover all three names at every depth."); } },

      { id:"freeze", label:"Object.freeze(Object.prototype) at startup",
        code:"Object.freeze(Object.prototype);   // first line of server.js",
        apply(q){ return ppApply(q, { frozen:true }, 5,
          "The write reached <code>Object.prototype</code> and bounced: a frozen object ignores new properties (and throws under strict mode). Honest traffic never writes there, so nothing else changes. (Its real-world caveat: an old dependency that patches built-ins will break at boot — which is how you find it.)",
          "Freezing only protects what it freezes."); } },

      { id:"validate-types", label:"Validate that theme and fontSize have the right types",
        code:'if (Object.hasOwn(body, "theme") && typeof body.theme !== "string") return res.sendStatus(400);',
        apply(q){
          const base = ppMerge(String(q).trim());
          if (!base.isObj) return { blocked:false, at:null, why:"Not a JSON object — rejected with 400, same as before the patch." };
          if (!base.polluted.length) return { blocked:false, at:null, why:"An ordinary preference — validated, merged and saved." };
          return { blocked:false, at:5, why:`Schema checks on the keys you expect say nothing about the keys you don't. The merge still walked ${ppKeys(base.polluted)} onto <code>Object.prototype</code> via <code>${esc(base.path || "?")}</code>.` };
        } }
    ]
  }
});
