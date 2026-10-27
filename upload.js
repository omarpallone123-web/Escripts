const crypto = require("crypto");

const BUCKET = "scripts";
const ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789";

function makeId(len = 10) {
  const bytes = crypto.randomBytes(len);
  let out = "";
  for (let i = 0; i < len; i++) out += ALPHABET[bytes[i] % ALPHABET.length];
  return out;
}

function sameSecret(a, b) {
  const ha = crypto.createHash("sha256").update(String(a)).digest();
  const hb = crypto.createHash("sha256").update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

module.exports = async (req, res) => {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Metodo non consentito" });
  }

  const { SUPABASE_URL, SUPABASE_SERVICE_KEY, UPLOAD_PASSWORD } = process.env;
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY || !UPLOAD_PASSWORD) {
    return res.status(500).json({ error: "Variabili ambiente mancanti su Vercel" });
  }

  const body = req.body || {};
  if (!sameSecret(body.password || "", UPLOAD_PASSWORD)) {
    return res.status(401).json({ error: "Password errata" });
  }

  const content = typeof body.content === "string" ? body.content : "";
  if (!content.trim()) {
    return res.status(400).json({ error: "Il file e vuoto" });
  }
  if (Buffer.byteLength(content, "utf8") > 3 * 1024 * 1024) {
    return res.status(413).json({ error: "File troppo grande (max 3 MB)" });
  }

  const id = makeId();
  const r = await fetch(`${SUPABASE_URL}/storage/v1/object/${BUCKET}/${id}.lua`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
      apikey: SUPABASE_SERVICE_KEY,
      "Content-Type": "text/plain; charset=utf-8",
      "x-upsert": "false",
    },
    body: content,
  });

  if (!r.ok) {
    const detail = await r.text().catch(() => "");
    return res.status(502).json({ error: "Errore Supabase: " + detail.slice(0, 200) });
  }

  return res.status(200).json({ id });
};
