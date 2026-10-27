const BUCKET = "scripts";

module.exports = async (req, res) => {
  const id = String((req.query && req.query.id) || "");
  if (!/^[a-z0-9]{10}$/.test(id)) {
    return res.status(404).send("Not found");
  }

  const { SUPABASE_URL, SUPABASE_SERVICE_KEY } = process.env;
  const r = await fetch(`${SUPABASE_URL}/storage/v1/object/${BUCKET}/${id}.lua`, {
    headers: {
      Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
      apikey: SUPABASE_SERVICE_KEY,
    },
  });

  if (!r.ok) return res.status(404).send("Not found");

  const text = await r.text();
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.setHeader("Cache-Control", "public, max-age=60");
  res.setHeader("X-Content-Type-Options", "nosniff");
  return res.status(200).send(text);
};
