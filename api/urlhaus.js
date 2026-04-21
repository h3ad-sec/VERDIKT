export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const { url: urlParam, sha256 } = req.query;
  if (!urlParam && !sha256) return res.status(400).json({ error: 'Missing url or sha256 parameter' });

  if (sha256 && !/^[a-fA-F0-9]{64}$/.test(sha256)) return res.status(400).json({ error: 'Invalid sha256 format' });

  try {
    const endpoint = sha256
      ? 'https://urlhaus-api.abuse.ch/v1/payload/'
      : 'https://urlhaus-api.abuse.ch/v1/url/';
    const body = new URLSearchParams(sha256
      ? { sha256_hash: sha256.toLowerCase() }
      : { url: urlParam });
    const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
    if (process.env.ABUSECH_AUTH_KEY) headers['Auth-Key'] = process.env.ABUSECH_AUTH_KEY;
    const upstream = await fetch(endpoint, {
      method: 'POST',
      body,
      headers,
    });
    const data = await upstream.json();
    return res.status(upstream.status).json(data);
  } catch (e) {
    return res.status(500).json({ error: 'Upstream request failed', detail: e.message });
  }
}
