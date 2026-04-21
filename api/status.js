export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');

  if (req.method === 'OPTIONS') return res.status(200).end();

  return res.status(200).json({
    vt:           !!process.env.VT_API_KEY,
    abuseipdb:    !!process.env.ABUSEIPDB_API_KEY,
    otx:          !!process.env.OTX_API_KEY,
    abusech:      !!process.env.ABUSECH_AUTH_KEY,
    vt_paid:      process.env.VT_PAID === 'true',
    shodan:       true,
    mode:         'server',
  });
}
