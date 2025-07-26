const express = require('express');
const https = require('https');
const http = require('http');
const tls = require('tls');
const dns = require('dns').promises;
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');

const app = express();

// Logging middleware
app.use(morgan(':method :url :status :res[content-length] - :response-time ms'));

// Rate limiting: max 100 requests per 15 minutes per IP
app.use(rateLimit({
	windowMs: 15 * 60 * 1000,
	max: 100,
	standardHeaders: 'draft-8',
	legacyHeaders: false
}));

async function checkSslExpiry(hostname) {
	return new Promise((resolve) => {
		const sock = tls.connect(443, hostname, { servername: hostname, rejectUnauthorized: false }, () => {
			const cert = sock.getPeerCertificate();
			sock.end();
			if (!cert.valid_to) return resolve({ validTo: null, daysRemaining: null });
			const validTo = new Date(cert.valid_to);
			const daysRemaining = Math.floor((validTo - Date.now()) / (1000 * 60 * 60 * 24));
			resolve({ validTo: validTo.toISOString(), daysRemaining });
		});
		sock.on('error', () => resolve({ validTo: null, daysRemaining: null }));
	});
}

async function resolveDnsRecords(hostname) {
	const res = {};
	try { res.A = await dns.resolve4(hostname); } catch (_) { res.A = []; }
	try { res.AAAA = await dns.resolve6(hostname); } catch (_) { res.AAAA = []; }
	try { res.CNAME = await dns.resolveCname(hostname); } catch (_) { res.CNAME = []; }
	try { res.MX = await dns.resolveMx(hostname); } catch (_) { res.MX = []; }
	try { res.TXT = await dns.resolveTxt(hostname); } catch (_) { res.TXT = []; }
	try { res.NS = await dns.resolveNs(hostname); } catch (_) { res.NS = []; }

	// PTR reverse DNS for each IP
	const ptrs = {};
	for (const ip of [...res.A, ...res.AAAA]) {
		try {
			const names = await dns.reverse(ip);
			ptrs[ip] = names;
		} catch (_) { ptrs[ip] = []; }
	}
	res.PTR = ptrs;

	// extract policy records
	const flatTxt = res.TXT.flat();
	res.SPF = flatTxt.filter(t => t.toLowerCase().includes('v=spf1'));
	res.DKIM = flatTxt.filter(t => t.toLowerCase().includes('dkim'));
	res.DMARC = flatTxt.filter(t => t.toLowerCase().includes('v=dmarc1'));
	
	return res;
}

app.get('/check', async (req, res) => {
	const { url } = req.query;
	if (!url) return res.status(400).json({ error: 'Missing url parameter' });

	const parsed = new URL(url);
	const mod = parsed.protocol === 'https:' ? https : http;
	const hostname = parsed.hostname;

	const t0 = Date.now();
	mod.get(url, async (resp) => {
		const t1 = Date.now();
		const ssl = parsed.protocol === 'https:' ? await checkSslExpiry(hostname) : null;
		const dnsRecords = await resolveDnsRecords(hostname);

		res.json({
			url,
			statusCode: resp.statusCode,
			responseTimeMs: t1 - t0,
			ssl,
			dns: dnsRecords
		});
	}).on('error', async (err) => {
		const dnsRecords = await resolveDnsRecords(hostname);
		res.status(500).json({ url, error: err.message, dns: dnsRecords });
	});
});

app.listen(3000, () => console.log('Check API listening on port 3000'));
