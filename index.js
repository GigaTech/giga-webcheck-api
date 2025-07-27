
const script_ver = "0.1.005"
const dtNow = Date.now()

const express = require('express');
const dns = require('dns').promises;
const https = require('https');
const http = require('http');
const tls = require('tls');
const url = require('url');

const app = express();
const port = process.env.PORT || 3000;



async function fetchSite(urlStr) {
  const parsedUrl = url.parse(urlStr);
  const isHttps = parsedUrl.protocol === 'https:';
  const hostname = parsedUrl.hostname;

  return new Promise((resolve) => {
    const start = Date.now();
    const lib = isHttps ? https : http;

    const req = lib.get(urlStr, (res) => {
      const time = Date.now() - start;
      res.resume();
      resolve({
        url: urlStr,
        statusCode: res.statusCode,
        responseTimeMs: time,
      });
    });

    req.on('error', (e) => {
      resolve({
        url: urlStr,
        error: e.message,
      });
    });

    req.setTimeout(10000, () => {
      req.destroy();
      resolve({
        url: urlStr,
        error: 'Timeout after 10s',
      });
    });
  });
}



async function getSSLInfo(hostname, port = 443) {
  return new Promise((resolve) => {
    const socket = tls.connect(
      port,
      hostname,
      { servername: hostname, rejectUnauthorized: false },
      () => {
        const cert = socket.getPeerCertificate();
        socket.end();
        resolve({
          subject: cert.subject,
          issuer: cert.issuer,
          valid_from: cert.valid_from,
          valid_to: cert.valid_to,
          days_until_expiry: Math.ceil((new Date(cert.valid_to) - Date.now()) / (1000 * 60 * 60 * 24)),
        });
      }
    );

    socket.on('error', (err) => {
      resolve({ error: err.message });
    });
  });
}



async function getDNSRecords1(hostname) {
  const result = {};

  try {
    result.A = await dns.resolve4(hostname);
  } catch (e) {
    result.A = [`Error: ${e.code}`];
  }

  try {
    result.AAAA = await dns.resolve6(hostname);
  } catch (e) {
    result.AAAA = [`Error: ${e.code}`];
  }

  try {
    result.CNAME = await dns.resolveCname(hostname);
  } catch (e) {
    result.CNAME = [`Error: ${e.code}`];
  }

  try {
    result.MX = await dns.resolveMx(hostname);
  } catch (e) {
    result.MX = [`Error: ${e.code}`];
  }

  try {
    result.TXT = await dns.resolveTxt(hostname);
  } catch (e) {
    result.TXT = [`Error: ${e.code}`];
  }

  try {
    result.NS = await dns.resolveNs(hostname);
  } catch (e) {
    result.NS = [`Error: ${e.code}`];
  }

  try {
    const ptrs = {};
    if (result.A && Array.isArray(result.A)) {
      for (const ip of result.A) {
        try {
          ptrs[ip] = await dns.reverse(ip);
        } catch (e) {
          ptrs[ip] = [`Reverse Error: ${e.code}`];
        }
      }
    }
    result.PTR = ptrs;
  } catch (e) {
    result.PTR = [`PTR Error: ${e.code}`];
  }

  return result;
}



async function getDNSRecords2(hostname) {
  const result = {};

  try {
    result.ALL = await dns.resolveAny(hostname);
  } catch (e) {
    result.ALL = [`Error: ${e.code}`];
  }

  return result;
}



app.get('/check', async (req, res) => {
	const url = req.query.url;
	if (!url) {
		return res.status(400).json({ error: 'Missing "url" query param' });
  }

  const urlToTest = url.startsWith('http') ? url : `https://${url}`;
  const hostname = url.parse(urlToTest).hostname;

  const [httpInfo, sslInfo, dnsInfo] = await Promise.all([
    fetchSite(urlToTest),
    getSSLInfo(hostname),
    getDNSRecords1(hostname),
    getDNSRecords2(hostname),
  ]);



  return res.json({

	version: script_ver,
    checked_at: dtNow,
    url: url,

    // HTTP: {
    //   HTTP: httpInfo,
    // },

    // SSL: {
    //   SSL: sslInfo,
    // },

    // DNS1: {
    //   DNS: dnsInfo1,
    // },

    // DNS2: {
    //   DNS: dnsInfo2,
    // }

  });



});



app.listen(port, () => {
  console.log(`Webcheck API listening on port ${port}`);
});
