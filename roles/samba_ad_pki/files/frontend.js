/* njs js_content handler. No fetch, headers-as-identity, body logging or secrets in URLs. */
function parseSign(text) {
    if (typeof text !== 'string' || text.length > 32768 ||
        !/^[\x09\x0a\x0d\x20-\x7e]*$/.test(text)) throw Error('invalid');
    let i = 0;
    const ws = () => { while (i < text.length && /[ \t\r\n]/.test(text[i])) i++; };
    const take = (c) => { ws(); if (text[i++] !== c) throw Error('invalid'); };
    function string() {
        ws();
        const start = i;
        if (text[i++] !== '"') throw Error('invalid');
        while (i < text.length) {
            const c = text[i++];
            if (c === '\\') { i++; continue; }
            if (c === '"') return JSON.parse(text.slice(start, i));
        }
        throw Error('invalid');
    }
    take('{');
    const obj = {};
    for (;;) {
        const key = string();
        if ((key !== 'csr' && key !== 'ott') || Object.prototype.hasOwnProperty.call(obj, key)) throw Error('invalid');
        take(':');
        obj[key] = string();
        ws();
        if (text[i] === '}') { i++; break; }
        take(',');
    }
    ws();
    if (i !== text.length || Object.keys(obj).length !== 2 ||
        typeof obj.csr !== 'string' || obj.csr.length > 16384 ||
        !/^-----BEGIN CERTIFICATE REQUEST-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE REQUEST-----\r?\n?$/.test(obj.csr) ||
        typeof obj.ott !== 'string' || obj.ott.length > 8192 ||
        !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(obj.ott)) throw Error('invalid');
    return obj;
}

function certificate(value) {
    return typeof value === 'string' && value.length <= 16384 &&
        /^-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\r?\n?$/.test(value);
}

async function sign(r) {
    r.headersOut['Content-Type'] = 'application/json';
    r.headersOut['Cache-Control'] = 'no-store';
    if (r.variables.request_uri !== '/1.0/sign') { r.return(404, '{"error":"not found"}'); return; }
    if (r.method !== 'POST') { r.return(405, '{"error":"method denied"}'); return; }
    const types = r.rawHeadersIn.filter(h => h[0].toLowerCase() === 'content-type');
    if (types.length !== 1 || types[0][1].toLowerCase() !== 'application/json') {
        r.return(415, '{"error":"content type denied"}'); return;
    }
    let body;
    try { body = JSON.stringify(parseSign(r.requestText)); }
    catch (_) { r.return(400, '{"error":"invalid request"}'); return; }
    try {
        // Upstream location is internal; it discards all incoming headers.
        const reply = await r.subrequest('/_s3_sign', {method: 'POST', body: body});
        if (reply.status !== 201) {
            const status = [400, 401, 403].indexOf(reply.status) >= 0 ? reply.status : 502;
            r.return(status, '{"error":"issuance denied"}'); return;
        }
        if (typeof reply.responseText !== 'string' || reply.responseText.length > 32768) throw Error('invalid');
        const result = JSON.parse(reply.responseText);
        if (!certificate(result.crt) || !Array.isArray(result.certChain) || result.certChain.length !== 2 ||
            result.certChain[0] !== result.crt || !result.certChain.every(certificate)) throw Error('invalid');
        // Return public certificate material only, never arbitrary upstream fields/errors.
        r.return(201, JSON.stringify({crt: result.crt, certChain: result.certChain}));
    } catch (_) {
        r.return(502, '{"error":"issuer unavailable"}');
    }
}

export default {sign};
