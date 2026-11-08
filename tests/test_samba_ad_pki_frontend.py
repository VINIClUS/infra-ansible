"""Run the production njs module in existing Node; no claim of native njs QA."""
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def test_frontend_never_forwards_unvalidated_or_ambiguous_requests():
    path = ROOT / "roles/samba_ad_pki/files/frontend.js"
    assert path.is_file(), "sign-only njs frontend missing"
    script = r'''
import {readFileSync} from 'node:fs';
import assert from 'node:assert/strict';
const source = readFileSync(process.argv[1]);
const mod = (await import('data:text/javascript;base64,' + source.toString('base64'))).default;
const csr = '-----BEGIN CERTIFICATE REQUEST-----\nQQ==\n-----END CERTIFICATE REQUEST-----\n';
const crt = '-----BEGIN CERTIFICATE-----\nQQ==\n-----END CERTIFICATE-----\n';
const body = JSON.stringify({csr, ott:'e30.e30.sig'});
let forwarded = [];
async function exercise(raw, options={}) {
  let result;
  const r = {method:'POST', variables:{request_uri:'/1.0/sign'},
    rawHeadersIn:[['Content-Type','application/json']], headersOut:{}, requestText:raw,
    return:(status,text)=>{result={status,text};},
    subrequest:async(uri,opts)=>{forwarded.push({uri,opts});return {
      status:201,responseText:JSON.stringify({crt,certChain:[crt,crt],ott:'MUST NOT ESCAPE'})};}};
  Object.assign(r,options);
  await mod.sign(r);
  return result;
}
assert.equal((await exercise(body)).status,201);
assert.equal(forwarded.length,1);
assert.equal(forwarded[0].uri,'/_s3_sign');
assert.deepEqual(JSON.parse(forwarded[0].opts.body),{csr,ott:'e30.e30.sig'});
const hostile = [
  body.replace('"ott":','"ott":"x","ott":'),
  body.replace('"ott":','"o\\u0074t":"x","ott":'),
  JSON.stringify({csr,ott:'e30.e30.sig',notAfter:'720h'}),
  JSON.stringify({csr,ott:'e30.e30.sig',templateData:{}}),
  JSON.stringify({csr,ott:'e30.e30.sig',nested:{x:1,x:2}}),
  body + ' garbage', '[1,2]', '{"csr":null,"ott":"e30.e30.sig"}',
  body.replace('QQ==','\ufffd'), ' '.repeat(32769),
  JSON.stringify({csr,ott:'e30.e30.sig\n'}), '{"__proto__":"x"}',
];
for (const value of hostile) {
  const before = forwarded.length;
  assert.equal((await exercise(value)).status,400);
  assert.equal(forwarded.length,before);
}
for (const uri of ['/1.0/sign?x=1','/1.0/%73ign','/a/../1.0/sign','/_s3_sign']) {
  const before=forwarded.length;
  assert.equal((await exercise(body,{variables:{request_uri:uri}})).status,404);
  assert.equal(forwarded.length,before);
}
assert.equal((await exercise(body,{method:'GET'})).status,405);
assert.equal((await exercise(body,{rawHeadersIn:[['Content-Type','text/plain']]})).status,415);
assert.equal((await exercise(body,{rawHeadersIn:[['Content-Type','application/json'],['content-type','application/json']]})).status,415);
for (const code of [400,401,403,500,302]) {
  const out = await exercise(body,{subrequest:async()=>({status:code,responseText:'SECRET TOKEN PRIVATE KEY'})});
  assert.ok(!out.text.includes('SECRET'));
  assert.ok([400,401,403,502].includes(out.status));
}
assert.equal((await exercise(body,{subrequest:async()=>{throw Error('SECRET')}})).status,502);
const ok = await exercise(body);
assert.ok(!ok.text.includes('MUST NOT ESCAPE'));
assert.deepEqual(Object.keys(JSON.parse(ok.text)).sort(),['certChain','crt']);
console.log('sign-only frontend cases passed (Node adapter; njs native unavailable)');
'''
    result = subprocess.run(["node", "--input-type=module", "-e", script, str(path)],
                            text=True, capture_output=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert "frontend cases passed" in result.stdout
