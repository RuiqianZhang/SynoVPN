const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const html = fs.readFileSync('internal/web/ui.html', 'utf8');
const script = html.match(/<script[^>]*>([\s\S]*?)<\/script>/)[1];
function setup(agent, fetch) {
 const nodes = new Map(), events = {}, timers = new Map();
 let serial = 0, revoked = [];
 function element(id) {
  if (!nodes.has(id)) nodes.set(id, { textContent:'', value:'', disabled:false,
   classList:{add(){},remove(){},toggle(){}}, addEventListener(){},
   removeAttribute(key){delete this[key]}, querySelector(){return element(id+'-button')} });
  return nodes.get(id);
 }
 class LocalURL extends URL {
  static createObjectURL(blob){assert.equal(blob.size,3);return 'blob:local-config'}
  static revokeObjectURL(url){revoked.push(url)}
 }
 const ctx={URL:LocalURL,URLSearchParams,AbortController,TypeError,Error,console,
  navigator:{userAgent:agent},location:{origin:'https://192.168.10.10:5001',host:'192.168.10.10:5001',href:'https://192.168.10.10:5001/webman/3rdparty/SynoVPN/app.cgi#enroll=phone-token'},
  history:{replaceState(){}},window:{addEventListener:(name,fn)=>events[name]=fn},
  document:{getElementById:element,querySelector:()=>element('header')},fetch,
  setTimeout(fn,ms){const id=++serial;timers.set(id,{fn,ms});return id},clearTimeout:id=>timers.delete(id)};
 vm.runInNewContext(script,ctx);
 return {nodes,events,timers,revoked,element};
}
(async()=>{
 let calls=0;
 const s=setup('Mozilla Android',async(url,options)=>{
  calls++;assert.equal(url.origin,'https://192.168.10.10:5001');assert.equal(url.searchParams.get('route'),'/api/enroll/claim');
  assert.equal(url.hash,'');assert.equal(options.method,'POST');assert.equal(options.body.get('claim'),'phone-token');assert.equal(options.redirect,'error');
  return {ok:true,headers:new Headers({'Content-Type':'application/zip','Content-Disposition':'attachment; filename="SynoVPN-device.zip"'}),blob:async()=>new Blob(['zip'])};
 });
 let prevented=false;
 await s.element('claimForm').onsubmit({preventDefault(){prevented=true}});
 assert(prevented);assert.equal(calls,1);assert.equal(s.element('claimSave').href,'blob:local-config');assert.equal(s.element('claimSave').download,'SynoVPN-device.zip');
 assert.equal(s.element('claimToken').value,'');assert.equal(s.element('claimForm-button').disabled,true);
 await s.element('claimForm').onsubmit({preventDefault(){}});assert.equal(calls,1);
 assert.equal(s.timers.size,1);assert.equal([...s.timers.values()][0].ms,300000);
 s.events.pagehide();assert.deepEqual(s.revoked,['blob:local-config']);assert.equal(s.element('claimSave').href,undefined);
 const bad=setup('Android',async()=>({ok:true,headers:new Headers({'Content-Type':'text/html'})}));
 await bad.element('claimForm').onsubmit({preventDefault(){}});assert(bad.element('claimError').textContent.includes('未返回配置包'));assert.equal(bad.element('claimSave').href,undefined);assert.equal(bad.timers.size,0);
 const network=setup('Android',async()=>{throw new TypeError('network')});
 await network.element('claimForm').onsubmit({preventDefault(){}});assert(network.element('claimError').textContent.includes('HTTPS'));assert.equal(network.element('claimSave').href,undefined);
 const ios=setup('iPhone Safari',()=>{throw Error('unexpected fetch')});assert.equal(ios.element('claimForm').onsubmit,undefined);assert.equal(ios.element('claimForm').action.searchParams.get('route'),'/api/enroll/claim');
 console.log('Android local-save flow, single-use request, cleanup, MIME/network errors and iOS native form passed.');
})().catch(error=>{console.error(error);process.exitCode=1});
