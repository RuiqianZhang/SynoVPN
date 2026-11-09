// UI behavior checks: routing/role boundaries, pagination, and preserving policy drafts.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const html = fs.readFileSync('internal/web/ui.html', 'utf8');
const script = html.match(/<script[^>]*>([\s\S]*?)<\/script>/)[1];
const flush = async () => { for (let i=0;i<30;i++) await Promise.resolve(); };
function setup({admin=true,cgi=false,hash='#/admin/devices'}={}) {
 const nodes=new Map(),events={},calls=[];
 function node(id='') {
  const classes=new Set((html.match(new RegExp('id="'+id+'" class="([^"]+)"'))?.[1]||'').split(' '));
  const n={id,value:'',textContent:'',children:[],attributes:{},disabled:false,
   classList:{add:x=>classes.add(x),remove:x=>classes.delete(x),contains:x=>classes.has(x),toggle(x,on){if(on===undefined)on=!classes.has(x);on?classes.add(x):classes.delete(x)}},
   setAttribute(k,v){this.attributes[k]=v},getAttribute(k){return this.attributes[k]||null},removeAttribute(k){delete this.attributes[k]},
   append(...kids){this.children.push(...kids);if(id==='policyUser'&&!this.value)this.value=kids[0]?.value||''},
   replaceChildren(...kids){this.children=[...kids]},addEventListener(){},focus(){},querySelector(){return node()},
   get options(){return this.children}
  };return n;
 }
 function $(id){if(!nodes.has(id))nodes.set(id,node(id));return nodes.get(id)}
 const links=[...html.matchAll(/<a[^>]*href="(#\/[^"]+)"/g)].map(m=>{const n=node();n.attributes.href=m[1];return n});
 const location=new URL('https://nas.example:5001/'+(cgi?'webman/3rdparty/SynoVPN/app.cgi?SynoToken=test-token':'')+hash);
 const devices=Array.from({length:23},(_,i)=>({id:'d'+i,name:'Device '+i,owner:'owner'+i%3,platform:'windows',state:'active',applied:true,online:i%2===0,created:1,expires:2}));
 const document={getElementById:$,createElement:()=>node(),createTextNode:text=>({textContent:text}),querySelector:()=>node(),querySelectorAll:()=>links,body:node()};
 const ctx={URL,URLSearchParams,console,document,location,navigator:{userAgent:'test'},
  window:{addEventListener:(k,fn)=>events[k]=fn,scrollTo(){}},history:{replaceState(_s,_t,url){location.href=new URL(url,location).href}},
  setInterval(){},clearInterval(){},setTimeout(){},clearTimeout(){},AbortController,TypeError,Error,
  fetch:async(url,opts={})=>{calls.push({url:new URL(url),method:opts.method});const route=cgi?url.searchParams.get('route'):url.pathname;let data;
   switch(route){
    case '/api/me':data={is_admin:admin,user:'tester',domain:'vpn.example',routes:['192.168.10.0/24'],max_devices:5,device_days:90};break;
    case '/api/devices':case '/api/admin/devices':data={devices,gateway:true};break;
    case '/api/admin/policy-users':data={users:[{name:'tester',owner:'1000:tester'}]};break;
    case '/api/admin/user-routes':data={inherit:false,routes:['192.168.10.20/32'],applied:true};break;
    case '/api/admin/public-routes':data={routes:[],applied:true};break;
    default:throw Error('Unexpected route '+route);
   }return {ok:true,headers:{get:()=> 'application/json'},json:async()=>data};
  }};
 $('adminState').value='all';vm.runInNewContext(script,ctx);
 return {$,calls,links,location,async go(hash){location.hash=hash;await events.hashchange();await flush()}};
}
(async()=>{
 for(const cgi of [false,true]){
  const s=setup({cgi});await flush();
  assert.equal(s.$('breadcrumbPage').textContent,'设备管理');assert.equal(s.$('adminDevices').children.length,10);
  s.$('adminNext').onclick();assert.equal(s.$('adminDevices').children.length,10);
  s.$('adminNext').onclick();assert.equal(s.$('adminDevices').children.length,3);assert(s.$('adminNext').disabled);
  s.$('adminSearch').value='Device 22';s.$('adminSearch').oninput();assert.equal(s.$('adminDevices').children.length,1);assert(s.$('adminPagination').classList.contains('hidden'));
  await s.go('#/admin/users');s.$('userRoutes').value='8.8.8.8';s.$('userRoutes').oninput();
  await s.go('#/admin/routes');await s.go('#/admin/users');assert.equal(s.$('userRoutes').value,'8.8.8.8');assert.match(s.$('userRoutesStatus').textContent,/未保存/);
  assert.equal(s.calls.filter(c=>c.url.pathname.endsWith('/api/admin/user-routes')||c.url.searchParams.get('route')==='/api/admin/user-routes').length,1);
  assert(s.calls.every(c=>!c.url.hash));assert(s.calls.every(c=>c.method!=='POST'));
  if(cgi){assert(s.calls.every(c=>c.url.pathname.endsWith('app.cgi')));assert(s.calls.every(c=>!c.url.searchParams.has('SynoToken')))}
  await s.go('#/help');assert(!s.$('helpPage').classList.contains('hidden'));assert(s.$('adminDashboard').classList.contains('hidden'));
  await s.go('#/unknown');assert.equal(s.location.hash,'#/devices');
 }
 const ordinary=setup({admin:false});await flush();assert.equal(ordinary.location.hash,'#/devices');assert(ordinary.$('adminNav').classList.contains('hidden'));assert(!ordinary.calls.some(c=>c.url.pathname.startsWith('/api/admin/')));
 console.log('Navigation, CGI links, role guard, 23-device pagination/filtering and unsaved policy drafts passed.');
})().catch(e=>{console.error(e);process.exitCode=1});
