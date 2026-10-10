'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');

class Element {
 constructor(tag='div'){this.tagName=tag;this.children=[];this.dataset={};this.handlers={};this.attributes={};this.value='';this.hidden=false;this.disabled=false;this.className='';this._text='';this.classList={toggle(){}};this.options=[];}
 set textContent(v){this._text=String(v);this.children=[];}
 get textContent(){return this._text+this.children.map(c=>c.textContent).join('');}
 set innerHTML(v){throw new Error('unsafe innerHTML assignment');}
 set outerHTML(v){throw new Error('unsafe outerHTML assignment');}
 setAttribute(k,v){if(k.startsWith('on'))throw new Error('inline event handler');this.attributes[k]=String(v);}
 addEventListener(k,v){this.handlers[k]=v;}
 append(...nodes){this.children.push(...nodes);}
 replaceChildren(...nodes){this._text='';this.children=nodes;}
 querySelector(sel){return this.querySelectorAll(sel)[0]||null;}
 querySelectorAll(sel){return this.children.flatMap(c=>[...(c.tagName===sel?[c]:[]),...c.querySelectorAll(sel)]);}
 remove(){}
 click(){return this.handlers.click?.({preventDefault(){}});}
}
function app(){
 const els=new Map(),get=id=>{if(!els.has(id))els.set(id,new Element());return els.get(id)};
 for(const filter of ['all','res','pure','chatgpt','claude']){const b=new Element('button');b.dataset.filter=filter;get('filters').append(b)}
 get('concurrency').value='8';const doc={getElementById:get,createElement:tag=>new Element(tag),documentElement:new Element('html'),body:new Element('body')};
 const requests=[],streams=[],timers=new Map();let next=0;
 const ctx=vm.createContext({document:doc,localStorage:{getItem(){return null},setItem(){},removeItem(){}},navigator:{clipboard:{writeText:async()=>{}}},URL,Date,Map,JSON,Number,String,Error,console,
 requestAnimationFrame(fn){timers.set(++next,fn);return next},setInterval(fn){timers.set(++next,fn);return next},clearInterval(id){timers.delete(id)},setTimeout,
 fetch:async(url,options)=>{requests.push({url,options});return {status:200,ok:true,json:async()=>({tasks:[]})}},EventSource:class{constructor(url){this.url=url;streams.push(this)}close(){this.closed=true}}});
 const source=fs.readFileSync(path.join(__dirname,'../dist/app.js'),'utf8').replace(/initialize\(\);\s*$/,'');vm.runInContext(source,ctx);
 return {ctx,els,get,doc,requests,streams,run:code=>vm.runInContext(code,ctx),flush(){for(const [id,fn]of timers){timers.delete(id);fn()}}};
}
test('all external values render as inert text and controls use listeners',()=>{
 const a=app();a.ctx.fixture={node_id:'x',node_name:'<img src=x onerror=alert(1)>',node_type:'<script>attack()</script>',success:true,ip_info:{ip:'8.8.8.8',isp:'<svg onload=attack()>',country:'<b>country</b>'},purity:{verified:false},services:{chatgpt:'restricted'},latency:{http_rtt:15}};
 const card=a.run('card(fixture)');assert.equal(card.children[0].textContent,a.ctx.fixture.node_name);assert.equal(card.children[1].textContent,a.ctx.fixture.node_type);assert.match(card.textContent,/<svg onload=attack\(\)>/);assert.equal(card.querySelectorAll('script').length,0);assert.equal(card.querySelectorAll('img').length,0);assert.equal(card.querySelectorAll('button').length,1);assert.equal(typeof card.querySelector('button').handlers.click,'function');assert.match(card.textContent,/风险未测量/);
});
test('filter excludes failed cards, handles unknown ratings, and pages at 50',()=>{
 const a=app();a.run("reset({id:'task',status:'completed',total:121,completed:121});for(let i=0;i<120;i++)ingest({node_id:String(i),node_name:String(i),success:true,purity:{ip_type:'residential',verified:false},latency:{http_rtt:20}});ingest({node_id:'bad',success:false,error:'bad'});render()");assert.equal(a.get('grid').children.length,50);assert.equal(a.get('pageText').textContent,'1 / 3 页 · 121 个节点');a.run("state.filter='res';render()");assert.equal(a.get('grid').children.length,50);assert.equal(a.run("[...state.results.values()].filter(matches).length"),120);a.run("state.filter='pure';render()");assert.equal(a.get('grid').children.length,0);assert.equal(a.get('emptyResults').hidden,false);
});
test('replayed SSE events do not duplicate nodes or counters',()=>{
 const a=app();a.run("reset({id:'task',status:'running',total:1,completed:0});connect()");const event={id:1,completed:1,status:'running',current:{node_id:'a',success:true,services:{chatgpt:'ok'},latency:{http_rtt:20}}};a.streams[0].onmessage({data:JSON.stringify(event)});a.streams[0].onmessage({data:JSON.stringify(event)});a.flush();assert.equal(a.run('state.results.size'),1);assert.equal(a.get('alive').textContent,'1');assert.equal(a.get('ai').textContent,'1');assert.equal(a.get('latency').textContent,'20 ms');
});
test('snapshot recovery completes missing results and closes connections',async()=>{
 const a=app();a.run("reset({id:'task',status:'running',total:2,completed:0});connect()");a.ctx.fetch=async(url,options)=>{a.requests.push({url,options});return{status:200,ok:true,json:async()=>url==='/api/tasks'?{tasks:[]}:{id:'task',status:'completed',completed:2,total:2,results:[{node_id:'a',success:true},{node_id:'b',success:false}]}}};await a.run('syncSnapshot()');a.flush();assert.equal(a.run('state.results.size'),2);assert.equal(a.run('state.task.status'),'completed');assert.equal(a.streams[0].closed,true);assert.equal(a.get('start').disabled,false);assert.equal(a.requests[0].options.credentials,'same-origin');assert.equal(a.requests[0].options.headers['X-NodePure'],'1');
});
test('switching modes disables hidden URL validation',()=>{const a=app();a.run("switchMode('text')");assert.equal(a.get('url').disabled,true);assert.equal(a.get('content').disabled,false);a.run("switchMode('url')");assert.equal(a.get('url').disabled,false)});
test('delayed snapshots cannot regress newer progress or revive finished tasks',async()=>{const a=app();a.run("reset({id:'task',status:'completed',total:2,completed:2})");a.ctx.fetch=async()=>({status:200,ok:true,json:async()=>({id:'task',status:'running',total:2,completed:1,results:[]})});await a.run('syncSnapshot()');assert.equal(a.run('state.task.status'),'completed');assert.equal(a.run('state.task.completed'),2)});
test('production assets have no CDN dependencies or HTML injection sinks',()=>{
 const dir=path.join(__dirname,'../dist');for(const f of ['index.html','app.js','app.css']){const s=fs.readFileSync(path.join(dir,f),'utf8');assert.doesNotMatch(s,/cdn\.tailwind|cdn\.jsdelivr|unpkg\.com|innerHTML|outerHTML|insertAdjacentHTML/);if(f==='index.html')assert.doesNotMatch(s,/onerror\s*=|onclick\s*=/)}
});
