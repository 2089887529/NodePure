'use strict';
const $=id=>document.getElementById(id);
const state={mode:'url',task:null,results:new Map(),filter:'all',page:1,stream:null,poll:null,frame:null,lastEvent:0,counts:{alive:0,res:0,ai:0,gpt:0,claude:0,pure:0,latSum:0,latCount:0}};
const labels={queued:'排队中',running:'检测中',completed:'检测完成',failed:'检测失败',canceled:'已取消'};
const terminal=s=>['completed','failed','canceled'].includes(s);
const statusLabel=s=>({ok:'网页连通',restricted:'受限/验证页',rate_limited:'限流',timeout:'超时',error:'请求失败',unknown:'未知'}[s]||'未知');
const saved={get(k){try{return localStorage.getItem(k)}catch{return null}},set(k,v){try{localStorage.setItem(k,v)}catch{}},remove(k){try{localStorage.removeItem(k)}catch{}}};
function message(text){$('message').textContent=text;$('message').hidden=!text;}
async function request(url,options={}){
 const response=await fetch(url,{...options,headers:{'X-NodePure':'1',...options.headers},credentials:'same-origin'});
 if(response.status===401){showLogin();throw new Error('请重新登录');}
 if(!response.ok){let data;try{data=await response.json()}catch{};throw new Error(data?.error||`请求失败 (${response.status})`);}
 return response;
}
async function json(url,options){const r=await request(url,options);return r.status===204?null:r.json();}
function post(url,data){return json(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});}
function stopConnections(){if(state.stream)state.stream.close();state.stream=null;if(state.poll)clearInterval(state.poll);state.poll=null;}
function showLogin(){stopConnections();$('app').hidden=true;$('loginPanel').hidden=false;$('logout').hidden=true;}
function showApp(password){$('app').hidden=false;$('loginPanel').hidden=true;$('logout').hidden=!password;}
function setTheme(theme){document.documentElement.dataset.theme=theme;$('theme').textContent=theme==='dark'?'浅色模式':'深色模式';saved.set('nodepure_theme',theme);}
$('theme').addEventListener('click',()=>setTheme(document.documentElement.dataset.theme==='dark'?'light':'dark'));
setTheme(saved.get('nodepure_theme')||'dark');
$('loginForm').addEventListener('submit',async e=>{e.preventDefault();try{await post('/api/auth/login',{password:$('password').value});$('password').value='';message('');await initialize();}catch(e){message(e.message);}});
$('logout').addEventListener('click',async()=>{try{await post('/api/auth/logout',{});state.task=null;saved.remove('nodepure_task');showLogin();}catch(e){message(e.message);}});
function switchMode(mode){state.mode=mode;$('url').disabled=mode!=='url';$('content').disabled=mode!=='text';for(const id of ['url','text']){$(id+'Tab').classList.toggle('active',id===mode);$(id+'Tab').setAttribute('aria-selected',String(id===mode));$(id+'Pane').hidden=id!==mode;}}
$('urlTab').addEventListener('click',()=>switchMode('url'));$('textTab').addEventListener('click',()=>switchMode('text'));
$('demo').addEventListener('click',()=>{switchMode('text');$('content').value='proxies:\n  - name: 格式示例（需要替换）\n    type: ss\n    server: example.com\n    port: 443\n    cipher: aes-128-gcm\n    password: replace-with-your-node-password\n';message('这是配置格式示例，需要替换为你的真实节点才能连接。');});
function reset(task){stopConnections();state.task=task;state.results.clear();state.lastEvent=0;state.filter='all';state.page=1;state.counts={alive:0,res:0,ai:0,gpt:0,claude:0,pure:0,latSum:0,latCount:0};for(const b of $('filters').querySelectorAll('button'))b.classList.toggle('active',b.dataset.filter==='all');$('progress').hidden=false;$('summary').hidden=false;$('results').hidden=false;$('grid').replaceChildren();$('progressDetail').textContent='';render();}
$('checkForm').addEventListener('submit',async e=>{
 e.preventDefault();if(state.task&&!terminal(state.task.status))return;
 const data={url:state.mode==='url'?$('url').value.trim():'',content:state.mode==='text'?$('content').value.trim():'',concurrency:Number($('concurrency').value)};
 if(!data.url&&!data.content){message('请输入订阅链接或节点配置。');return;}
 $('start').disabled=true;message('');try{const result=await post('/api/check',data);reset({id:result.task_id,total:result.total_nodes,completed:0,status:result.status});saved.set('nodepure_task',result.task_id);connect();refreshHistory();}catch(e){$('start').disabled=false;message(e.message);}
});
function contribution(item,sign){if(!item.success)return;const c=state.counts;c.alive+=sign;const p=item.purity,s=item.services;if(p?.ip_type==='residential')c.res+=sign;if(p?.verified&&p.purity_score>=80)c.pure+=sign;if(s?.chatgpt==='ok')c.gpt+=sign;if(s?.claude==='ok')c.claude+=sign;if(s?.chatgpt==='ok'||s?.claude==='ok')c.ai+=sign;if(item.latency?.http_rtt>=0){c.latSum+=sign*item.latency.http_rtt;c.latCount+=sign;}}
function ingest(item){const old=state.results.get(item.node_id);if(old)contribution(old,-1);state.results.set(item.node_id,item);contribution(item,1);}
function scheduleRender(){if(state.frame!==null)return;state.frame=requestAnimationFrame(()=>{state.frame=null;render();});}
function matches(r){if(state.filter==='all')return true;if(!r.success)return false;switch(state.filter){case 'res':return r.purity?.ip_type==='residential';case 'pure':return r.purity?.verified&&r.purity.purity_score>=80;case 'chatgpt':return r.services?.chatgpt==='ok';case 'claude':return r.services?.claude==='ok';default:return false;}}
function element(tag,text,className){const n=document.createElement(tag);if(text!==undefined)n.textContent=String(text);if(className)n.className=className;return n;}
function detail(dl,label,value){const row=element('div');row.append(element('dt',label),element('dd',value||'—'));dl.append(row);return row;}
function card(r){
 const el=element('article',undefined,'card');el.append(element('h3',r.node_name),element('span',r.node_type,'protocol'));
 if(!r.success){el.append(element('p',r.error||'未获取有效出口','error'));return el;}
 const dl=element('dl'),ip=r.ip_info||{},p=r.purity||{},s=r.services||{};
 const row=detail(dl,'出口 IP',ip.ip);const copy=element('button',ip.ip||'—','copy');copy.type='button';copy.addEventListener('click',async()=>{try{await navigator.clipboard.writeText(ip.ip);message('出口 IP 已复制');}catch{message('当前浏览器不能复制，请手动选择出口 IP。');}});row.querySelector('dd').replaceChildren(copy);
 detail(dl,'地区',[ip.country,ip.city].filter(Boolean).join(' · '));detail(dl,'运营商',ip.isp);detail(dl,'ASN',ip.asn);el.append(dl);
 const chips=element('div',undefined,'chips');chips.append(element('span',p.ip_type_label||'类型未知','chip'),element('span',p.native_label||'原生性未知','chip'),element('span',p.verified&&p.purity_score!=null?`风险参考分 ${p.purity_score}`:'风险未测量','chip'));
 const latency=r.latency?.http_rtt;chips.append(element('span',latency>=0?`HTTP ${latency} ms`:'HTTP 测量失败','chip'));el.append(chips);
 const services=element('div',undefined,'chips services');for(const [key,name] of [['chatgpt','GPT'],['claude','Claude'],['youtube','YouTube'],['google','Google']]){services.append(element('span',`${name} · ${statusLabel(s[key])}`,s[key]==='ok'?'chip ok':'chip'));}el.append(services);
 el.append(element('p',`来源 ${ip.source||'未知'} · ${ip.source_at?new Date(ip.source_at).toLocaleString():'未知时间'}${ip.lookup_error?' · 元信息查询不完整':''}`,'source'));return el;
}
function render(){
 const task=state.task,c=state.counts;if(!task)return;const pct=task.total?Math.min(100,Math.round(task.completed/task.total*100)):0;$('bar').value=pct;$('percent').textContent=pct+'%';$('status').textContent=labels[task.status]||task.status;$('progressDetail').textContent=task.error||`${task.completed} / ${task.total} 个节点已完成`;$('start').disabled=!terminal(task.status);$('cancel').hidden=terminal(task.status);
 $('total').textContent=`${task.completed} / ${task.total}`;$('alive').textContent=c.alive;$('residential').textContent=c.res;$('ai').textContent=c.ai;$('latency').textContent=c.latCount?Math.round(c.latSum/c.latCount)+' ms':'—';
 const counts={all:state.results.size,res:c.res,pure:c.pure,chatgpt:c.gpt,claude:c.claude};const filterNames={all:'全部',res:'住宅 ISP 线索',pure:'风险评分 ≥80',chatgpt:'GPT 网页',claude:'Claude 网页'};
 for(const b of $('filters').querySelectorAll('button')){b.textContent=`${filterNames[b.dataset.filter]} (${counts[b.dataset.filter]})`;}
 const filtered=[...state.results.values()].filter(matches),pages=Math.max(1,Math.ceil(filtered.length/50));state.page=Math.min(state.page,pages);$('grid').replaceChildren(...filtered.slice((state.page-1)*50,state.page*50).map(card));$('pageText').textContent=`${state.page} / ${pages} 页 · ${filtered.length} 个节点`;$('previous').disabled=state.page<=1;$('next').disabled=state.page>=pages;$('emptyResults').hidden=filtered.length>0;
}
async function syncSnapshot(id=state.task?.id){if(!id)return;const snapshot=await json('/api/task/'+encodeURIComponent(id));if(state.task?.id!==id)return;if(snapshot.completed>=state.task.completed&&(!terminal(state.task.status)||terminal(snapshot.status)))state.task={...snapshot,results:undefined};for(const r of snapshot.results||[])ingest(r);scheduleRender();if(terminal(state.task.status)){stopConnections();refreshHistory();}}
function connect(){
 stopConnections();const id=state.task.id;const source=new EventSource('/api/stream/'+encodeURIComponent(id)+'?after='+state.lastEvent);state.stream=source;
 source.onmessage=e=>{if(state.task?.id!==id)return;try{const ev=JSON.parse(e.data);if(ev.id<=state.lastEvent)return;state.lastEvent=ev.id;state.task.completed=ev.completed;state.task.status=ev.status;state.task.error=ev.error;if(ev.current)ingest(ev.current);scheduleRender();if(ev.finished)syncSnapshot(id).catch(e=>message(e.message));}catch(e){message('结果解析失败，将从任务快照恢复。');syncSnapshot(id).catch(e=>message(e.message));}};
 source.onerror=()=>{if(state.task?.id!==id)return;$('status').textContent='连接恢复中…';syncSnapshot(id).catch(e=>message(e.message));};
 state.poll=setInterval(()=>syncSnapshot(id).catch(e=>message(e.message)),3000);
}
$('cancel').addEventListener('click',async()=>{if(!state.task)return;try{await post('/api/task/'+state.task.id+'/cancel',{});await syncSnapshot();}catch(e){message(e.message);}});
for(const b of $('filters').querySelectorAll('button'))b.addEventListener('click',()=>{state.filter=b.dataset.filter;state.page=1;for(const other of $('filters').querySelectorAll('button'))other.classList.toggle('active',other===b);render();});
$('previous').addEventListener('click',()=>{state.page--;render();});$('next').addEventListener('click',()=>{state.page++;render();});
async function download(response,name){const blob=await response.blob(),url=URL.createObjectURL(blob),link=element('a');link.href=url;link.download=name;document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);}
$('exportClash').addEventListener('click',async()=>{if(!state.task)return;const ids=[...state.results.values()].filter(r=>matches(r)&&r.success).map(r=>r.node_id);if(!ids.length){message('当前筛选没有可导出的节点。');return;}try{const r=await request('/api/export/clash',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({task_id:state.task.id,node_ids:ids,min_score:state.filter==='pure'?80:0})});await download(r,'nodepure_filtered.yaml');}catch(e){message(e.message);}});
$('exportCSV').addEventListener('click',async()=>{if(!state.task)return;try{await download(await request('/api/export/csv/'+state.task.id),'nodepure_report.csv');}catch(e){message(e.message);}});
async function refreshHistory(){try{const data=await json('/api/tasks');const rows=data.tasks.map(t=>{const row=element('div',undefined,'history-row');row.append(element('span',`${new Date(t.created_at).toLocaleString()} · ${labels[t.status]} · ${t.completed}/${t.total}`));const actions=element('div',undefined,'row'),open=element('button','查看');open.type='button';open.addEventListener('click',async()=>{try{reset(t);saved.set('nodepure_task',t.id);await syncSnapshot(t.id);if(!terminal(state.task.status))connect();}catch(e){message(e.message);}});actions.append(open);if(terminal(t.status)){const del=element('button','删除');del.type='button';del.addEventListener('click',async()=>{try{await request('/api/task/'+t.id,{method:'DELETE'});if(state.task?.id===t.id){stopConnections();saved.remove('nodepure_task');state.task=null;$('progress').hidden=true;$('summary').hidden=true;$('results').hidden=true;$('start').disabled=false;}refreshHistory();}catch(e){message(e.message);}});actions.append(del);}row.append(actions);return row;});$('history').replaceChildren(...rows);if(!rows.length)$('history').append(element('p','暂无任务','muted'));}catch(e){message(e.message);}}
$('refreshHistory').addEventListener('click',refreshHistory);
async function initialize(){try{const info=await json('/api/auth/session');$('limits').textContent=`最多 ${info.max_nodes} 个节点 · 全局并发上限 ${info.max_concurrency}`;for(const option of $('concurrency').options)option.disabled=Number(option.value)>info.max_concurrency;if(!info.authenticated){showLogin();return;}showApp(info.password_required);await refreshHistory();const id=saved.get('nodepure_task');if(id){try{const t=await json('/api/task/'+encodeURIComponent(id));reset(t);for(const r of t.results||[])ingest(r);render();if(!terminal(t.status))connect();}catch{saved.remove('nodepure_task');}}}catch(e){message(e.message);}}
initialize();
