let I18N = {};
let currentConv = null;

function qs(id){return document.getElementById(id)}
function esc(s){return (s||'').replace(/[&<>\"]/g, c=>({"&":"&amp;","<":"&lt;",">":"&gt;","\\":"&#92;","\"":"&quot;"}[c]))}

async function api(path, opts){
  const r = await fetch(path, opts);
  if(!r.ok) throw new Error(await r.text());
  const ct = r.headers.get('content-type')||'';
  if(ct.includes('application/json')) return r.json();
  return r.text();
}

async function loadLang(lang){
  try{ I18N = await api(`/i18n/${lang}.json`); }
  catch(e){ I18N = await api(`/i18n/en.json`); }

  document.querySelectorAll('[data-i18n]').forEach(el=>{
    const k = el.getAttribute('data-i18n');
    if(I18N[k]) el.textContent = I18N[k];
  });

  qs('text').placeholder = I18N['message.placeholder'] || qs('text').placeholder;
}

function fmtTs(ts){
  try{ return new Date(ts*1000).toLocaleString(); }
  catch(e){ return String(ts) }
}

async function refreshMe(){
  const me = await api('/api/me');
  qs('me').textContent = `${I18N['me.id']||'My ID'}: ${me.id}`;
}

async function refreshContacts(){
  const list = await api('/api/contacts');
  const root = qs('contacts');
  root.innerHTML = '';
  list.forEach(c=>{
    const el = document.createElement('div');
    el.className = 'item';
    el.innerHTML = `<div class="title">${esc(c.id)}</div><div class="small">${esc(c.host||'')}${c.port?(':'+c.port):''} ${c.is_relay? '(relay)':''}</div>`;
    el.onclick = ()=>{ qs('to').value = c.id; };
    root.appendChild(el);
  });
}

async function refreshConversations(){
  const list = await api('/api/conversations');
  const root = qs('conversations');
  root.innerHTML = '';
  list.forEach(c=>{
    const el = document.createElement('div');
    el.className = 'item';
    const name = (c.type === 'group') ? (c.title || ('group '+(c.uuid||''))) : (c.peer || ('#'+c.id));
    el.innerHTML = `<div class="title">${esc(name)}</div><div class="small">${esc(c.last_body||'')} • ${fmtTs(c.last_ts||0)}</div>`;
    el.onclick = ()=>openConversation(c);
    root.appendChild(el);
  });
}

async function openConversation(c){
  currentConv = c;
  const name = (c.type === 'group') ? (c.title || (c.uuid||'group')) : (c.peer || ('#'+c.id));
  qs('chatTitle').textContent = `${I18N['chat.with']||'Chat'}: ${name}`;

  if(c.type === 'group'){
    qs('to').value = '';
    qs('to').disabled = true;
    qs('to').placeholder = I18N['group.mode'] || 'group chat';
  }else{
    qs('to').disabled = false;
    if(c.peer) qs('to').value = c.peer;
  }
  await refreshMessages();
}

async function refreshMessages(){
  if(!currentConv) return;
  const msgs = await api(`/api/messages?conv=${currentConv.id}`);
  const root = qs('messages');
  root.innerHTML = '';
  msgs.forEach(m=>{
    const el = document.createElement('div');
    el.className = 'msg';
    const dir = m.dir === 1 ? (I18N['message.out']||'out') : (I18N['message.in']||'in');
    el.innerHTML = `<div class="meta">${esc(dir)} • ${esc(m.sender)} • ${fmtTs(m.ts)}</div><div class="body">${esc(m.body)}</div>`;
    root.appendChild(el);
  });
  root.scrollTop = root.scrollHeight;
}

async function addContact(){
  const id = qs('c_id').value.trim();
  const host = qs('c_host').value.trim();
  const port = qs('c_port').value.trim();
  const relay = qs('c_relay').checked ? '1':'0';
  const body = new URLSearchParams({id, host, port, relay});
  await api('/api/add_contact', {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body});
  qs('c_id').value='';
  qs('c_host').value='';
  qs('c_port').value='';
  await refreshContacts();
  await refreshConversations();
}

async function createGroup(){
  const title = qs('g_title').value.trim();
  const members = qs('g_members').value.trim();
  if(!members) return;
  const body = new URLSearchParams({title, members});
  await api('/api/create_group', {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body});
  qs('g_title').value='';
  qs('g_members').value='';
  await refreshConversations();
}

async function sendMsg(){
  const text = qs('text').value;
  if(!text) return;

  if(currentConv && currentConv.type === 'group'){
    const body = new URLSearchParams({conv: String(currentConv.id), text});
    await api('/api/send_group', {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body});
  }else{
    const to = qs('to').value.trim();
    if(!to) return;
    const body = new URLSearchParams({to, text});
    await api('/api/send', {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body});
  }

  qs('text').value='';
  await refreshConversations();
  if(currentConv) await refreshMessages();
}

async function boot(){
  const browser = (navigator.language||'en').slice(0,2);
  const sel = qs('langSelect');
  sel.value = ['en','fr'].includes(browser) ? browser : 'en';
  await loadLang(sel.value);
  await refreshMe();
  await refreshContacts();
  await refreshConversations();
  setInterval(()=>{ refreshConversations(); if(currentConv) refreshMessages(); }, 2000);

  qs('btnAdd').onclick = ()=>addContact().catch(e=>alert(e));
  qs('btnSend').onclick = ()=>sendMsg().catch(e=>alert(e));
  qs('btnGroup').onclick = ()=>createGroup().catch(e=>alert(e));
  sel.onchange = async ()=>{ await loadLang(sel.value); await refreshMe(); };
}

boot().catch(e=>alert(e));
