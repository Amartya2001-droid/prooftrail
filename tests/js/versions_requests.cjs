// Controlled promise ordering against the actual client controller; no timers.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function ui() {
  class Element {
    constructor() { this.children=[]; this.hidden=false; this.disabled=false; this.dataset={}; this.value=''; this.own=''; }
    set textContent(value) { this.own=String(value); this.children=[]; }
    get textContent() { return this.own+this.children.map(child=>child.textContent).join(''); }
    set innerHTML(value) { assert.equal(value,''); this.textContent=''; }
    appendChild(child) { this.children.push(child); return child; }
    addEventListener() {}
    setAttribute() {}
  }
  const nodes=new Map(), storage=new Map([['pt-token','first-session']]), calls=[];
  const node=id=> { if(!nodes.has(id)) nodes.set(id,new Element()); return nodes.get(id); };
  const context=vm.createContext({
    document:{getElementById:node,createElement:()=>new Element(),addEventListener(){}},
    sessionStorage:{getItem:k=>storage.get(k),setItem:(k,v)=>storage.set(k,v),removeItem:k=>storage.delete(k)},
    setInterval:()=>1,clearInterval(){},URLSearchParams,
    fakeApi:path=>new Promise((resolve,reject)=>calls.push({path,resolve,reject})),
  });
  const run=code=>vm.runInContext(code,context);
  run(fs.readFileSync('frontend/app.js','utf8'));
  run("api = fakeApi; currentProjectId = 'A';");
  return {node,storage,calls,run,labels:()=>node('version-list').children.map(row=>row.textContent.split(' — ')[0])};
}
function page(prefix,count,total=count,start=0) {
  return {versions:Array.from({length:count},(_,i)=>({label:prefix+(start+i),content_id:'sha256:'+prefix+(start+i),timestamp:'2026-11-26T12:00:00Z',size:12})),total};
}
async function seed(h,payload=page('A',50,52)) {
  const loading=h.run('loadVersions()'); h.calls.at(-1).resolve(payload); await loading;
}
const cases={
  async newer_reset_wins() {
    const h=ui(), older=h.run('loadVersions()'), newer=h.run('loadVersions()');
    h.calls[1].resolve(page('new',2)); await newer;
    h.calls[0].resolve(page('old',1)); await older;
    assert.deepEqual(h.labels(),['new0','new1'],'late reset must not append stale versions');
    assert.equal(h.run('versionOffset'),2);
  },
  async older_reset_waits() {
    const h=ui(), older=h.run('loadVersions()'), newer=h.run('loadVersions()');
    h.calls[0].resolve(page('old',1)); await older;
    assert.deepEqual(h.labels(),[],'superseded result must stay hidden while latest request waits');
    h.calls[1].resolve(page('new',2)); await newer;
    assert.deepEqual(h.labels(),['new0','new1']);
  },
  async project_switch() {
    const h=ui(), old=h.run('loadVersions()'); h.run("currentProjectId = 'B'");
    const current=h.run('loadVersions()'); h.calls[1].resolve(page('B',1)); await current;
    h.calls[0].resolve(page('A',1)); await old;
    assert.deepEqual(h.labels(),['B0'],'other project response must not append');
    h.run("currentProjectId = 'A'"); const failing=h.run('loadVersions()');
    const outcome=failing.then(()=>null,error=>error);
    h.run("currentProjectId = 'B'"); const latest=h.run('loadVersions()');
    h.calls[3].resolve(page('B',1)); await latest;
    h.calls[2].reject(new Error('old project unavailable'));
    assert.equal(await outcome,null,'obsolete read error must not surface in the new project');
    assert.deepEqual(h.labels(),['B0']);
  },
  async account_switch() {
    const h=ui(), old=h.run('loadVersions()'); h.storage.set('pt-token','different-session');
    h.calls[0].resolve(page('private-old-account',1)); await old;
    assert.deepEqual(h.labels(),[],'previous account response must not render');
    assert.equal(h.run('versionOffset'),0);
  },
  async duplicate_page() {
    const h=ui(); await seed(h);
    const first=h.run('loadVersions(false)'), second=h.run('loadVersions(false)');
    assert.equal(h.calls.length,2,'one reset and only one in-flight next page');
    assert(h.node('button-versions-more').disabled);
    assert(h.calls[1].path.endsWith('offset=50'));
    h.calls[1].resolve(page('A',2,52,50)); await Promise.all([first,second]);
    assert.equal(h.labels().length,52); assert.equal(new Set(h.labels()).size,52);
    assert.equal(h.run('versionOffset'),52);
    assert.equal(h.node('button-versions-more').hidden,true);
  },
  async reset_during_page() {
    const h=ui(); await seed(h);
    const stale=h.run('loadVersions(false)'), reset=h.run('loadVersions()');
    h.calls[2].resolve(page('current',50,52)); await reset;
    const latest=h.run('loadVersions(false)');
    h.calls[1].resolve(page('obsolete',1,51,50)); await stale;
    assert.equal(h.labels().length,50,'old page must not append after reset');
    assert(h.node('button-versions-more').disabled,'old completion must not unlock the new page request');
    h.calls[3].resolve(page('current',2,52,50)); await latest;
    assert.equal(h.labels().length,52); assert.equal(h.run('versionOffset'),52);
    assert(h.labels().every(label=>label.startsWith('current')));
  },
  async page_failure_retry() {
    const h=ui(); await seed(h);
    const failed=h.run('loadVersions(false)');
    assert(h.node('button-versions-more').disabled);
    const rejection=assert.rejects(failed,/network unavailable/);
    h.calls[1].reject(new Error('network unavailable')); await rejection;
    assert.equal(h.node('button-versions-more').disabled,false);
    assert.equal(h.run('versionOffset'),50);
    const retry=h.run('loadVersions(false)');
    assert(h.calls[2].path.endsWith('offset=50'));
    h.calls[2].resolve(page('A',2,52,50)); await retry;
    assert.equal(h.labels().length,52); assert.equal(h.run('versionOffset'),52);
  },
  async missing_selection() {
    const h=ui(); await seed(h); h.run('currentProjectId = null');
    await h.run('loadVersions()');
    assert.deepEqual(h.labels(),[],'cleared selection must not retain private rows');
    assert.equal(h.node('button-versions-more').hidden,true);
    assert.equal(h.run('versionOffset'),0);
    const other=ui(); await seed(other); other.storage.delete('pt-token');
    const pending=other.run('loadVersions()');
    assert.equal(other.calls.length,1,'signed-out refresh must not issue a history request');
    await pending; assert.deepEqual(other.labels(),[]);
  },
};
const selected=process.argv[2];
(async()=>{
  assert(cases[selected],'unknown regression scenario'); await cases[selected]();
  console.log('PASS: '+selected);
})().catch(error=>{console.error(error);process.exitCode=1;});
