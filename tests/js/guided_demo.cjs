const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const nodes = new Map();
const node = id => {
  if (!nodes.has(id)) nodes.set(id, {textContent:'',hidden:false,disabled:false,dataset:{},setAttribute(){},appendChild(){}});
  return nodes.get(id);
};
const storage = new Map([['pt-token','session']]);
const context = vm.createContext({
  document:{getElementById:node,createElement:()=>node(Symbol()),addEventListener(){}},
  sessionStorage:{getItem:k=>storage.get(k),setItem:(k,v)=>storage.set(k,v),removeItem:k=>storage.delete(k)},
  crypto:{randomUUID:()=> 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'},
  setInterval:()=>1,clearInterval(){},URLSearchParams,
});
const run = code => vm.runInContext(code,context);
run(fs.readFileSync('frontend/app.js','utf8'));
run('loadAgents = async () => {}; loadActivity = async () => {};');
let creates=0, verifyCalls=0, disputeCalls=0, release;
const runs=[];
context.fakeApi=async (path,opts)=>{
  if(path==='/api/demo/projects') {
    creates++;
    assert.equal(opts.body.request_id,'a'.repeat(32));
    if(creates===1) await new Promise(resolve=>release=resolve);
    return {project_id:'sample',title:'Demo'};
  }
  if(path.includes('/agents/runs?')) return {runs};
  if(path.endsWith('/agents/run')) {
    runs.push({task_kind:opts.body.kind,status:'finished'});
    if(opts.body.kind==='verify_project') { verifyCalls++; throw new Error('response lost after persisted run'); }
    disputeCalls++;
    return {run_id:'run',task_kind:opts.body.kind,verdict:'clean',summaries:{},findings:[]};
  }
  if(path.endsWith('/verify')) return {ledger_valid:true};
  throw new Error('unexpected route');
};
run('api = fakeApi');
(async()=>{
  const first=run('runGuidedDemo()');
  await run('runGuidedDemo()');
  assert.equal(creates,1,'double click must not start another creation');
  assert(node('button-run-verify').disabled);
  release(); await first;
  assert.match(node('guided-demo-status').textContent,/Demo paused/);
  assert.equal(node('demo-step-verify').dataset.state,'paused');
  assert.equal(node('button-resume-demo').hidden,false);
  await run('runGuidedDemo()');
  assert.equal(verifyCalls,1,'resume must not repeat a persisted run whose response was lost');
  assert.equal(disputeCalls,1);
  assert.match(node('guided-demo-status').textContent,/Demo complete/);
  await run('runGuidedDemo()');
  assert.equal(verifyCalls,1); assert.equal(disputeCalls,1);
  assert.equal(node('demo-step-ledger').dataset.state,'done');
  assert.equal(node('button-run-verify').disabled,false);
  run('setToken(null)');
  assert.equal(storage.has('pt-demo-request'),false);
  assert.equal(node('guided-demo-panel').hidden,true);
  const before=creates;
  await run('runGuidedDemo()');
  assert.equal(creates,before,'signed-out demo must not write');
  console.log('PASS: duplicate prevention, lost-response resume, completed resume and sign-out');
})().catch(e=>{console.error(e);process.exitCode=1;});
