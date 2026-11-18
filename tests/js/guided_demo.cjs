const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const nodes = new Map();
const node = id => {
  if (!nodes.has(id)) nodes.set(id, {textContent:'',hidden:false,disabled:false,dataset:{},setAttribute(){},appendChild(){}});
  return nodes.get(id);
};
const storage = new Map([['pt-token','session']]);
let nonceCounter = 0;
const context = vm.createContext({
  document:{getElementById:node,createElement:()=>node(Symbol()),addEventListener(){}},
  sessionStorage:{getItem:k=>storage.get(k),setItem:(k,v)=>storage.set(k,v),removeItem:k=>storage.delete(k)},
  crypto:{randomUUID:()=> String.fromCharCode(97 + nonceCounter++).repeat(32)},
  setInterval:()=>1,clearInterval(){},URLSearchParams,
});
const run = code => vm.runInContext(code,context);
run(fs.readFileSync('frontend/app.js','utf8'));
run('loadAgents = async () => {}; loadActivity = async () => {};');
let creates=0, verifyCalls=0, disputeCalls=0, release, releaseFresh;
const samples=new Map();
context.fakeApi=async (path,opts)=>{
  if(path==='/api/demo/projects') {
    creates++;
    const requestId=opts.body.request_id;
    if(!samples.has(requestId)) samples.set(requestId,{project_id:'sample-'+requestId[0],runs:[]});
    if(creates===1) await new Promise(resolve=>release=resolve);
    if(requestId==='b'.repeat(32) && creates===5) await new Promise(resolve=>releaseFresh=resolve);
    return {...samples.get(requestId),title:'Demo',matches_scenario:!samples.get(requestId).edited};
  }
  const sample=[...samples.values()].find(value=>path.startsWith('/api/projects/'+value.project_id+'/'));
  if(!sample) throw new Error('unexpected project');
  if(path.includes('/agents/runs?')) return {runs:sample.runs};
  if(path.endsWith('/agents/run')) {
    sample.runs.push({task_kind:opts.body.kind,status:'finished'});
    if(opts.body.kind==='verify_project') {
      verifyCalls++;
      if(verifyCalls===1) throw new Error('response lost after persisted run');
    } else disputeCalls++;
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
  const originalNonce=storage.get('pt-demo-request');
  await run('startFreshDemo()');
  assert.equal(storage.get('pt-demo-request'),originalNonce,'pending creation must keep its request ID');
  assert.equal(creates,1);
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
  samples.get(originalNonce).edited = true;
  await run('runGuidedDemo()');
  assert.match(node('guided-demo-status').textContent,/sample has been edited/);
  assert.equal(node('demo-step-sample').dataset.state,'paused');
  assert.equal(node('button-resume-demo').hidden,true);
  assert.equal(verifyCalls,1); assert.equal(disputeCalls,1);
  assert.equal(samples.get(originalNonce).runs.length,2);
  run('manualAgentBusy = true');
  await run('startFreshDemo()');
  assert.equal(storage.get('pt-demo-request'),originalNonce,'manual agent work blocks fresh start');
  run('manualAgentBusy = false');
  const fresh=run('startFreshDemo()');
  await run('startFreshDemo()');
  assert.equal(creates,5,'double fresh click must create only one new sample');
  assert.equal(storage.get('pt-demo-request'),'b'.repeat(32));
  assert(node('button-fresh-demo').disabled);
  releaseFresh(); await fresh;
  assert.equal(samples.size,2);
  assert.equal(samples.get(originalNonce).runs.length,2,'previous evidence must remain unchanged');
  assert.equal(samples.get('b'.repeat(32)).runs.length,2);
  assert.equal(verifyCalls,2); assert.equal(disputeCalls,2);
  assert.equal(node('button-fresh-demo').disabled,false);
  run('setToken(null)');
  assert.equal(storage.has('pt-demo-request'),false);
  assert.equal(node('guided-demo-panel').hidden,true);
  const before=creates;
  await run('startFreshDemo()');
  assert.equal(creates,before,'signed-out demo must not write');
  console.log('PASS: duplicate prevention, lost-response resume, completed resume, edited-sample pause, fresh sample isolation and sign-out');
})().catch(e=>{console.error(e);process.exitCode=1;});
