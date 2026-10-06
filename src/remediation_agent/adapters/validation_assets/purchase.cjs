'use strict';
// Operator-owned integration assertions. Actual server, middleware, and sqlite3 driver.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const net = require('node:net');
const {spawn} = require('node:child_process');
const sqlite3 = require('sqlite3');
const tests = [];
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const cases = [
  ['purchase_below_stock', async c => { const r = await c.post({productId:1,quantity:1}); assert.equal(r.status,200); assert.equal(r.body.success,true); assert.equal(r.body.remaining,9); assert.equal(await c.stock(),9); }],
  ['purchase_equal_stock', async c => { const r = await c.post({productId:1,quantity:10}); assert.equal(r.status,200); assert.equal(r.body.remaining,0); assert.equal(await c.stock(),0); }],
  ['purchase_above_stock', async c => { const r = await c.post({productId:1,quantity:11}); assert.equal(r.status,400); assert.equal(r.body.error,'Insufficient inventory'); assert.equal(await c.stock(),10); }],
  ['purchase_invalid_inputs', async c => { for (const body of [{productId:1,quantity:0},{productId:1,quantity:-1},{productId:1,quantity:1.5},{productId:'1',quantity:'1'},{}]) { const r=await c.post(body); assert.equal(r.status,400); assert.equal(r.body.error,'Invalid product ID or quantity'); } assert.equal((await c.post('{',false,true)).status,400); assert.equal(await c.stock(),10); }],
  ['purchase_form_encoding', async c => { assert.equal((await c.post({productId:1,quantity:1},true)).status,400); assert.equal(await c.stock(),10); }],
  ['purchase_unknown_product', async c => { assert.equal((await c.post({productId:999,quantity:1})).status,400); assert.equal(await c.stock(),10); }],
  ['purchase_persistence', async c => { assert.equal((await c.post({productId:1,quantity:2})).status,200); await c.restart(); assert.equal(await c.stock(),8); }],
  ['purchase_concurrent', async c => { const results = await Promise.all(Array.from({length:15},()=>c.post({productId:1,quantity:1}))); assert.equal(results.filter(r=>r.status===200).length,10); assert.equal(results.filter(r=>r.status===400).length,5); assert.equal(await c.stock(),0); }],
];
async function fixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(),'aios-purchase-'));
  let app, db;
  const run = (sql, values=[]) => new Promise((resolve,reject)=>db.run(sql,values,error=>error?reject(error):resolve()));
  const get = sql => new Promise((resolve,reject)=>db.get(sql,(error,row)=>error?reject(error):resolve(row)));
  const close = async () => {
    if (app && app.exitCode === null && app.signalCode === null) {
      app.kill('SIGTERM');
      await Promise.race([new Promise(resolve=>app.once('exit',resolve)),delay(1000)]);
      if (app.exitCode === null && app.signalCode === null) { app.kill('SIGKILL'); await new Promise(resolve=>app.once('exit',resolve)); }
    }
  };
  try {
    for (const name of ['server.js','schema.sql','seed.sql']) fs.copyFileSync(name,path.join(dir,name));
    // Copy application helpers, but never tests, dependencies, secrets or the validation runner.
    if (fs.existsSync('lib')) fs.cpSync('lib',path.join(dir,'lib'),{recursive:true});
    db = new sqlite3.Database(path.join(dir,'ecommerce.db'));
    await new Promise((resolve,reject)=>db.exec(fs.readFileSync('schema.sql','utf8'),e=>e?reject(e):resolve()));
    await new Promise((resolve,reject)=>db.exec(fs.readFileSync('seed.sql','utf8'),e=>e?reject(e):resolve()));
    await run('UPDATE products SET inventory = 10 WHERE id = 1');
    const port = await new Promise((resolve,reject)=>{const s=net.createServer();s.on('error',reject);s.listen(0,'127.0.0.1',()=>{const p=s.address().port;s.close(()=>resolve(p));});});
    const url = `http://127.0.0.1:${port}`;
    const start = async () => {
      app = spawn(process.execPath,[path.join(dir,'server.js')],{cwd:dir,env:{PATH:process.env.PATH,NODE_PATH:process.env.NODE_PATH,PORT:String(port)},stdio:'ignore'});
      for(let i=0;i<100;i++) {
        if(app.exitCode !== null || app.signalCode !== null) throw new Error('Application startup failed');
        try { const r=await fetch(url+'/products',{signal:AbortSignal.timeout(100)}); if(r.ok && Array.isArray(await r.json())) return; } catch {}
        await delay(50);
      }
      throw new Error('Application readiness timeout');
    };
    await start();
    return {post:async(body,form=false,raw=false)=>{const r=await fetch(url+'/purchase',{method:'POST',headers:{'Content-Type':form?'application/x-www-form-urlencoded':'application/json'},body:raw?body:form?new URLSearchParams(body):JSON.stringify(body),signal:AbortSignal.timeout(3000)});const text=await r.text(); let result; try{result=JSON.parse(text);}catch{result={unparsed:true};} return {status:r.status,body:result};},
      stock:async()=>(await get('SELECT inventory FROM products WHERE id = 1')).inventory,
      restart:async()=>{await close();await start();},
      dispose:async()=>{await close();await new Promise(resolve=>db.close(resolve));fs.rmSync(dir,{recursive:true,force:true});}};
  } catch(error) { await close(); if(db) await new Promise(resolve=>db.close(resolve)); fs.rmSync(dir,{recursive:true,force:true}); throw error; }
}
(async()=>{
  for(const [test_id,test] of cases) {
    let c;
    try {c=await fixture();await test(c);tests.push({test_id,outcome:'PASSED',detail:''});}
    catch(error){tests.push({test_id,outcome:error.code==='ERR_ASSERTION'?'ASSERTION_FAILED':'SETUP_ERROR',detail:String(error.message).slice(0,1000)});}
    finally {if(c) await c.dispose();}
  }
  process.stdout.write(JSON.stringify({cases:tests}));
  process.exitCode=tests.every(t=>t.outcome==='PASSED')?0:1;
})().catch(error=>{process.stdout.write(JSON.stringify({cases:[{test_id:'setup',outcome:'SETUP_ERROR',detail:String(error.message).slice(0,1000)}]}));process.exitCode=1;});
