'use strict';
// Operator-owned checkout assertions. Exercise the real Express app and sqlite3 driver over loopback.
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
  ['checkout_persists_before_success', async c => {
    const before = await c.orderCount();
    const response = await c.post();
    assert.equal(response.status, 200);
    assert.deepEqual(response.body, {message: 'Order placed', itemCount: 1});
    assert.equal(await c.orderCount(), before + 1);
    const order = await c.latestOrder();
    assert.equal(order.total, c.product.price);
    assert.equal(order.status, 'placed');
  }],
  ['checkout_write_failure_no_success', async c => {
    const before = await c.orderCount();
    const response = await c.post();
    assert.notEqual(response.status, 200);
    assert.notEqual(response.body.message, 'Order placed');
    assert.equal(await c.orderCount(), before);
  }],
];
async function fixture(rejectWrites) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aios-checkout-'));
  let app, db;
  const get = (sql, values=[]) => new Promise((resolve,reject)=>db.get(sql,values,(error,row)=>error?reject(error):resolve(row)));
  const close = async () => {
    if (app && app.exitCode === null && app.signalCode === null) {
      app.kill('SIGTERM');
      await Promise.race([new Promise(resolve=>app.once('exit',resolve)),delay(1000)]);
      if (app.exitCode === null && app.signalCode === null) { app.kill('SIGKILL'); await new Promise(resolve=>app.once('exit',resolve)); }
    }
  };
  try {
    for (const name of ['server.js','schema.sql','seed.sql']) fs.copyFileSync(name,path.join(dir,name));
    if (fs.existsSync('lib')) fs.cpSync('lib',path.join(dir,'lib'),{recursive:true});
    db = new sqlite3.Database(path.join(dir,'ecommerce.db'));
    await new Promise((resolve,reject)=>db.exec(fs.readFileSync('schema.sql','utf8'),error=>error?reject(error):resolve()));
    await new Promise((resolve,reject)=>db.exec(fs.readFileSync('seed.sql','utf8'),error=>error?reject(error):resolve()));
    const product = await get('SELECT id, price FROM products ORDER BY id LIMIT 1');
    if (!product) throw new Error('Checkout fixture has no product');
    if (rejectWrites) await new Promise((resolve,reject)=>db.exec(
      "CREATE TRIGGER aios_reject_order BEFORE INSERT ON orders BEGIN SELECT RAISE(ABORT, 'simulated write failure'); END",
      error=>error?reject(error):resolve(),
    ));
    const port = await new Promise((resolve,reject)=>{const server=net.createServer();server.on('error',reject);server.listen(0,'127.0.0.1',()=>{const assigned=server.address().port;server.close(()=>resolve(assigned));});});
    const url = `http://127.0.0.1:${port}`;
    app = spawn(process.execPath,[path.join(dir,'server.js')],{cwd:dir,env:{PATH:process.env.PATH,NODE_PATH:process.env.NODE_PATH,PORT:String(port),ECOMMERCE_DB_PATH:path.join(dir,'ecommerce.db')},stdio:'ignore'});
    for(let i=0;i<100;i++) {
      if(app.exitCode !== null || app.signalCode !== null) throw new Error('Application startup failed');
      try { const response=await fetch(url+'/products',{signal:AbortSignal.timeout(100)}); if(response.ok && Array.isArray(await response.json())) break; } catch {}
      if(i===99) throw new Error('Application readiness timeout');
      await delay(50);
    }
    return {
      product,
      post:async()=>{const response=await fetch(url+'/checkout',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({cart:[{id:product.id,price:0}]}),signal:AbortSignal.timeout(3000)});const text=await response.text();let body;try{body=JSON.parse(text);}catch{body={unparsed:true};}return {status:response.status,body};},
      orderCount:async()=>(await get('SELECT COUNT(*) AS count FROM orders')).count,
      latestOrder:async()=>get('SELECT total, status FROM orders ORDER BY id DESC LIMIT 1'),
      dispose:async()=>{await close();await new Promise(resolve=>db.close(resolve));fs.rmSync(dir,{recursive:true,force:true});},
    };
  } catch(error) { await close(); if(db) await new Promise(resolve=>db.close(resolve)); fs.rmSync(dir,{recursive:true,force:true}); throw error; }
}
(async()=>{
  for(const [test_id,test] of cases) {
    let context;
    try {context=await fixture(test_id==='checkout_write_failure_no_success');await test(context);tests.push({test_id,outcome:'PASSED',detail:''});}
    catch(error){tests.push({test_id,outcome:error.code==='ERR_ASSERTION'?'ASSERTION_FAILED':'SETUP_ERROR',detail:String(error.message).slice(0,1000)});}
    finally {if(context) await context.dispose();}
  }
  process.stdout.write(JSON.stringify({cases:tests}));
  process.exitCode=tests.every(test=>test.outcome==='PASSED')?0:1;
})().catch(error=>{process.stdout.write(JSON.stringify({cases:[{test_id:'setup',outcome:'SETUP_ERROR',detail:String(error.message).slice(0,1000)}]}));process.exitCode=1;});
