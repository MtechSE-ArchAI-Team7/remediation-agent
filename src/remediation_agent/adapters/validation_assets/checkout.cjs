'use strict';
// Operator-owned integration assertions. Both snapshots execute these identical assertions.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const net = require('node:net');
const {spawn} = require('node:child_process');
const sqlite3 = require('sqlite3');
const {chromium} = require('playwright-core');
const definition = require('./profiles.json').ecommerce_checkout;
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

async function fixture(rejectWrites) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aios-checkout-'));
  let app, db, browser;
  let diagnostics = '';
  const query = (sql, values=[]) => new Promise((resolve,reject)=>db.all(sql,values,(error,rows)=>error?reject(error):resolve(rows)));
  const exec = sql => new Promise((resolve,reject)=>db.exec(sql,error=>error?reject(error):resolve()));
  const closeApp = async () => {
    if (app && app.exitCode === null && app.signalCode === null) {
      const exited = new Promise(resolve=>app.once('exit',resolve));
      app.kill('SIGTERM');
      await Promise.race([exited,delay(1000)]);
      if (app.exitCode === null && app.signalCode === null) { app.kill('SIGKILL'); await exited; }
    }
  };
  const dispose = async () => {
    if (browser) await browser.close();
    await closeApp();
    if (db) await new Promise((resolve,reject)=>db.close(error=>error?reject(error):resolve()));
    fs.rmSync(dir,{recursive:true,force:true});
    if (fs.existsSync(dir)) throw new Error('Disposable fixture cleanup failed');
  };
  try {
    for (const name of ['server.js','schema.sql','seed.sql','public']) {
      fs.cpSync(name,path.join(dir,name),{recursive:true});
    }
    if (fs.existsSync('lib')) fs.cpSync('lib',path.join(dir,'lib'),{recursive:true});
    db = new sqlite3.Database(path.join(dir,'ecommerce.db'));
    await exec(fs.readFileSync('schema.sql','utf8'));
    await exec(fs.readFileSync('seed.sql','utf8'));
    // Deterministic prices, actual SQLite rows. No mocked driver or application implementation.
    const products = await query('SELECT id, price FROM products ORDER BY id LIMIT 2');
    if (products.length !== 2) throw new Error('Checkout fixture requires two seeded products');
    await exec(`UPDATE products SET price=11.25 WHERE id=${Number(products[0].id)}; UPDATE products SET price=7.50 WHERE id=${Number(products[1].id)}`);
    products[0].price=11.25; products[1].price=7.50;
    if (rejectWrites) await exec("CREATE TRIGGER aios_reject_order BEFORE INSERT ON orders BEGIN SELECT RAISE(ABORT, 'simulated write failure'); END");
    const port = await new Promise((resolve,reject)=>{const server=net.createServer();server.on('error',reject);server.listen(0,'127.0.0.1',()=>{const assigned=server.address().port;server.close(()=>resolve(assigned));});});
    const url = `http://127.0.0.1:${port}`;
    const start = async () => {
      diagnostics = '';
      app = spawn(process.execPath,[path.join(dir,'server.js')],{cwd:dir,env:{PATH:process.env.PATH,NODE_PATH:process.env.NODE_PATH,PORT:String(port)},stdio:['ignore','pipe','pipe']});
      for (const stream of [app.stdout, app.stderr]) stream.on('data',chunk=>{diagnostics=(diagnostics+chunk.toString()).slice(-1200);});
      for(let i=0;i<100;i++) {
        if(app.exitCode !== null || app.signalCode !== null) throw new Error('Application startup failed: '+diagnostics);
        try { const response=await fetch(url+'/products',{signal:AbortSignal.timeout(100)}); if(response.ok && (await response.json()).length>=2) return; } catch {}
        await delay(50);
      }
      throw new Error('Application readiness timeout: '+diagnostics);
    };
    await start();
    const count = async ()=>(await query('SELECT COUNT(*) AS count FROM orders'))[0].count;
    return {
      products, url, count,
      restart:async()=>{await closeApp();await start();},
      post:async(body={cart:[{id:products[0].id,price:0}]})=>{
        const response=await fetch(url+'/checkout',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),signal:AbortSignal.timeout(3000)});
        const text=await response.text();let parsed;try{parsed=JSON.parse(text);}catch{parsed={unparsed:true};}
        return {status:response.status,body:parsed};
      },
      latest:async()=>(await query('SELECT * FROM orders ORDER BY id DESC LIMIT 1'))[0],
      storefront:async()=>{
        try {browser=await chromium.launch({executablePath:process.env.AIOS_BROWSER_EXECUTABLE,headless:true,env:{PATH:process.env.PATH},args:['--disable-dev-shm-usage'],timeout:10000});}
        catch(error) {error.name='BrowserStartupError';throw error;}
        const context=await browser.newContext({serviceWorkers:'block'});
        // Only the disposable app is reachable from the browser, including redirects and subresources.
        await context.route('**/*',route=>new URL(route.request().url()).origin===url?route.continue():route.abort());
        const page=await context.newPage();page.setDefaultTimeout(3000);
        const dialogs=[];
        page.on('dialog',async dialog=>{dialogs.push(dialog.message());await dialog.dismiss().catch(()=>{});});
        await page.goto(url,{waitUntil:'domcontentloaded'});
        await page.getByText('Add to Cart',{exact:true}).first().waitFor();
        await page.getByText('Add to Cart',{exact:true}).first().click();
        await page.locator('button[onclick="showCart()"]').click();
        dialogs.length=0;
        return {page,dialogs};
      },
      dispose,
    };
  } catch(error) { await dispose(); throw error; }
}

const cases = {
  checkout_persists_before_success: async c => {
    const before=await c.count(); const response=await c.post();
    assert.equal(response.status,200);
    assert.deepEqual(response.body,{message:'Order placed',itemCount:1});
    assert.equal(await c.count(),before+1);
    assert.equal((await c.latest()).total,c.products[0].price);
    // No status literal is required by the accepted contract.
  },
  checkout_server_priced_multiple_products: async c => {
    const response=await c.post({cart:c.products.map(p=>({id:p.id,price:0}))});
    assert.equal(response.status,200);assert.equal(response.body.itemCount,2);
    const order=await c.latest();assert.ok(order,'Order must be persisted');
    assert.equal(order.total,18.75);
  },
  checkout_invalid_carts: async c => {
    for(const body of [{},{cart:[]},{cart:'bad'},{cart:[null]},{cart:[{id:'1'}]},{cart:[{id:1.5}]},{cart:[{id:-1}]},{cart:[{id:99999999}]}]) {
      const before=await c.count();const response=await c.post(body);
      assert.ok(response.status>=400 && response.status<500,'Invalid cart must return a client error');
      assert.notEqual(response.body.message,'Order placed');assert.equal(await c.count(),before);
    }
  },
  checkout_write_failure_no_success: async c => {
    const before=await c.count();const response=await c.post();
    assert.ok(response.status>=400);assert.notEqual(response.body.message,'Order placed');
    assert.equal(await c.count(),before);
  },
  checkout_restart_persistence: async c => {
    const before=await c.count();assert.equal((await c.post()).status,200);
    assert.equal(await c.count(),before+1); const order=await c.latest();
    await c.restart();assert.equal(await c.count(),before+1);assert.deepEqual(await c.latest(),order);
  },
  checkout_browser_confirmed_success: async c => {
    const before=await c.count();const {page,dialogs}=await c.storefront();
    let release;
    const pending=new Promise(resolve=>{release=resolve;});
    const requested=page.waitForRequest(c.url+'/checkout').catch(()=>null);
    await page.route(c.url+'/checkout',async route=>{await pending;await route.continue().catch(()=>{});});
    const responsePromise=page.waitForResponse(c.url+'/checkout').catch(()=>null);
    await page.getByText('Checkout',{exact:true}).click();
    try {
      assert.ok(await requested,'Checkout must submit the actual request');
      await delay(150);
      assert.equal(await page.locator('#cart-count').textContent(),'1','Keep cart while persistence is pending');
      assert.equal(dialogs.length,0,'Do not announce success while request is pending');
    } finally { release(); }
    const response=await responsePromise;assert.ok(response,"Checkout response must complete");assert.equal(response.status(),200);
    await page.waitForFunction(()=>document.getElementById('cart-count').textContent==='0').catch(()=>assert.fail('Confirmed success must clear the cart'));
    assert.equal(await c.count(),before+1);
    assert.ok(dialogs.some(text=>/order.*(placed|success)|success.*order/i.test(text)),'Show confirmed success');
  },
  checkout_browser_http_failure: async c => {
    const before=await c.count();const {page,dialogs}=await c.storefront();
    const responsePromise=page.waitForResponse(c.url+'/checkout').catch(()=>null);
    await page.getByText('Checkout',{exact:true}).click();
    const response=await responsePromise;assert.ok(response,"Checkout response must complete");assert.ok(response.status()>=400);await delay(200);
    assert.equal(await page.locator('#cart-count').textContent(),'1');
    assert.ok(!dialogs.some(text=>/order.*(placed|success)|success.*order/i.test(text)));
    assert.equal(await c.count(),before);
  },
  checkout_browser_network_failure: async c => {
    const before=await c.count();const {page,dialogs}=await c.storefront();
    await page.route(c.url+'/checkout',route=>route.abort('connectionfailed'));
    const failed=page.waitForEvent('requestfailed',r=>r.url()===c.url+'/checkout').catch(()=>null);
    await page.getByText('Checkout',{exact:true}).click();assert.ok(await failed,'Checkout must submit the actual request');await delay(200);
    assert.equal(await page.locator('#cart-count').textContent(),'1');
    assert.ok(!dialogs.some(text=>/order.*(placed|success)|success.*order/i.test(text)));
    assert.equal(await c.count(),before);
  },
  checkout_catalog_regression: async c => {
    const response=await fetch(c.url+'/products');assert.equal(response.status,200);
    const products=await response.json();assert.ok(Array.isArray(products));assert.ok(products.length>=2);
    const index=await fetch(c.url+'/');assert.equal(index.status,200);
    assert.match(await index.text(),/<script[^>]+app\.js/);
  },
};
(async()=>{
  const results=[];
  assert.deepEqual(Object.keys(cases).sort(),Object.keys(definition.assertions).sort(),'Profile and executable assertions must match');
  for(const [test_id,test] of Object.entries(cases)) {
    let context, record;
    try {context=await fixture(['checkout_write_failure_no_success','checkout_browser_http_failure'].includes(test_id));await test(context);record={test_id,outcome:'PASSED',detail:''};}
    catch(error){record={test_id,outcome:error.code==='ERR_ASSERTION'||(context&&error.name==='TimeoutError')?'ASSERTION_FAILED':'SETUP_ERROR',detail:String(error.message).split('\n').filter(line=>!line.includes('<launching>')).join('\n').slice(0,1200)};}
    finally {if(context) {try {await context.dispose();} catch {record={test_id,outcome:'SETUP_ERROR',detail:'Disposable fixture cleanup failed'};}}}
    results.push(record);
  }
  process.stdout.write(JSON.stringify({cases:results}));
  process.exitCode=results.every(test=>test.outcome==='PASSED')?0:1;
})().catch(error=>{process.stdout.write(JSON.stringify({cases:[{test_id:'setup',outcome:'SETUP_ERROR',detail:String(error.message).split('\n').filter(line=>!line.includes('<launching>')).join('\n').slice(0,1200)}]}));process.exitCode=1;});
