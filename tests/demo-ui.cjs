// Local-only UI regression harness. No Go server, scanner, or external tool required.
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawn } = require('node:child_process');
const assert = require('node:assert/strict');
const { once } = require('node:events');
const sleep = ms => new Promise(r => setTimeout(r, ms));
const root = path.resolve(__dirname, '..', 'web', 'static');
const out = path.resolve(process.env.TEST_OUTPUT || path.join(os.tmpdir(), 'go-scan-ui-demo-results'));
fs.mkdirSync(out, { recursive: true });
const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'goscan-demo-'));
let chrome, ws, server;
const requests = [], errors = [], network = [];
let checks = 0;
function check(value, msg) { assert.ok(value, msg); checks++; }
(async () => {
 server = http.createServer((req,res) => {
  requests.push({method:req.method, path:req.url});
  if (req.url === '/api/info') {
   res.setHeader('Content-Type','application/json');
   if ((req.headers.referer || '').includes('offline=1')) { res.writeHead(503); res.end('{"error":"fixture unavailable"}'); return; }
   res.end(JSON.stringify({nmap:{available:false},root:false,os:'fixture',arch:'mock',tools:[]})); return;
  }
  if (req.url.startsWith('/api/')) { res.writeHead(500); res.end('{}'); return; }
  const name = new URL(req.url, 'http://localhost').pathname;
  const file = path.join(root, name === '/' ? 'index.html' : name);
  if (!file.startsWith(root + path.sep) || !fs.existsSync(file)) {res.writeHead(404); res.end(); return;}
  res.setHeader('Content-Type', file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : 'text/html');
  res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self'; script-src 'self'");
  res.end(fs.readFileSync(file));
 });
 server.listen(0,'127.0.0.1'); await once(server,'listening');
 const base = `http://127.0.0.1:${server.address().port}`;
 chrome = spawn(process.env.CHROMIUM || 'chromium', ['--headless','--no-sandbox','--disable-dev-shm-usage','--disable-background-networking','--no-first-run','--remote-debugging-port=0',`--user-data-dir=${profile}`,'about:blank'], {stdio:'ignore'});
 const portFile = path.join(profile,'DevToolsActivePort');
 for (let i=0; i<150 && !fs.existsSync(portFile); i++) await sleep(100);
 check(fs.existsSync(portFile), 'Chromium starts');
 const port = fs.readFileSync(portFile,'utf8').split('\n')[0];
 const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
 ws = new WebSocket(targets.find(t=>t.type==='page').webSocketDebuggerUrl); await once(ws,'open');
 let seq=0; const pending = new Map();
 ws.onmessage = event => {
  const msg = JSON.parse(event.data);
  if (msg.id && pending.has(msg.id)) {const p=pending.get(msg.id); pending.delete(msg.id); msg.error ? p.reject(new Error(JSON.stringify(msg.error))) : p.resolve(msg.result);}
  if (msg.method === 'Runtime.exceptionThrown') errors.push(msg.params.exceptionDetails.text);
  if (msg.method === 'Network.requestWillBeSent') network.push(msg.params.request.url);
 };
 const send = (method, params={}) => new Promise((resolve,reject)=>{const id=++seq; pending.set(id,{resolve,reject}); ws.send(JSON.stringify({id,method,params}));});
 const run = async expression => {
  const r=await send('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});
  if (r.exceptionDetails) throw new Error(JSON.stringify(r.exceptionDetails));
  return r.result.value;
 };
 const text = id => run(`document.getElementById(${JSON.stringify(id)}).textContent`);
 const click = selector => run(`document.querySelector(${JSON.stringify(selector)}).click()`);
 const waitFor = async expression => {for(let i=0;i<100;i++){if(await run(expression)) return;await sleep(50);}throw new Error('Timeout: '+expression);};
 const shot = async name => {const r=await send('Page.captureScreenshot',{format:'png',captureBeyondViewport:true}); fs.writeFileSync(path.join(out,name),Buffer.from(r.data,'base64'));};
 await send('Runtime.enable'); await send('Network.enable'); await send('Page.enable');
 await send('Emulation.setDeviceMetricsOverride',{width:1440,height:1100,deviceScaleFactor:1,mobile:false});
 await send('Page.navigate',{url:base});
 await waitFor(`document.getElementById('env')?.textContent.includes('fixture')`);
 await click('[data-mode="dir"]'); await sleep(300);
 check((await text('cmd-preview')).includes('离线演示'), 'Directory preview is offline');
 check(await run(`document.getElementById('targets').closest('.field').classList.contains('hidden')`),'Shared target hidden');
 check(await run(`document.getElementById('d-url').readOnly`),'Demo target is read-only');
 await run(`document.getElementById('d-ext').value='html,txt'; document.getElementById('d-ext').dispatchEvent(new Event('input'));`); await sleep(300);
 check((await text('cmd-preview')).includes('html,txt'), 'Preview reflects parameters');
 await click('#btn-start'); await sleep(520);
 check(await run(`document.querySelector('[data-mode="tool"]').disabled`),'Mode switches locked during playback');
 await click('#btn-stop');
 check((await text('st-status'))==='演示已停止','Stop works');
 const stoppedLog=await text('log'); await sleep(1000);
 check((await text('log'))===stoppedLog,'Stopped timer does not continue');
 await click('#btn-start'); await waitFor(`document.getElementById('st-status').textContent === '演示完成'`);
 check((await text('tbody')).includes('simulated'),'Simulated row visible');
 check((await text('st-open'))==='0','Demo never claims an open port');
 check(!(await run(`document.getElementById('result-note').classList.contains('hidden')`)), 'Persistent simulated-data notice');
 await shot('directory-demo.png');
 await run(`window.demoBlobs=[]; window.demoDownloads=[]; URL.createObjectURL=(b)=>{window.demoBlobs.push(b.text());return 'blob:fixture';}; HTMLAnchorElement.prototype.click=function(){window.demoDownloads.push(this.download);};`);
 await click('#exp-json');
 const json=JSON.parse(await run(`window.demoBlobs[0]`));
 check(json.simulated===true && json.mode==='dir','JSON marks simulation');
 check(await run(`window.demoDownloads[0].startsWith('demo-')`),'Demo filename');
 await click('#exp-csv'); const csv=await run(`window.demoBlobs[1]`);
 check(csv.includes('simulated') && csv.includes('"true"'),'CSV marks simulation');
 await run(`document.getElementById('filter').value='no-match-fixture';document.getElementById('filter').dispatchEvent(new Event('input'));`);
 check((await text('tbody')).includes('暂无结果'),'Filter works');
 await run(`document.getElementById('filter').value='';document.getElementById('filter').dispatchEvent(new Event('input'));`);
 await click('[data-view="hosts"]');
 check((await text('hosts')).includes('simulated'),'Host card is marked simulated');
 await click('[data-view="table"]'); await click('[data-mode="tool"]'); await sleep(300);
 check((await text('cmd-preview')).includes('离线演示'),'Tool preview is offline');
 check(await run(`document.getElementById('t-tool').options.length === 7`),'Tools work without installed binaries');
 for (const id of ['arp-scan','gobuster','whatweb','wpscan','joomscan','droopescan','nikto']) {
  await run(`document.getElementById('t-tool').value=${JSON.stringify(id)};document.getElementById('t-tool').dispatchEvent(new Event('change'));`); await sleep(230);
  check((await text('cmd-preview')).includes(`"tool": "${id}"`), `Preview tool ${id}`);
 }
 await click('#btn-start'); await waitFor(`document.getElementById('st-status').textContent === '演示完成'`);
 check((await text('log')).includes('未启动进程'),'Tool log explicitly does not run processes');
 await shot('tool-demo.png');
 await send('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:true}); await sleep(200);
 check(await run(`document.documentElement.scrollWidth <= window.innerWidth`),'Mobile page has no horizontal overflow');
 await shot('mobile-demo.png');
 await send('Page.navigate',{url:base+'/?offline=1'});
 await waitFor(`document.getElementById('env')?.textContent.includes('环境检测失败')`);
 await click('[data-mode="tool"]'); await click('#btn-start');
 await waitFor(`document.getElementById('st-status').textContent === '演示完成'`);
 check((await text('log')).includes('未启动进程'),'Demo works when environment API is unavailable');
 check(requests.filter(r=>r.path.startsWith('/api/')).every(r=>r.path==='/api/info' && r.method==='GET'),'No preview, scan, stop, or SSE API calls');
 check(network.every(url=>url.startsWith(base)),'Page sends no requests outside local fixture');
 check(errors.length===0,`No JavaScript exceptions: ${errors}`);
 fs.writeFileSync(path.join(out,'ui-results.json'), JSON.stringify({checks,requests,errors,externalRequests:network.filter(url=>!url.startsWith(base)),screenshots:['directory-demo.png','tool-demo.png','mobile-demo.png']},null,2));
 console.log(`PASS: ${checks} UI checks. Results: ${out}`);
})().catch(e=>{console.error(e); process.exitCode=1;}).finally(async()=>{
 if(ws) ws.close();
 if(chrome) {chrome.kill('SIGTERM'); await Promise.race([once(chrome,'exit'), sleep(3000)]);}
 if(server) server.closeAllConnections();
 if(server) server.close();
 fs.rmSync(profile,{recursive:true,force:true});
});
