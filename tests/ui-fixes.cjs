const {chromium}=require('playwright');
const fs=require('node:fs');
const assert=require('node:assert/strict');
const base=process.env.HONEYFORGE_UI_URL||'http://127.0.0.1:8765';
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
(async()=>{
  const browser=await chromium.launch({headless:true,executablePath:process.env.BROWSER_PATH||['G:/Program Files/Google/Chrome/Application/chrome.exe','C:/Program Files/Google/Chrome/Application/chrome.exe'].find(fs.existsSync)});
  const page=await browser.newPage({viewport:{width:1440,height:1000},locale:'ru-RU'});
  const errors=[],requests=[]; let passwordPosts=0;
  page.on('pageerror',error=>errors.push(error.message));
  const pots=[{id:'pot-a',name:'Demo low',description:'',tags:['demo'],service_key:'tcp-banner',interaction_level:'low',
    status:'failed',error:'Listener failed',generation:1,profile_name:'TCP',profile_version:1,host_id:'lab-docker',host_name:'Lab',
    endpoint:{address:'hp-a:8022',alias:'hp-a',port:8022},event_count:2,created_at:'2026-10-14',last_seen:null},
    {id:'pot-b',name:'Web test',description:'',tags:[],service_key:'http-admin',interaction_level:'medium',status:'running',error:null,
    generation:1,profile_name:'HTTP',profile_version:1,host_id:'lab-docker',host_name:'Lab',endpoint:{address:'hp-b:8080',alias:'hp-b',port:8080},event_count:1,last_seen:null}];
  const services=[['tcp-banner','TCP-сервис с баннером','low'],['http-admin','HTTP-панель администратора','medium']].map(([key,display_name,interaction_level])=>
    ({key,display_name,interaction_level,protocol:'TCP',description:'Описание сервиса',default_port:8022,event_types:['connection'],capabilities:['Настройка'],fields:['banner'],runtime:{memory_mb:128,cpu_limit:.5,containers:2},health_check:'Проверка состояния'}));
  await page.addInitScript(()=>{window.WebSocket=class {constructor(){setTimeout(()=>this.onopen?.(),10);}close(){}};});
  await page.route('**/api/v1/**',async route=>{
    const req=route.request(),url=new URL(req.url()),path=url.pathname.replace('/api/v1',''); requests.push(url.pathname+url.search);
    let data;
    if(path==='/auth/me')data={id:'ui-user',username:'speaker',role:'administrator'};
    else if(path==='/settings')data={version:'2.8-test',mode:'development-preview'};
    else if(path==='/profiles'||path==='/users')data=[];
    else if(path==='/honeypots')data=pots;
    else if(path==='/hosts')data=[{id:'lab-docker',name:'Lab'}];
    else if(path==='/service-types')data=services;
    else if(path==='/alerts/summary')data={open:12,acknowledged:3,resolved:9,total:24,enabled_rules:1};
    else if(path==='/alerts/rules')data=[{id:'rule',name:'Проверка входов',event_type:'authentication_attempt',threshold:3,window_seconds:60,severity:'high',enabled:true}];
    else if(path==='/alerts')data=[{id:'alert',honeypot_id:'pot-a',triggered_at:new Date().toISOString(),severity:'high',status:'open',details:{rule:'Проверка входов',count:3,window_seconds:60}}];
    else if(path==='/events')data={total:1,page:1,page_size:50,items:[{id:1,timestamp:new Date().toISOString(),honeypot_id:'pot-a',source_ip:'192.0.2.1',source_port:1234,destination_port:8022,session_id:'session',protocol:'TCP',event_type:'data_received',severity:'medium',payload:{summary:'Shell command',input_preview:'uname -a'}}]};
    else if(path==='/auth/password'){passwordPosts++;data={ok:true};}
    else data={};
    await route.fulfill({json:data});
  });
  const open=async name=>{await page.goto(base+'/#'+name);await page.locator('#content h1').waitFor();};
  try{
    await open('honeypots');
    await page.locator('[data-action="danger-options"]').click();
    await page.getByRole('button',{name:'Просто закрыть',exact:true}).click();
    assert(await page.locator('#danger-strip').isHidden());
    await page.locator('[name=q]').fill('Web');await sleep(500);
    assert.equal(await page.locator('tbody tr').count(),1);
    assert.match(await page.locator('tbody').innerText(),/Web test/);
    assert(await page.locator('#danger-strip').isHidden());
    await page.reload();await page.locator('[data-action="danger-options"]').waitFor();
    await page.locator('[data-action="danger-options"]').click();
    await page.getByRole('button',{name:'Больше не показывать',exact:true}).click();
    await page.reload();await page.locator('#inventory-filters').waitFor();
    assert(await page.locator('#danger-strip').isHidden());
    await page.locator('[data-filter-set=status] summary').click();
    await page.locator('input[name=status][value=failed]').check();await sleep(300);
    assert.equal(await page.locator('tbody tr').count(),1);
    assert.match(await page.locator('tbody').innerText(),/Demo low/);
    await page.locator('input[name=status][value=running]').check();await sleep(300);
    assert.equal(await page.locator('tbody tr').count(),2);
    await page.locator('[data-action="inventory-reset"]').click();
    assert.equal(await page.locator('input[name=status]:checked').count(),0);
    await open('catalog');
    const card=page.locator('.catalog-service').first();
    assert.equal(await card.getAttribute('open'),null);
    await card.locator('summary').click();assert.notEqual(await card.getAttribute('open'),null);
    await page.reload();await page.locator('.catalog-service[open]').waitFor();
    await page.locator('.crumb a').click();await page.locator('.section-link').first().waitFor();
    assert.equal(await page.locator('.section-link').count(),4);
    const toggle=page.locator('[data-nav-group=monitoring] .nav-group-toggle');
    await toggle.click();assert.equal(await toggle.getAttribute('aria-expanded'),'false');
    await page.reload();await page.locator('[data-nav-group=monitoring] .nav-group-toggle[aria-expanded=false]').waitFor();
    await open('settings');
    await page.locator('[name=current_password]').fill('Current-password-123');
    await page.locator('[name=new_password]').fill('New-password-12345');
    await page.locator('[name=confirm_password]').fill('Different-password-123');
    await page.locator('#password-form button.secondary').click();
    assert.equal(passwordPosts,0);
    assert.equal(await page.locator('[name=confirm_password]').evaluate(node=>node.validity.valid),false);
    const eye=page.locator('.password-input').filter({has:page.locator('[name=new_password]')}).locator('button');
    await eye.click();assert.equal(await page.locator('[name=new_password]').getAttribute('type'),'text');
    await eye.click();assert.equal(await page.locator('[name=new_password]').getAttribute('type'),'password');
    const right=page.locator('.settings-layout > div').nth(1);
    const panels=await right.locator(':scope > .panel').evaluateAll(nodes=>nodes.map(node=>({top:node.getBoundingClientRect().top,bottom:node.getBoundingClientRect().bottom})));
    assert(panels[1].top-panels[0].bottom<35,'No large gap between interface and system settings');
    fs.mkdirSync('artifacts/ui-fixes',{recursive:true});
    await page.screenshot({path:'artifacts/ui-fixes/settings-desktop.png',fullPage:true});
    await open('events');
    await page.locator('[name=event_type]').selectOption('data_received');await sleep(300);
    assert(requests.some(url=>url.includes('event_type=data_received')));
    assert.equal(await page.getByRole('button',{name:'Применить фильтры'}).count(),0);
    assert((await page.locator('.event-description').boundingBox()).width<500);
    await page.screenshot({path:'artifacts/ui-fixes/events-desktop.png',fullPage:true});
    await open('alerts');
    assert.deepEqual(await page.locator('.tiles .tile strong').allTextContents(),['12','3','9']);
    for(const name of ['honeypots','catalog','settings','events']){
      await page.setViewportSize({width:390,height:844});await open(name);
      assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),name+' must fit a phone');
    }
    await page.screenshot({path:'artifacts/ui-fixes/events-mobile.png',fullPage:true});
    assert.deepEqual(errors,[]);
    console.log('UI FIXES PASS: dismiss/reload, search and checkbox filters, catalog, breadcrumbs, groups, password validation/visibility, spacing, global alert counts, mobile.');
  }catch(error){fs.mkdirSync('artifacts/ui-fixes',{recursive:true});await page.screenshot({path:'artifacts/ui-fixes/failure.png',fullPage:true});throw error;}
  finally{await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
