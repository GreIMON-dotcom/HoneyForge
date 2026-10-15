const {chromium}=require('playwright');
const fs=require('node:fs');
const crypto=require('node:crypto');
const assert=require('node:assert/strict');
(async()=>{
 const env=Object.fromEntries(fs.readFileSync('.env','utf8').split(/\r?\n/).filter(l=>l.includes('=')).map(l=>{const i=l.indexOf('=');return[l.slice(0,i),l.slice(i+1)];}));
 const cert=new crypto.X509Certificate(fs.readFileSync('infrastructure/certs/server.crt'));
 const pin=crypto.createHash('sha256').update(cert.publicKey.export({type:'spki',format:'der'})).digest('base64');
 const browser=await chromium.launch({headless:true,executablePath:process.env.BROWSER_PATH||['G:/Program Files/Google/Chrome/Application/chrome.exe','C:/Program Files/Google/Chrome/Application/chrome.exe'].find(fs.existsSync),args:['--ignore-certificate-errors-spki-list='+pin]});
 const page=await browser.newPage({viewport:{width:1440,height:1000},locale:'en-US',timezoneId:'Europe/Moscow'});
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 const report={pages:[],allowedData:[],untranslated:[]};
 const directory='artifacts/ru-ui';fs.mkdirSync(directory,{recursive:true});
 try{
  await page.goto('https://localhost:8443');
  assert.equal(await page.locator('html').getAttribute('lang'),'ru');
  await page.getByLabel('Имя пользователя',{exact:true}).fill(env.ADMIN_USERNAME);
  await page.getByLabel('Пароль',{exact:true}).fill('incorrect-lab-password');
  await page.getByRole('button',{name:'Войти →'}).click();
  await page.getByText('Неверное имя пользователя или пароль',{exact:true}).waitFor();
  await page.screenshot({path:directory+'/login.png',fullPage:true});
  await page.getByLabel('Пароль',{exact:true}).fill(env.ADMIN_PASSWORD);
  await page.getByRole('button',{name:'Войти →'}).click();
  await page.getByRole('heading',{name:'Панель управления',exact:true}).waitFor();
  const stored=await page.evaluate(async()=>{
   const strings=[];
   for(const path of ['/profiles','/honeypots','/hosts','/alerts/rules','/users','/events?page_size=200','/alerts','/audit']){
    const data=await (await fetch('/api/v1'+path)).json();
    const visit=(v,k)=>{if(typeof v==='string'&&['name','description','username','summary','identity','banner','status_message','rule','actor','resource','management_address','id','host_id'].includes(k))strings.push(v);else if(v&&typeof v==='object')Object.entries(v).forEach(([key,item])=>visit(item,key));};visit(data,'');
   }
   return strings;
  });
  report.allowedData=[...new Set(stored)].filter(v=>/[a-z]/i.test(v)).map(text=>({text,reason:'Сохранённые имена, идентификаторы или исходная телеметрия; автоматический перевод запрещён.'}));
  const allowed=[...new Set(stored),env.ADMIN_USERNAME,'HoneyForge','CN=HoneyForge Local Lab CA','agent:low','agent:medium','controller:lab-docker','lab-docker','decoy','honeyforge:local'];
  async function inspect(name){
   const nodes=await page.locator('body').evaluate(body=>{
    const walker=document.createTreeWalker(body,NodeFilter.SHOW_TEXT);const texts=[];
    while(walker.nextNode()){const node=walker.currentNode;const parent=node.parentElement;if(parent&&parent.getClientRects().length&&!parent.closest('pre,script,style,code')&&node.textContent.trim())texts.push(node.textContent.trim());}return texts;
   });
   for(const text of nodes){
    let rest=text.replace(/^(GET|POST|PATCH|DELETE|PUT) \/[^ ]+/, '');
    for(const value of allowed.sort((a,b)=>b.length-a.length))if(value)rest=rest.split(value).join('');
    rest=rest.replace(/\b(?:https?:\/\/[^\s]+|[0-9a-f]{8}(?:-[0-9a-f-]+)?|v\d+(?:\.\d+)*|TCP|HTTP|HTTPS|TLS|CPU|SQLite|Docker|GET|POST|Compose|WebSocket|PostgreSQL|API|OpenAPI|CSV|JSON|UUID|IP|CA|Origin|CSRF|SSH|HttpOnly|Bearer|cookie|low|medium)\b/gi,'');
    if(/[A-Za-z]{2,}/.test(rest))report.untranslated.push({page:name,text});
   }
   assert(!nodes.some(text=>text.includes('Текст недоступен')||text.includes('undefined')),'Unresolved UI text on '+name);
  }
  const sections=[['dashboard','Панель управления','Панель управления'],['honeypots','Ловушки','Управление ловушками'],['constructor','Конструктор ловушек','Конструктор ловушек'],['profiles','Профили','Конструктор профилей'],['catalog','Каталог сервисов','Каталог сервисов'],['events','События','События в реальном времени'],['analytics','Аналитика','Аналитика'],['alerts','Оповещения','Оповещения'],['deployments','Развёртывание','Управление развёртыванием'],['resources','Ресурсы лаборатории','Ресурсы лаборатории'],['audit','Журнал аудита','Журнал аудита'],['settings','Настройки','Настройки']];
  for(const [id,link,title] of sections){
   await page.getByRole('link',{name:link,exact:true}).click();await page.getByRole('heading',{name:title,exact:true}).waitFor();
   assert.equal(await page.locator('.error-banner').count(),0);
   await inspect(id);
   for(const [width,height,label]of [[1440,1000,'desktop'],[768,1024,'tablet'],[390,844,'narrow']]){
    await page.setViewportSize({width,height});
    assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),id+' horizontal page overflow at '+width);
    const top=await page.locator('.topbar').boundingBox();const user=await page.locator('.user-button').boundingBox();
    assert(user.y>=top.y&&user.y+user.height<=top.y+top.height+1,'Header clips the user menu');
    await page.screenshot({path:`${directory}/${id}-${label}.png`,fullPage:true});
   }
   report.pages.push(id);await page.setViewportSize({width:1440,height:1000});
   const modalAction={resources:'Изменить политику',settings:'+ Добавить пользователя',alerts:'+ Создать правило'}[id];
   if(modalAction){
    await page.getByRole('button',{name:modalAction,exact:true}).first().click();
    await page.getByRole('dialog').waitFor();await inspect(id+'-dialog');
    for(const [width,label]of [[1440,'desktop'],[768,'tablet']]){await page.setViewportSize({width,height:1000});await page.screenshot({path:`${directory}/${id}-dialog-${label}.png`,fullPage:true});}
    await page.getByRole('button',{name:'Закрыть',exact:true}).click();await page.setViewportSize({width:1440,height:1000});
   }
  }
  await page.getByRole('link',{name:'Профили',exact:true}).click();
  await page.getByRole('button',{name:'+ Создать профиль'}).click();
  await page.getByRole('button',{name:'Сохранить профиль'}).click();
  assert.equal(await page.getByLabel('Название профиля',{exact:true}).evaluate(e=>e.validationMessage),'Заполните это поле.');
  const name='Тестовый HTTP-сервер «Ёж» '+Date.now();
  await page.getByLabel('Название профиля',{exact:true}).fill(name);
  await page.getByLabel('Описание',{exact:true}).fill('Профиль для обнаружения подключений <img src=x onerror=alert(1)>');
  await page.getByLabel('Тип сервиса',{exact:true}).selectOption('http-admin');
  await page.getByLabel('Название профиля',{exact:true}).fill(name);
  await page.getByLabel('Описание',{exact:true}).fill('Профиль для обнаружения подключений <img src=x onerror=alert(1)>');
  await page.getByLabel('Порт сервиса по умолчанию',{exact:true}).fill('18080');
  await inspect('profile-form');
  await page.screenshot({path:directory+'/profile-form-desktop.png',fullPage:true});
  await page.setViewportSize({width:768,height:1024});await page.screenshot({path:directory+'/profile-form-tablet.png',fullPage:true});
  await page.getByRole('button',{name:'Сохранить профиль'}).click();
  await page.getByRole('row').filter({hasText:name}).waitFor();await page.reload();
  const row=page.getByRole('row').filter({hasText:name});await row.waitFor();
  assert.equal(await row.locator('img').count(),0,'User input was interpreted as HTML');
  await row.getByRole('button',{name:'Изменить',exact:true}).click();
  assert.equal(await page.getByLabel('Описание',{exact:true}).inputValue(),'Профиль для обнаружения подключений <img src=x onerror=alert(1)>');
  await page.getByRole('button',{name:'Закрыть',exact:true}).click();
  page.once('dialog',dialog=>dialog.accept());await row.getByRole('button',{name:'Удалить',exact:true}).click();await row.waitFor({state:'hidden'});
  await page.goto('https://localhost:8443/docs');await page.getByText('Общие схемы данных',{exact:true}).waitFor();await inspect('api-docs');await page.screenshot({path:directory+'/api-docs.png',fullPage:true});
  assert.deepEqual(errors,[]);
  assert.deepEqual(report.untranslated,[],'Unexplained visible Latin text; inspect report');
  console.log('УСПЕШНО: двенадцать разделов, 3 размера окна, русский вход и валидация, кириллица после обновления, экранирование и справочник API.');
 }finally{fs.writeFileSync(directory+'/report.json',JSON.stringify(report,null,2));await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
