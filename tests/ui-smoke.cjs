const {chromium}=require('playwright');
const fs=require('node:fs');
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const {execFile}=require('node:child_process');
const {promisify}=require('node:util');
const run=promisify(execFile);

async function wizard(page){
  const name='Проверка мастера '+Date.now();
  const next=()=>page.getByRole('button',{name:'Далее →',exact:true}).click();
  await page.getByRole('link',{name:'Конструктор ловушек'}).click();
  await page.getByRole('heading',{name:'Конструктор ловушек',exact:true}).waitFor();
  await page.getByLabel('Тип сервиса',{exact:true}).selectOption('http-site');
  await page.getByLabel('Название ловушки',{exact:true}).fill(name);
  await page.getByLabel('Название нового профиля',{exact:true}).fill('Профиль '+name);
  await next();
  await page.getByLabel('Название сайта',{exact:true}).fill('Портал <b>проверки</b>');
  await page.getByRole('button',{name:'+ Добавить компонент',exact:true}).first().click();
  assert.equal(await page.getByLabel('Название сайта',{exact:true}).inputValue(),'Портал <b>проверки</b>');
  await next();
  await page.getByRole('button',{name:'Проверить точку подключения',exact:true}).click();
  await page.getByText(/Точка подключения доступна: порт \d+\./).waitFor();
  await next();
  await page.getByText('Бюджет узла',{exact:false}).waitFor();
  await next();
  await page.getByText('Создать правило оповещения для этой ловушки',{exact:true}).click();
  await next();
  await page.getByText('Конфигурация прошла проверку сервера',{exact:false}).waitFor();
  await next();
  await page.getByRole('button',{name:'Создать и развернуть',exact:true}).click();
  await page.getByRole('heading',{name,exact:true}).waitFor();
  await page.getByText('Работает',{exact:true}).first().waitFor({timeout:120000});
  await page.getByText('Синхронизировано',{exact:true}).waitFor({timeout:30000});
  const address=(await page.locator('.mono',{hasText:/^hp-[0-9a-f]{8}:\d+$/}).first().innerText()).split(':');
  await run('docker',['compose','--profile','demo','run','--rm','test-client','http',address[0],address[1]],{timeout:90000});
  await page.locator('[data-action="event"]').first().waitFor({timeout:60000});
  const served=(await run('docker',['compose','--profile','demo','run','--rm','--entrypoint','python','test-client','-c',
    `import urllib.request;print(urllib.request.urlopen('http://${address[0]}:${address[1]}/',timeout=5).read().decode())`],{timeout:90000})).stdout;
  assert(served.includes('Портал &lt;b&gt;проверки&lt;/b&gt;')&&!served.includes('<b>проверки'),'Decoy page must escape operator text');
  page.once('dialog',dialog=>dialog.accept());
  await page.getByRole('button',{name:'Остановить',exact:true}).click();
  await page.getByText('Остановлена',{exact:true}).first().waitFor({timeout:60000});
  page.once('dialog',dialog=>dialog.accept());
  await page.getByRole('button',{name:'Удалить экземпляр',exact:true}).click();
  await page.getByRole('heading',{name:'Управление ловушками',exact:true}).waitFor({timeout:60000});
  await page.getByRole('row').filter({hasText:name}).waitFor({state:'hidden',timeout:60000});
  console.log('UI PASS: wizard created, deployed, probed and deleted a real instance; events appeared without reload.');
}

(async()=>{
  const env=Object.fromEntries(fs.readFileSync('.env','utf8').split(/\r?\n/).filter(l=>l.includes('=')).map(l=>{const i=l.indexOf('=');return[l.slice(0,i),l.slice(i+1)];}));
  const baseURL=process.env.HONEYFORGE_UI_URL||'http://127.0.0.1:8765';
  const args=[];
  if(baseURL==='https://localhost:8443'){
    const certificate=new crypto.X509Certificate(fs.readFileSync('infrastructure/certs/server.crt'));
    const pin=crypto.createHash('sha256').update(certificate.publicKey.export({type:'spki',format:'der'})).digest('base64');
    args.push('--ignore-certificate-errors-spki-list='+pin);
  }
  const browser=await chromium.launch({headless:true,args,executablePath:process.env.BROWSER_PATH||['G:/Program Files/Google/Chrome/Application/chrome.exe','C:/Program Files/Google/Chrome/Application/chrome.exe'].find(fs.existsSync)});
  const errors=[];
  const page=await browser.newPage({viewport:{width:1440,height:1000},locale:'en-US',timezoneId:'Europe/Moscow'});
  page.on('pageerror',e=>errors.push(e.message));
  try{
    await page.goto(baseURL);
    await page.getByLabel('Имя пользователя',{exact:true}).fill(env.ADMIN_USERNAME);
    await page.getByLabel('Пароль',{exact:true}).fill(env.ADMIN_PASSWORD);
    await page.getByRole('button',{name:'Войти →'}).click();
    await page.getByRole('heading',{name:'Панель управления'}).waitFor();
    await page.getByText('Соединение активно',{exact:true}).waitFor();
    await fs.promises.mkdir('artifacts',{recursive:true});
    await page.screenshot({path:'artifacts/dashboard-desktop.png',fullPage:true});
    if(process.env.HONEYFORGE_COMPOSE_UI==='1'){
      assert.equal(baseURL,'https://localhost:8443');
      await wizard(page);
    }
    await page.getByRole('link',{name:'Профили',exact:true}).click();
    await page.getByRole('button',{name:'+ Создать профиль'}).click();
    const profileName='Проверка интерфейса '+Date.now();
    await page.getByLabel('Название профиля',{exact:true}).fill(profileName);
    await page.getByLabel('Описание',{exact:true}).fill('Профиль для проверки кириллицы');
    await page.getByRole('button',{name:'Сохранить профиль',exact:true}).click();
    await page.getByRole('cell',{name:profileName+' Профиль для проверки кириллицы',exact:true}).waitFor();
    const row=page.getByRole('row').filter({hasText:profileName});
    await row.getByRole('button',{name:'Изменить',exact:true}).click();
    await page.getByLabel('Баннер TCP-сервиса').fill('SSH-2.0-UI_Verified');
    await page.getByRole('button',{name:'Сохранить профиль',exact:true}).click();
    await row.getByRole('cell',{name:'v2',exact:true}).waitFor();
    page.once('dialog',dialog=>dialog.accept());
    await row.getByRole('button',{name:'Удалить',exact:true}).click();
    await row.waitFor({state:'hidden'});
    await page.getByRole('link',{name:'События',exact:true}).click();
    await page.getByLabel('IP-адрес источника',{exact:true}).fill('192.0.2.10');
    await page.waitForResponse(response=>response.url().includes('/events?') && response.url().includes('source_ip=192.0.2.10'));
    await page.getByText('0 событий · страница 1 из 1').waitFor();
    await page.getByRole('link',{name:'Оповещения',exact:true}).click();
    await page.getByRole('button',{name:'+ Создать правило'}).click();
    await page.getByLabel('Название правила').fill('Правило проверки интерфейса '+Date.now());
    await page.getByRole('button',{name:'Сохранить правило'}).click();
    await page.getByRole('cell',{name:'Попытка аутентификации ≥ 10'}).first().waitFor();
    for(const [link,name] of [['Ловушки','Управление ловушками'],['Конструктор ловушек','Конструктор ловушек'],['Каталог сервисов','Каталог сервисов'],['Аналитика','Аналитика'],
        ['Развёртывание','Управление развёртыванием'],['Ресурсы лаборатории','Ресурсы лаборатории'],['Журнал аудита','Журнал аудита'],['Настройки','Настройки']]){
      await page.getByRole('link',{name:link,exact:true}).click();
      await page.getByRole('heading',{name,exact:true}).waitFor();
      assert.equal(await page.locator('.error-banner').count(),0);
    }
    await page.setViewportSize({width:768,height:1024});
    await page.getByRole('button',{name:'Открыть меню',exact:true}).click();
    await page.getByRole('link',{name:'Панель управления',exact:true}).click();
    await page.getByRole('heading',{name:'Панель управления'}).waitFor();
    await page.getByRole('heading',{name:'Сетевая активность'}).waitFor();
    await page.getByRole('heading',{name:'География угроз'}).waitFor();
    await page.screenshot({path:'artifacts/dashboard-tablet.png',fullPage:true});
    assert(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth));
    assert.deepEqual(errors,[]);
    await page.locator('.user-button').click();
    await page.getByRole('button',{name:'Выйти'}).click();
    await page.getByRole('heading',{name:'Вход в HoneyForge'}).waitFor();
    console.log('UI PASS: login, live connection, profile create/edit/delete, filters, alert rule, all twelve sections, tablet layout, logout; no JavaScript errors.');
  }catch(error){
    console.error('Browser diagnostics:',{url:page.url(),errors,body:(await page.locator('body').innerText()).slice(0,1500)});
    await page.screenshot({path:'artifacts/ui-failure.png',fullPage:true}).catch(()=>{});
    throw error;
  }finally{await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
