import {t} from './i18n.js';
const target=document.querySelector('#reference');
const response=await fetch('/openapi.json');
if(!response.ok){target.textContent=t('apiDocs.loadError');}else{
 const spec=await response.json();target.textContent='';
 for(const[path,methods]of Object.entries(spec.paths)){
  for(const[method,operation]of Object.entries(methods)){
   const details=document.createElement('details');details.className='panel';
   const summary=document.createElement('summary');summary.className='panel-head';summary.textContent=`${method.toUpperCase()} ${path} · ${operation.summary||''}`;
   const pre=document.createElement('pre');pre.textContent=JSON.stringify(operation,null,2);details.append(summary,pre);target.append(details);
  }
 }
 const heading=document.createElement('h2');heading.textContent=t('apiDocs.schemas');const pre=document.createElement('pre');pre.textContent=JSON.stringify(spec.components?.schemas,null,2);target.append(heading,pre);
}
