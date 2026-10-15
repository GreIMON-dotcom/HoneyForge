const fs=require('node:fs');
const acorn=require('acorn');
const result=[];
const displayArguments={button:[0],heading:[0,1],panel:[0],empty:[0],toast:[0],openDialog:[0],formField:[1],selectField:[1],checkField:[1],confirm:[0],Error:[0]};
for(const file of fs.readdirSync('frontend').filter(p=>p.endsWith('.js'))){
 const source=fs.readFileSync('frontend/'+file,'utf8');
 const tree=acorn.parse(source,{ecmaVersion:'latest',sourceType:'module',locations:true});
 const add=(node,text,kind)=>{if(/[A-Za-z]{2,}/.test(text)&&!/[А-Яа-яЁё]/.test(text))result.push({file:'frontend/'+file,line:node.loc.start.line,text,kind});};
 function html(node,text){
  for(const match of text.matchAll(/>([^<>]+)</g)){const value=match[1].trim();if(value&&!value.includes('${'))add(node,value,'html');}
  for(const match of text.matchAll(/(?:aria-label|title|placeholder)=["']([^"']+)["']/g))if(!match[1].includes('${'))add(node,match[1],'attribute');
 }
 function walk(node){
  if(!node||typeof node!=='object')return;
  if(['CallExpression','NewExpression'].includes(node.type)){
   const name=node.callee?.name;
   for(const index of displayArguments[name]||[]){const argument=node.arguments[index];if(argument?.type==='Literal'&&typeof argument.value==='string')add(argument,argument.value,'display argument');}
  }
  if(node.type==='Literal'&&typeof node.value==='string'&&node.value.includes('<'))html(node,node.value);
  if(node.type==='TemplateElement')html(node,node.value.raw);
  if(node.type==='AssignmentExpression'&&['textContent','innerText','title'].includes(node.left?.property?.name)&&node.right.type==='Literal')add(node,node.right.value,'text assignment');
  for(const [key,value]of Object.entries(node))if(!['loc','start','end'].includes(key)){if(Array.isArray(value))value.forEach(walk);else if(value&&typeof value==='object')walk(value);}
 }
 walk(tree);
}
process.stdout.write(JSON.stringify(result));
