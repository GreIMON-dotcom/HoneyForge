export const locale = 'ru-RU';
const numbers = new Intl.NumberFormat(locale);
const dates = new Intl.DateTimeFormat(locale, {year:'numeric', month:'2-digit', day:'2-digit', hour:'2-digit', minute:'2-digit', second:'2-digit', hour12:false});
const plurals = new Intl.PluralRules(locale);
const relatives = new Intl.RelativeTimeFormat(locale, {numeric:'auto'});
export const formatNumber = value => numbers.format(Number(value));
export const formatDate = value => value && !Number.isNaN(new Date(value).getTime()) ? dates.format(new Date(value)) : '—';
export function relativeTime(value, now=Date.now()) {
  if(!value)return '—';
  const seconds=(new Date(value).getTime()-now)/1000;
  if(!Number.isFinite(seconds))return '—';
  if(Math.abs(seconds)<45)return 'Только что';
  const [unit,size]=Math.abs(seconds)<3600?['minute',60]:Math.abs(seconds)<86400?['hour',3600]:['day',86400];
  return relatives.format(Math.round(seconds/size),unit);
}
export function createTranslator(dictionary, {debug=false, onMissing=console.warn}={}) {
  const lookup = key => key.split('.').reduce((value,part)=>value && Object.hasOwn(value,part)?value[part]:undefined,dictionary);
  function t(key,parameters={}) {
    const value=lookup(key);
    if(typeof value!=='string') {
      if(debug)onMissing('Missing translation: '+key);
      return 'Текст недоступен';
    }
    return value.replace(/\{([a-zA-Z0-9_]+)\}/g,(_,name)=>Object.hasOwn(parameters,name)?String(parameters[name]):'—');
  }
  function plural(key,count) {
    return t(key+'.'+plurals.select(Number(count)),{count:formatNumber(count)});
  }
  function label(category,value) {
    if(value===null||value===undefined||value==='')return '—';
    const group=lookup('labels.'+category);
    return group && Object.hasOwn(group,String(value)) ? group[String(value)] : t('common.unknown');
  }
  return {t,plural,label,has:key=>lookup(key)!==undefined};
}
