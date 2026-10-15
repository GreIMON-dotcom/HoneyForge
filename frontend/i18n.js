import {createTranslator} from './i18n-core.js';
export {formatDate, formatNumber, relativeTime} from './i18n-core.js';
const response=await fetch(new URL('./locales/ru.json',import.meta.url));
if(!response.ok)throw new Error('Не удалось загрузить перевод интерфейса. Обновите страницу.');
const dictionary=await response.json();
export const {t,plural,label,has}=createTranslator(dictionary,{debug:document.documentElement.dataset.i18nDebug==='true'});
export function safeError(error) {
  const text=typeof error==='string'?error:error?.message;
  return typeof text==='string' && /[А-Яа-яЁё]/.test(text) ? text : t('errors.unexpected');
}
