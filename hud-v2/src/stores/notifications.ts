import { writable } from 'svelte/store';
import { secret } from './events';

export type NoticePage = 'dashboard'|'tasks'|'agents'|'modules'|'security'|'authentication'|'logs'|'tools'|'settings';
export type Notice = { id:string; category:string; message:string; severity:'info'|'warning'|'critical'; timestamp:number; page:NoticePage; read:boolean };
const limit = 30; let sequence = 0;
export const notifications = writable<Notice[]>([]);
export const unreadNotifications = writable(0);
function updateUnread(rows: Notice[]){ unreadNotifications.set(rows.filter((row)=>!row.read).length); }
export function notify(category:string, message:unknown, severity:Notice['severity']='info', page:NoticePage='dashboard'){
  if(typeof message !== 'string' || secret.test(message)) return;
  const clean=message.replace(/[\r\n\t]+/g,' ').trim().slice(0,160); if(!clean) return;
  const now=Date.now();
  notifications.update((rows)=>{
    const recent=rows[0];
    if(recent && recent.category===category && recent.message===clean && now-recent.timestamp<5000) return rows;
    const next=[{id:`${now}:${sequence++}`,category,message:clean,severity,timestamp:now,page,read:false},...rows].slice(0,limit);
    updateUnread(next); return next;
  });
}
export function markNotificationsRead(){ notifications.update((rows)=>{const next=rows.map((row)=>({...row,read:true})); updateUnread(next); return next;}); }
