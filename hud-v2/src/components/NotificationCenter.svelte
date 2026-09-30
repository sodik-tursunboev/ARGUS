<script lang="ts">
  import { createEventDispatcher } from 'svelte'; import { notifications, unreadNotifications, markNotificationsRead, type NoticePage } from '../stores/notifications';
  const dispatch=createEventDispatcher<{navigate:NoticePage}>(); const stamp=(time:number)=>new Date(time).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});
  let open=false;
  function go(page:NoticePage){markNotificationsRead();dispatch('navigate',page);open=false;}
</script>
<details class="notification-center" bind:open><summary aria-label="Open notifications">NOTICES{#if $unreadNotifications}<b>{$unreadNotifications}</b>{/if}</summary><div class="notice-popover"><header><span>RECENT ACTIVITY</span><button on:click={markNotificationsRead}>MARK READ</button></header>{#if $notifications.length}{#each $notifications as notice (notice.id)}<button class:warning={notice.severity==='warning'} class:critical={notice.severity==='critical'} on:click={()=>go(notice.page)}><time>{stamp(notice.timestamp)}</time><b>{notice.category}</b><span>{notice.message}</span></button>{/each}{:else}<p>NO RECENT EVENTS</p>{/if}</div></details>
