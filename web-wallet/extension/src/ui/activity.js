// Web wallet src/app.js:945; approved plan §3.5 sends only trusted-interface activity to the background alarm.
export function bindActivity(document, client, onActivity = () => {}, onError = () => {}) {
  const activity = () => { onActivity(); void client.request('setLastActiveTime').catch(onError); };
  const types = ['pointerdown', 'keydown', 'input'];
  for (const type of types) document.addEventListener(type, activity);
  return () => { for (const type of types) document.removeEventListener(type, activity); };
}
