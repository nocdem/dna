// Nodus Connect groups — the screens (package G3): the Groups part of
// Chats (open invitations, group rows with unread counts, "New group"), a
// group's conversation (sender names, a banner when the group's protection
// is old or the group changed, the members with the owner's add / remove,
// Leave), and the New group dialog.
//
// HOST-DRIVEN, like src/connect/ui/messages.js, which owns the screens and
// hands over its building blocks (`h`, below). Rendering follows that file's
// rules (design rev 5 §1.9): every text through textContent; text written by
// someone else — a group name, a message, a member's name — through
// untrusted() (a <bdi> with the unusual-characters marker); no innerHTML.
// Plain words only: no technical terms on screen (CLAUDE.md, Flutter UI rule,
// followed by the Connect site).
//
// h: { engine(), isOpen(), online(), ownFp(), contacts() -> [{ fp, salt }],
//      el, button, untrusted, statusLine, input, setAttrs, icon, iconButton,
//      backButton(), nameTitle(fp), nameHint(fp), displayName(fp),
//      shortWhen(at), dayLabel(date), sameDay(a, b), explain(error, fallback),
//      openGroup(gid), render(opts) }
import { textProblem, nameProblem, MAX_MEMBERS, TEXT_MAX_BYTES, GroupError } from './model.js';

const OFFLINE_TEXT = 'This opens once Messages is connected to the network.';

export function createGroupsView(h) {
  const { el, button, untrusted, statusLine, input, setAttrs } = h;
  // The groups module's refusals are plain words; anything else gets the
  // screen's own (h.explain keeps the page's storage errors).
  const explain = (error, fallback) => (error instanceof GroupError ? error.message : h.explain(error, fallback));
  const u = {};
  let selected, removeArmed;

  // ── Chats: the Groups part ─────────────────────────────────────────────
  u.inviteList = setAttrs(el('ul', { className: 'request-list' }), { 'aria-label': 'Group invitations' });
  u.groupList = setAttrs(el('ul', { className: 'contact-list' }), { 'aria-label': 'Groups' });
  u.blockStatus = statusLine('hint');
  u.newButton = button('New group', () => openCreate(), 'secondary small');
  u.block = el('div', { className: 'nc-groups' },
    el('div', { className: 'nc-groups-head' }, el('h3', { text: 'Groups' }), u.newButton),
    u.inviteList, u.groupList, u.blockStatus);

  // ── a group's conversation ─────────────────────────────────────────────
  u.avatar = el('span');
  u.title = el('h2', { className: 'nc-bar-title' });
  u.title.tabIndex = -1;
  u.subtitle = el('span', { className: 'contact-claim' });
  u.head = el('div', { className: 'nc-bar conversation-head' }, h.backButton(), u.avatar, el('div', { className: 'conversation-title' }, u.title, u.subtitle));
  u.banner = el('p', { className: 'notice conversation-note' });
  u.memberList = el('ul', { className: 'request-list' });
  u.inviteSelect = input('select', { id: 'nc-group-invite', 'aria-label': 'Contact to invite' });
  u.inviteButton = button('Invite', () => void inviteSelected(), 'small');
  u.inviteRow = el('div', { className: 'request-actions' }, u.inviteSelect, u.inviteButton);
  u.membersStatus = statusLine();
  u.leaveButton = button('Leave group', () => void leaveSelected(), 'secondary small messenger-erase');
  u.members = el('details', { className: 'hint conversation-diag' }, el('summary', { text: 'Members' }), u.memberList, u.inviteRow, u.membersStatus, u.leaveButton);
  u.messageList = setAttrs(el('ol', { className: 'message-list' }), { 'aria-label': 'Group messages', 'aria-live': 'polite' });
  u.composer = input('textarea', { id: 'nc-group-text', rows: '1', maxlength: String(TEXT_MAX_BYTES), placeholder: 'Write to the group', 'aria-label': 'Group message', autocomplete: 'off' });
  u.sendButton = el('button', { className: 'composer-send' }); u.sendButton.type = 'submit';
  u.sendButton.setAttribute('aria-label', 'Send'); u.sendButton.title = 'Send';
  u.sendButton.append(h.icon('send'));
  u.sendStatus = statusLine('hint composer-status');
  u.form = el('form', { className: 'composer' }, el('div', { className: 'composer-row' }, u.composer, u.sendButton), u.sendStatus);
  u.closedNote = el('p', { className: 'hint composer-closed' });
  u.view = el('div', { className: 'messenger-view messenger-conversation messenger-group' }, u.head, u.banner, u.members, u.messageList, u.form, u.closedNote);
  u.view.hidden = true;
  u.form.onsubmit = event => void sendSelected(event);
  u.composer.addEventListener('keydown', event => {
    if (event.key !== 'Enter' || event.shiftKey || event.isComposing || event.keyCode === 229) return;
    event.preventDefault();
    u.form.requestSubmit();
  });

  // ── New group dialog ───────────────────────────────────────────────────
  u.dialogTitle = el('h2', { text: 'New group' });
  u.dialogTitle.id = 'nc-group-new-title';
  u.nameInput = input('input', { id: 'nc-group-name', type: 'text', maxlength: '64', autocomplete: 'off', required: '' });
  u.pickList = el('ul', { className: 'nc-group-pick' });
  u.createStatus = statusLine();
  const createSubmit = el('button', { text: 'Create group' }); createSubmit.type = 'submit';
  u.createForm = el('form', { className: 'messenger-form' },
    setAttrs(el('label', { text: 'Group name' }), { for: 'nc-group-name' }), u.nameInput,
    el('p', { className: 'hint', text: 'Choose contacts to invite. They join once they accept. A group can have up to 64 people, including you.' }),
    u.pickList, u.createStatus,
    el('div', { className: 'nc-dialog-actions' }, button('Close', () => u.dialog.close(), 'secondary'), createSubmit));
  u.dialog = setAttrs(el('dialog', { className: 'nc-dialog' }, u.dialogTitle, u.createForm), { 'aria-labelledby': 'nc-group-new-title' });
  u.createForm.onsubmit = event => void createGroup(event);

  // ── rendering ──────────────────────────────────────────────────────────
  function groupAvatar(name, gid, extra = '') {
    const node = el('span', { className: `contact-avatar avatar-${parseInt(gid[0], 16) % 6}${extra}` });
    node.setAttribute('aria-hidden', 'true');
    const letters = [...String(name || '').replace(/\s+/g, '')].slice(0, 2).join('').toUpperCase();
    node.textContent = letters || '#';
    return node;
  }
  function senderLabel(fp) { return fp === h.ownFp() ? 'You' : h.displayName(fp); }

  // The Groups part of Chats. `unreadOnly`: the Unread filter.
  function renderBlock({ unreadOnly = false } = {}) {
    const engine = h.engine();
    if (!engine) { u.block.hidden = true; return; }
    u.block.hidden = false;
    u.newButton.disabled = !h.online();
    const invites = engine.invitations();
    u.inviteList.replaceChildren(...invites.map(inv => el('li', { className: 'request-row' },
      groupAvatar(inv.name, inv.gid),
      el('div', { className: 'request-main' },
        el('span', { className: 'contact-name' }, el('span', { className: 'request-label', text: 'Group invitation' }), untrusted(inv.name || 'Unnamed group', undefined, { name: true })),
        el('span', { className: 'contact-claim' }, 'from ', h.nameTitle(inv.owner)),
        el('div', { className: 'request-actions' },
          button('Join', () => void acceptInvite(inv.gid), 'small'),
          button('Ignore', () => void ignoreInvite(inv.gid), 'secondary small'))))));
    u.inviteList.hidden = !invites.length;
    const rows = engine.list().filter(g => !unreadOnly || g.unread > 0)
      .map(g => ({ g, last: engine.lastMessage(g.gid) }))
      // most recent conversation first (local order), then groups without messages
      .sort((a, b) => {
        if (a.last && b.last) { const x = BigInt(a.last.seq), y = BigInt(b.last.seq); return x > y ? -1 : x < y ? 1 : 0; }
        return a.last ? -1 : b.last ? 1 : 0;
      });
    u.groupList.replaceChildren(...rows.map(({ g, last }) => {
      const row = el('button', { className: `contact-row${g.unread ? ' has-unread' : ''}` });
      row.type = 'button';
      row.dataset.gid = g.gid;
      row.setAttribute('aria-current', String(selected === g.gid));
      const preview = el('span', { className: 'contact-preview' });
      if (g.status === 'removed') preview.textContent = 'You are no longer in this group';
      else if (g.status === 'accepting' || g.status === 'joining') preview.textContent = 'Joining… waiting for the owner';
      else if (last) preview.append(`${senderLabel(last.fp)}: `, untrusted(last.text));
      else preview.textContent = g.ready ? 'No messages yet' : 'Setting up the group…';
      const side = el('span', { className: 'contact-side' });
      if (last) { const when = el('time', { text: h.shortWhen(last.at) }); when.dateTime = new Date(last.at).toISOString(); side.append(when); }
      if (g.unread) side.append(setAttrs(el('span', { className: 'count-badge', text: String(g.unread) }), { 'aria-label': `${g.unread} new` }));
      row.append(groupAvatar(g.name, g.gid), el('span', { className: 'contact-main' }, el('span', { className: 'contact-name' }, el('strong', {}, untrusted(g.name || 'Unnamed group', undefined, { name: true }))), preview), side, h.icon('chevron'));
      row.onclick = () => h.openGroup(g.gid);
      return el('li', {}, row);
    }));
    u.groupList.hidden = !rows.length;
  }
  function unreadTotal() {
    const engine = h.engine();
    return engine ? engine.list().reduce((sum, g) => sum + g.unread, 0) : 0;
  }

  function bannerText(g) {
    if (g.status === 'removed') return 'You are no longer in this group. Earlier messages stay on this device.';
    if (g.problem === 'taken') return 'This group\'s address on the network is held by someone else. The group cannot be changed.';
    if (g.problem === 'damaged') return 'This group could not be read from this device\'s storage. It cannot be changed here.';
    if (g.problem === 'member_key') return `${g.problemFp ? h.displayName(g.problemFp) : 'A member'} cannot receive the group's protection with their current app. Remove them to change the group.`;
    if (g.problem === 'conflict' || g.problem === 'stale') return 'This group was changed from another device. Changes made here wait; messages still work.';
    const parts = [];
    if (g.keyOld) parts.push(g.role === 'owner'
      ? 'The group\'s protection is over 30 days old; it is renewed automatically.'
      : 'The group\'s owner has not been online for over 30 days, so the group\'s protection has not been renewed. Messages still work.');
    if (g.refused.length) parts.push(`${g.refused.map(fp => h.displayName(fp)).join(', ')} could not join: their app cannot receive group messages yet.`);
    if (g.settingUp) parts.push('Updating the group on the network…');
    if (g.note) parts.push(g.note);
    return parts.join(' ');
  }

  function renderView({ scroll = false } = {}) {
    const engine = h.engine();
    const g = engine && selected ? engine.view(selected) : null;
    u.view.hidden = !g;
    if (!g) return;
    const list = u.messageList;
    const atBottom = list.scrollHeight - list.scrollTop - list.clientHeight < 40;
    u.avatar.replaceWith(u.avatar = groupAvatar(g.name, g.gid, ' conversation-avatar'));
    u.title.replaceChildren(untrusted(g.name || 'Unnamed group', undefined, { name: true }));
    u.subtitle.textContent = g.ready ? `${g.members.length} member${g.members.length === 1 ? '' : 's'}${g.role === 'owner' ? ' · you are the owner' : ''}` : 'Not ready yet';
    u.banner.textContent = bannerText(g);
    u.banner.hidden = !u.banner.textContent;
    renderMembers(g);
    const canWrite = g.ready && g.status === 'active';
    u.form.hidden = !canWrite;
    u.closedNote.hidden = canWrite;
    u.closedNote.textContent = g.status === 'removed' ? 'You can no longer write to this group.'
      : g.status === 'active' ? 'The group is being set up. You can write once it is ready.' : 'You can write once the owner has added you.';
    u.sendButton.disabled = !h.online() || engine.sending;
    if (canWrite && !h.online()) u.sendStatus.textContent = u.sendStatus.textContent || OFFLINE_TEXT;
    const items = [];
    let day;
    for (const m of engine.conversation(g.gid)) {
      const at = new Date(m.at);
      if (!day || !h.sameDay(day, at)) { day = at; items.push(el('li', { className: 'message-day', text: h.dayLabel(at) })); }
      const mine = m.dir === 'out';
      const when = el('time', { text: at.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) });
      when.dateTime = at.toISOString();
      const meta = el('div', { className: 'message-meta' }, when);
      if (mine) meta.append(el('span', { className: 'message-status', text: m.failed ? ' not sent' : m.published ? ' ✓ sent' : ' ○ waiting to send' }));
      const body = [];
      if (!mine) body.push(el('div', { className: 'message-sender' }, h.nameTitle(m.fp)));
      body.push(el('div', { className: 'message-text' }, untrusted(m.text)), meta);
      items.push(el('li', { className: mine ? 'message message-out' : 'message message-in' }, el('div', { className: 'message-bubble' }, ...body)));
    }
    if (!items.length) items.push(el('li', { className: 'message-none', text: canWrite ? 'No messages yet. Say hello.' : 'No messages yet.' }));
    list.replaceChildren(...items);
    if (scroll || atBottom) list.scrollTop = list.scrollHeight;
    engine.markRead(g.gid);
  }

  // Members: the list of the version in force (a removal shows only once the
  // owner's change is out — design §3), with who is joining, invited or
  // leaving; the owner's Remove (asks once more) and Invite (contacts only,
  // decision 8); a member's Leave (decision 13).
  function renderMembers(g) {
    const owner = g.role === 'owner', ownFp = h.ownFp();
    if (removeArmed && !g.members.includes(removeArmed) && !g.invited.includes(removeArmed)) removeArmed = undefined;
    const row = (fp, label) => {
      const parts = [el('span', { className: 'contact-name' }, h.nameTitle(fp)), h.nameHint(fp)];
      if (label) parts.push(el('span', { className: 'contact-claim', text: label }));
      const main = el('div', { className: 'request-main' }, ...parts.filter(Boolean));
      if (owner && fp !== ownFp && (g.members.includes(fp) || g.invited.includes(fp)) && !g.leaving.includes(fp)) {
        const armed = removeArmed === fp;
        const remove = button(armed ? 'Confirm: remove' : (g.members.includes(fp) ? 'Remove' : 'Withdraw invitation'), () => void removeSelected(fp), 'secondary small');
        remove.setAttribute('aria-label', `${armed ? 'Confirm: remove' : 'Remove'} ${h.displayName(fp)}`);
        main.append(el('div', { className: 'request-actions' }, remove));
      }
      return el('li', { className: 'request-row' }, el('span'), main);
    };
    const rows = g.members.map(fp => row(fp, fp === g.owner ? 'owner' : g.leaving.includes(fp) ? 'leaving — removed at the next group update' : ''));
    for (const fp of g.joining) rows.push(row(fp, 'accepted — added at the next group update'));
    for (const fp of g.invited) rows.push(row(fp, 'invited'));
    u.memberList.replaceChildren(...rows);
    u.inviteRow.hidden = !owner || g.status !== 'active';
    if (owner) {
      const taken = new Set([...g.members, ...g.joining, ...g.invited]);
      const free = h.contacts().filter(c => c.salt && !taken.has(c.fp));
      u.inviteSelect.replaceChildren(...free.map(c => { const o = el('option', { text: h.displayName(c.fp) }); o.value = c.fp; return o; }));
      u.inviteSelect.disabled = u.inviteButton.disabled = !free.length || !h.online() || taken.size >= MAX_MEMBERS;
    }
    u.leaveButton.hidden = owner || !['accepting', 'joining', 'active'].includes(g.status);
  }

  function renderPickList() {
    const contacts = h.contacts().filter(c => c.salt);
    u.pickList.replaceChildren(...(contacts.length ? contacts.map(c => {
      const box = input('input', { type: 'checkbox', id: `nc-group-pick-${c.fp.slice(0, 16)}` });
      box.value = c.fp;
      return el('li', {}, setAttrs(el('label', {}, box, ' ', h.nameTitle(c.fp)), { for: box.id }));
    }) : [el('li', { className: 'contact-empty', text: 'No contacts to invite yet. You can create the group and invite people later.' })]));
  }

  // ── actions ────────────────────────────────────────────────────────────
  const busy = new Set();
  async function guarded(key, statusNode, run, fallback) {
    if (busy.has(key)) return;
    if (!h.online()) { statusNode.textContent = OFFLINE_TEXT; return; }
    busy.add(key);
    try { await run(); }
    catch (error) { statusNode.textContent = explain(error, fallback); }
    finally { busy.delete(key); h.render(); }
  }
  function openCreate() {
    if (!h.isOpen()) return;
    if (!h.online()) { u.blockStatus.textContent = OFFLINE_TEXT; return; }
    u.createStatus.textContent = '';
    u.nameInput.value = '';
    renderPickList();
    if (!u.dialog.open) u.dialog.showModal();
    u.nameInput.focus();
  }
  async function createGroup(event) {
    event.preventDefault();
    const name = u.nameInput.value;
    const problem = nameProblem(name);
    if (problem) { u.createStatus.textContent = problem; return; }
    const people = [...u.pickList.querySelectorAll('input[type="checkbox"]')].filter(b => b.checked).map(b => b.value);
    if (people.length > MAX_MEMBERS - 1) { u.createStatus.textContent = `A group can have at most ${MAX_MEMBERS} people, including you.`; return; }
    await guarded('create', u.createStatus, async () => {
      u.createStatus.textContent = 'Creating the group…';
      const made = await h.engine().create(name, people);
      u.dialog.close();
      u.blockStatus.textContent = made.notInvited.length
        ? `The group was created. ${made.notInvited.length} invitation${made.notInvited.length === 1 ? '' : 's'} could not be sent; invite them again from Members.`
        : 'The group was created.';
      h.openGroup(made.gid);
    }, 'The group could not be created. Try again in a minute.');
  }
  async function acceptInvite(gid) {
    await guarded(`join:${gid}`, u.blockStatus, async () => {
      await h.engine().acceptInvite(gid);
      u.blockStatus.textContent = 'You asked to join. The group opens once its owner adds you.';
    }, 'Joining failed. Try again in a minute.');
  }
  async function ignoreInvite(gid) {
    try { await h.engine().ignoreInvite(gid); u.blockStatus.textContent = 'Invitation ignored.'; }
    catch (error) { u.blockStatus.textContent = explain(error, 'The invitation could not be removed right now.'); }
    h.render();
  }
  async function inviteSelected() {
    const fp = u.inviteSelect.value;
    if (!selected || !fp) return;
    await guarded(`invite:${selected}`, u.membersStatus, async () => {
      await h.engine().invite(selected, fp);
      u.membersStatus.textContent = `${h.displayName(fp)} was invited. They join once they accept.`;
    }, 'The invitation could not be sent. Try again in a minute.');
  }
  async function removeSelected(fp) {
    if (removeArmed !== fp) { removeArmed = fp; u.membersStatus.textContent = `Remove ${h.displayName(fp)}? They stay listed until the group is updated on the network.`; h.render(); return; }
    removeArmed = undefined;
    await guarded(`remove:${selected}`, u.membersStatus, async () => {
      await h.engine().removeMember(selected, fp);
      u.membersStatus.textContent = `${h.displayName(fp)} is removed at the next group update.`;
    }, 'The change could not be saved. Try again.');
  }
  async function leaveSelected() {
    const gid = selected;
    if (!gid) return;
    await guarded(`leave:${gid}`, u.membersStatus, async () => {
      await h.engine().leave(gid);
      selected = undefined;
      u.blockStatus.textContent = 'You left the group. Its owner has been told.';
      h.render();
    }, 'Leaving failed. Try again in a minute.');
  }
  // One send at a time (the composer's text is taken once — 0.1.55): the
  // engine keeps the message on this device first, then publishes it.
  async function sendSelected(event) {
    event.preventDefault();
    const engine = h.engine(), gid = selected, text = u.composer.value;
    if (!engine || !gid || engine.sending) return;
    if (!h.online()) { u.sendStatus.textContent = OFFLINE_TEXT; return; }
    const problem = textProblem(text);
    if (problem) { if (text.trim()) u.sendStatus.textContent = problem; return; }
    u.sendButton.disabled = true;
    try {
      // The composer is emptied once the message is kept on this device
      // (onKept); until then a second Enter is refused by engine.sending.
      const result = await engine.send(gid, text, {
        onKept: () => { if (u.composer.value === text) u.composer.value = ''; h.render({ scroll: true }); }
      });
      u.sendStatus.textContent = result === 'kept' ? 'Not sent yet. It is tried again automatically.' : '';
    } catch (error) {
      u.sendStatus.textContent = explain(error, 'The message could not be kept. Try again.');
    }
    h.render({ scroll: true });
  }

  return {
    block: u.block, view: u.view, dialog: u.dialog,
    get selected() { return selected; },
    open(gid) { selected = gid; removeArmed = undefined; u.sendStatus.textContent = ''; u.membersStatus.textContent = ''; u.members.open = false; },
    close() { selected = undefined; removeArmed = undefined; },
    focus() { (u.form.hidden ? u.title : u.composer).focus({ preventScroll: true }); },
    renderBlock, renderView, unreadTotal,
    reset() {
      selected = undefined; removeArmed = undefined; busy.clear();
      for (const node of [u.blockStatus, u.membersStatus, u.sendStatus, u.createStatus, u.banner]) node.textContent = '';
      u.composer.value = ''; u.nameInput.value = '';
      u.inviteList.replaceChildren(); u.groupList.replaceChildren(); u.messageList.replaceChildren(); u.memberList.replaceChildren();
      if (u.dialog.open) u.dialog.close();
      u.view.hidden = true;
    }
  };
}
