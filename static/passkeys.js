/* Binary encoding only. WebAuthn and all signature verification use platform/library APIs. */
const el = id => document.getElementById(id);
let csrf = '';
const decode = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4-s.length%4)%4)), c => c.charCodeAt(0));
const encode = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
async function api(path, body, method = 'POST') {
    const response = await fetch('/api/' + path, {method: body === undefined ? 'GET' : method,
        credentials: 'same-origin', headers: body === undefined ? {} : {'Content-Type':'application/json','X-CSRF-Token':csrf},
        body: body === undefined ? undefined : JSON.stringify(body)});
    const result = await response.json();
    if (!response.ok) throw new Error(`${response.status}: ${result.error || '요청 실패'}`);
    return result;
}
function options(value, registration) {
    value.challenge = decode(value.challenge);
    if (registration) value.user.id = decode(value.user.id);
    for (const key of ['allowCredentials', 'excludeCredentials'])
        if (value[key]) value[key] = value[key].map(c => ({...c, id:decode(c.id)}));
    return value;
}
function serialize(c) {
    const response = {clientDataJSON:encode(c.response.clientDataJSON)};
    for (const k of ['attestationObject','authenticatorData','signature','userHandle'])
        if (c.response[k]) response[k] = encode(c.response[k]);
    if (c.response.getTransports) response.transports = c.response.getTransports();
    return {id:c.id, rawId:encode(c.rawId), type:c.type, response,
        clientExtensionResults:c.getClientExtensionResults()};
}
async function authenticate(action='login', target='') {
    const opts = await api('auth/options', {action,target});
    const credential = await navigator.credentials.get({publicKey:options(opts, false)});
    await api('auth/verify', {credential:serialize(credential)});
}
async function register(mode, label) {
    const opts = await api('register/options', {mode, label, name:el('account-name').value});
    const credential = await navigator.credentials.create({publicKey:options(opts, true)});
    await api('register/verify', {credential:serialize(credential)});
}
async function refresh() {
    const session = await api('session'); csrf = session.csrf;
    el('signed-out').hidden = !!session.user;
    el('signed-in').hidden = !session.user;
    el('private-notes').replaceChildren(); el('passkey-list').replaceChildren();
    el('account-info').textContent = '';
    if (!session.user) return;
    el('account-info').textContent = `${session.user.name} · 계정 ID: ${session.user.id}`;
    const [notes, keys] = await Promise.all([api('notes'),api('passkeys')]);
    for (const n of notes.notes) {
        const li = document.createElement('li'); li.textContent = `${n.body} (자료 ID: ${n.id})`;
        el('private-notes').append(li);
    }
    for (const k of keys.passkeys) {
        const li = document.createElement('li'); li.textContent = `${k.name} · 등록일 ${k.created} `;
        const button = document.createElement('button'); button.type='button';
        button.textContent = keys.passkeys.length === 1 ? '마지막 패스키 삭제 불가' : '본인 인증 후 삭제';
        button.disabled = keys.passkeys.length === 1;
        button.onclick = () => run(async () => {
            if (!confirm(`${k.name} 패스키를 서버에서 삭제할까요? 기기 저장소의 항목은 직접 정리해야 합니다.`)) return;
            await authenticate('delete', k.id);
            await api('passkeys/'+k.id, {}, 'DELETE');
        });
        li.append(button); el('passkey-list').append(li);
    }
}
async function run(action) {
    document.querySelectorAll('#passkey-space button').forEach(b => b.disabled=true);
    el('auth-status').textContent='기기의 패스키 안내를 따라 주세요.';
    try {
        if (!window.PublicKeyCredential || !window.isSecureContext) throw new Error('localhost 또는 HTTPS의 WebAuthn 지원 브라우저가 필요합니다.');
        await action(); await refresh(); el('auth-status').textContent='완료했습니다.';
    } catch (error) {
        try { await api('cancel', {}); } catch (_) { /* Expiry also removes pending ceremony. */ }
        el('auth-status').textContent = ['NotAllowedError','AbortError'].includes(error.name)
            ? '취소되었거나 시간이 초과되었습니다. 미완료 계정·패스키는 서버에 저장하지 않습니다.'
            : error.message;
    } finally {
        document.querySelectorAll('#signed-out button, #logout, #add-key').forEach(b => b.disabled=false);
        // Rebuild key controls without overriding an error message.
        try { await refresh(); } catch (_) { el('signed-in').hidden=true; el('private-notes').replaceChildren(); }
    }
}
el('signup').onclick=()=>run(()=>register('new',el('first-label').value));
el('login').onclick=()=>run(()=>authenticate());
el('logout').onclick=()=>run(()=>api('logout',{}));
el('add-key').onclick=()=>run(async()=>{await authenticate('add'); await register('add',el('extra-label').value);});
window.addEventListener('pageshow',()=>refresh().catch(e=>{el('auth-status').textContent=e.message;}));
