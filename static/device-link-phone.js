const phoneEl = id => document.getElementById(id);
let phoneCSRF = '', phoneLink = null, phoneTimer = null;
// Remove bearer token from the address bar/history before any API request.
let linkToken = location.hash.slice(1);
history.replaceState(null, '', '/link-device');
const phoneDecode = s => Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.length%4)%4)), c=>c.charCodeAt(0));
const phoneEncode = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
async function phoneAPI(path, body) {
    const response = await fetch('/api/'+path, {method:body===undefined?'GET':'POST',credentials:'same-origin',
        headers:body===undefined?{}:{'Content-Type':'application/json','X-CSRF-Token':phoneCSRF},
        body:body===undefined?undefined:JSON.stringify(body)});
    const result = await response.json();
    if (!response.ok) throw new Error(`${response.status}: ${result.error || '요청 실패'}`);
    return result;
}
function stopPhone(message) {
    clearInterval(phoneTimer); phoneEl('enrollment').hidden=true; phoneEl('cancel').hidden=true;
    phoneEl('status').textContent=message;
}
async function phonePoll() {
    try {
        const result = await phoneAPI('device-links/'+phoneLink);
        if (result.state === 'approved') stopPhone('PC에서 승인했습니다. 홈으로 이동하여 새 패스키로 로그인하세요.');
        if (result.state === 'cancelled') stopPhone('연결이 취소되었습니다. 기기에 남은 미승인 패스키는 직접 정리하세요.');
    } catch (e) { stopPhone(e.message); }
}
phoneEl('create').onclick = async () => {
    phoneEl('create').disabled=true;
    try {
        const opts=await phoneAPI(`device-links/${phoneLink}/options`,{label:phoneEl('label').value});
        opts.challenge=phoneDecode(opts.challenge); opts.user.id=phoneDecode(opts.user.id);
        opts.excludeCredentials=(opts.excludeCredentials||[]).map(c=>({...c,id:phoneDecode(c.id)}));
        const c=await navigator.credentials.create({publicKey:opts});
        const credential={id:c.id,rawId:phoneEncode(c.rawId),type:c.type,
            response:{clientDataJSON:phoneEncode(c.response.clientDataJSON),attestationObject:phoneEncode(c.response.attestationObject),
                transports:c.response.getTransports?c.response.getTransports():[]},clientExtensionResults:c.getClientExtensionResults()};
        const result=await phoneAPI(`device-links/${phoneLink}/verify`,{credential});
        phoneEl('enrollment').hidden=true;
        phoneEl('code').textContent=result.code;
        phoneEl('status').textContent='아직 로그인할 수 없습니다. PC와 코드가 같은지 비교하고 PC에서 승인하세요.';
    } catch (e) {
        try { await phoneAPI(`device-links/${phoneLink}/cancel`,{}); } catch (_) {}
        stopPhone(['NotAllowedError','AbortError'].includes(e.name)?'기기 등록을 취소했습니다. PC에서 새 링크를 만드세요.':e.message);
    } finally { phoneEl('create').disabled=false; }
};
phoneEl('cancel').onclick=async()=>{
    try { await phoneAPI(`device-links/${phoneLink}/cancel`,{}); stopPhone('연결을 취소했습니다.'); }
    catch(e) {stopPhone(e.message);}
};
(async()=>{
    try {
        if (!linkToken) throw new Error('PC에서 새 연결 링크를 만들어 여세요. 새로고침한 링크는 재사용할 수 없습니다.');
        const session=await phoneAPI('session'); phoneCSRF=session.csrf;
        const result=await phoneAPI('device-links/claim',{token:linkToken}); linkToken='';
        phoneLink=result.id;
        phoneEl('account').textContent=`연결 대상 계정: ${result.account}`;
        phoneEl('status').textContent=`만료: ${new Date(result.expires*1000).toLocaleTimeString()}. 패스키를 만들면 PC 승인이 필요합니다.`;
        phoneEl('enrollment').hidden=false; phoneEl('cancel').hidden=false;
        phoneTimer=setInterval(phonePoll,2500);
    } catch(e) {linkToken=''; stopPhone(e.message);}
})();
