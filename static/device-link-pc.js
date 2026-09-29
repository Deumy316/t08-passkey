let deviceLink = null, linkTimer = null, linkBusy = false;
function clearLinkShare() {
    el('link-url').value = ''; el('link-qr').replaceChildren();
    el('link-copy').hidden = true;
}
async function pollLink() {
    if (!deviceLink || linkBusy) return;
    try {
        const status = await api('device-links/' + deviceLink);
        el('link-code').textContent = status.code || '아이폰 등록을 기다리는 중';
        el('link-state').textContent = `${status.label || '새 기기'} · ${status.state} · 만료 ${new Date(status.expires*1000).toLocaleTimeString()}`;
        el('link-approve').hidden = status.state !== 'pending';
        if (status.state !== 'open') clearLinkShare();
        if (['approved', 'cancelled'].includes(status.state)) {
            clearInterval(linkTimer); deviceLink = null;
            el('link-cancel').hidden = true;
            await refresh();
        }
    } catch (error) {
        clearInterval(linkTimer); clearLinkShare(); deviceLink = null;
        el('link-approve').hidden = true; el('link-cancel').hidden = true;
        el('link-state').textContent = error.message;
    }
}
async function linkAction(action) {
    if (linkBusy) return;
    linkBusy = true;
    el('link-start').disabled = true; el('link-approve').disabled = true;
    try { await action(); }
    catch (error) {
        el('auth-status').textContent = ['NotAllowedError','AbortError'].includes(error.name)
            ? '본인 인증이 취소되었습니다. 연결은 승인되지 않았습니다.' : error.message;
    } finally {
        linkBusy = false; el('link-start').disabled = false; el('link-approve').disabled = false;
        await pollLink();
    }
}
el('link-start').onclick = () => linkAction(async () => {
    await authenticate('link-create');
    const result = await api('device-links', {});
    deviceLink = result.id;
    el('link-panel').hidden = false; el('link-cancel').hidden = false;
    el('link-copy').hidden = false; el('link-approve').hidden = true;
    el('link-url').value = result.url;
    // SVG comes only from the local QR library, never from a third-party URL.
    const svg = new DOMParser().parseFromString(result.qr, 'image/svg+xml').documentElement;
    el('link-qr').replaceChildren(document.importNode(svg, true));
    clearInterval(linkTimer); linkTimer = setInterval(pollLink, 2500);
});
el('link-copy').onclick = async () => {
    try { await navigator.clipboard.writeText(el('link-url').value); }
    catch (_) { el('link-url').select(); }
};
el('link-approve').onclick = () => linkAction(async () => {
    if (!confirm(`아이폰의 코드가 ${el('link-code').textContent}와 정확히 일치합니까? 모르는 요청은 취소하세요.`)) return;
    const id = deviceLink;
    await authenticate('link-approve', id);
    await api(`device-links/${id}/approve`, {});
    el('auth-status').textContent = '승인했습니다. 아이폰에서 새 패스키로 로그인하세요.';
});
el('link-cancel').onclick = () => linkAction(async () => {
    await api(`device-links/${deviceLink}/cancel`, {});
});
