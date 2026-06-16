/*
 * Shared "send account info via WhatsApp / SMS" logic.
 * Self-contained so any page can use it: AccountMessage.open(clientData).
 * Mirrors the dashboard behaviour (phone extraction, channel choice, templates).
 * Depends only on a global showToast() (defined in base.html).
 */
(function (global) {
    'use strict';

    function esc(value) {
        return String(value ?? '')
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    function toLatinDigits(value) {
        const fa = '۰۱۲۳۴۵۶۷۸۹';
        const ar = '٠١٢٣٤٥٦٧٨٩';
        return String(value || '').replace(/[۰-۹٠-٩]/g, ch => {
            const f = fa.indexOf(ch); if (f >= 0) return String(f);
            const a = ar.indexOf(ch); return a >= 0 ? String(a) : ch;
        });
    }

    function normalizeCandidate(candidate) {
        let d = toLatinDigits(candidate || '').replace(/[^\d]/g, '');
        if (!d) return '';
        if (d.startsWith('00')) d = d.slice(2);
        if (d.startsWith('98') && d.length === 12 && d[2] === '9') return d;
        if (d.startsWith('0') && d.length === 11 && d[1] === '9') return `98${d.slice(1)}`;
        if (d.startsWith('9') && d.length === 10) return `98${d}`;
        const local = d.match(/09\d{9}/); if (local) return `98${local[0].slice(1)}`;
        const intl = d.match(/98(9\d{9})/); if (intl) return `98${intl[1]}`;
        if (d.length >= 10 && d.length <= 15) return d;
        return '';
    }

    function extractNumbers(...sources) {
        const found = [];
        const byNumber = new Map();
        sources.forEach((source) => {
            const rawValue = (typeof source === 'object' && source !== null) ? source.value : source;
            const label = ((typeof source === 'object' && source !== null) ? source.label : '') || 'Phone';
            const raw = toLatinDigits(rawValue || '');
            if (!raw.trim()) return;
            (raw.match(/(?:\+|00)?\d[\d\s().-]{8,}\d/g) || []).forEach((cand) => {
                const number = normalizeCandidate(cand);
                if (!number) return;
                if (byNumber.has(number)) {
                    const ex = byNumber.get(number);
                    if (!ex.labels.includes(label)) ex.labels.push(label);
                    ex.label = ex.labels.join(' + ');
                    return;
                }
                const item = { number, label, labels: [label], display: `+${number}` };
                byNumber.set(number, item);
                found.push(item);
            });
        });
        return found;
    }

    function absoluteUrl(value) {
        const raw = String(value || '').trim();
        if (!raw) return '';
        try { return new URL(raw, window.location.origin).href; } catch (_) { return raw; }
    }

    const DEFAULT_TEMPLATE = [
        'اطلاعات اکانت شما',
        'اسم اکانت: {email}',
        'مدت زمان باقی مانده: {remaining_time}',
        'حجم باقی مانده: {remaining_volume}',
        'لینک dash sub: {dashboard_link}',
        '',
        'لطفا از طریق لینک بالا به سرویس خود متصل شین .'
    ].join('\n');

    const templateCache = {};   // channel -> { content, telegram_channel, whatsapp_channel }
    async function getTemplate(channel) {
        if (templateCache[channel] !== undefined) return templateCache[channel];
        try {
            const res = await fetch(`/api/account-message-templates/active?channel=${encodeURIComponent(channel)}`);
            const data = await res.json();
            const content = (data && data.template && data.template.content)
                ? data.template.content
                : ((data && data.content) ? data.content : '');
            templateCache[channel] = {
                content: content,
                telegram_channel: (data && data.telegram_channel) ? data.telegram_channel : '',
                whatsapp_channel: (data && data.whatsapp_channel) ? data.whatsapp_channel : '',
            };
        } catch (_) {
            templateCache[channel] = { content: '', telegram_channel: '', whatsapp_channel: '' };
        }
        return templateCache[channel];
    }

    function renderMessage(templateObj, client) {
        const tpl = (templateObj && templateObj.content) ? templateObj.content : DEFAULT_TEMPLATE;
        const telegramCh = (templateObj && templateObj.telegram_channel) || '';
        const whatsappCh = (templateObj && templateObj.whatsapp_channel) || '';
        const values = {
            email: client.email || '-',
            account_name: client.email || '-',
            service_name: client.email || '-',
            remaining_time: client.expiryTime || '-',
            remaining_volume: client.remaining_formatted || '-',
            dashboard_link: absoluteUrl(client.dash_sub_url || client.sub_url || ''),
            sub_link: absoluteUrl(client.sub_url || ''),
            server_name: client.server_name || '',
            telegram_channel: telegramCh,
            whatsapp_channel: whatsappCh,
        };
        return applyConditionals(tpl, values).replace(/\{([a-zA-Z0-9_]+)\}/g, (m, k) =>
            Object.prototype.hasOwnProperty.call(values, k) ? values[k] : m);
    }

    // Resolve {if_<name>}...{/if_<name>} blocks: kept when values['<name>_given']
    // (or values['<name>']) is truthy, else the block + leading newline is dropped.
    function applyConditionals(templateStr, values) {
        return String(templateStr || '').replace(
            /(\n?)\{if_([a-zA-Z0-9_]+)\}([\s\S]*?)\{\/if_\2\}/g,
            function (m, lead, name, inner) {
                var flag = values && (values[name + '_given'] !== undefined ? values[name + '_given'] : values[name]);
                return flag ? (lead + inner) : '';
            });
    }

    function buildSms(phone, message) {
        return `sms:${phone.display || ('+' + phone.number)}?body=${encodeURIComponent(message)}`;
    }

    // ── Phone-choice modal (singleton, fresh per call) ───────────────────
    function openPhoneChoice(numbers, onSelect, title) {
        const list = Array.isArray(numbers) ? numbers : [];
        if (list.length === 0) return false;
        let overlay = document.getElementById('am-phone-choice');
        if (!overlay) {
            overlay = document.createElement('div');
            overlay.id = 'am-phone-choice';
            overlay.className = 'modal-overlay hidden';
            overlay.innerHTML = `
                <div class="modal" style="max-width:420px;">
                    <div class="modal-header">
                        <h2 id="am-phone-title">Select phone number</h2>
                        <button class="modal-close" type="button" data-am-close>&times;</button>
                    </div>
                    <div class="modal-body"><div id="am-phone-list" style="display:grid;gap:10px;"></div></div>
                </div>`;
            document.body.appendChild(overlay);
            overlay.addEventListener('click', (e) => {
                if (e.target === overlay || e.target.closest('[data-am-close]')) overlay.classList.add('hidden');
            });
        }
        overlay.querySelector('#am-phone-title').textContent = title || 'Select phone number';
        const container = overlay.querySelector('#am-phone-list');
        container.textContent = '';
        list.forEach((item) => {
            const btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'btn btn-secondary';
            btn.style.justifyContent = 'space-between';
            btn.innerHTML = `<span>${esc(item.label || 'Phone')}</span><strong dir="ltr">${esc(item.display || ('+' + item.number))}</strong>`;
            btn.addEventListener('click', () => { overlay.classList.add('hidden'); onSelect(item); });
            container.appendChild(btn);
        });
        overlay.classList.remove('hidden');
        return true;
    }

    // ── Channel-choice modal (singleton; reads current handler dynamically) ──
    function openChannelChoice(phone, onSelect) {
        let overlay = document.getElementById('am-channel-choice');
        if (!overlay) {
            overlay = document.createElement('div');
            overlay.id = 'am-channel-choice';
            overlay.className = 'modal-overlay hidden';
            overlay.innerHTML = `
                <div class="modal" style="max-width:420px;">
                    <div class="modal-header">
                        <h2>Send account info</h2>
                        <button class="modal-close" type="button" data-am-close>&times;</button>
                    </div>
                    <div class="modal-body">
                        <div id="am-channel-phone" style="margin-bottom:12px;padding:10px 12px;border:1px solid var(--border-color);border-radius:8px;display:flex;justify-content:space-between;gap:10px;">
                            <span>Phone</span><strong dir="ltr"></strong>
                        </div>
                        <div style="display:grid;gap:10px;">
                            <button class="btn btn-secondary" type="button" data-am-channel="whatsapp" style="justify-content:space-between;"><span>WhatsApp</span><strong>wa.me</strong></button>
                            <button class="btn btn-secondary" type="button" data-am-channel="sms" style="justify-content:space-between;"><span>SMS</span><strong>sms:</strong></button>
                        </div>
                    </div>
                </div>`;
            document.body.appendChild(overlay);
            overlay.addEventListener('click', (e) => {
                const chBtn = e.target.closest('[data-am-channel]');
                if (chBtn) {
                    overlay.classList.add('hidden');
                    const cb = overlay._onSelect, ph = overlay._phone;
                    if (typeof cb === 'function') cb(chBtn.dataset.amChannel, ph);
                    return;
                }
                if (e.target === overlay || e.target.closest('[data-am-close]')) overlay.classList.add('hidden');
            });
        }
        overlay._onSelect = onSelect;
        overlay._phone = phone;
        const box = overlay.querySelector('#am-channel-phone');
        if (box) {
            box.querySelector('span').textContent = phone?.label || 'Phone';
            box.querySelector('strong').textContent = phone?.display || ('+' + (phone?.number || ''));
        }
        overlay.classList.remove('hidden');
    }

    // Map templateType to the channel prefix used for API calls
    function _resolveChannelPrefix(templateType) {
        if (templateType === 'royalty') return 'royalty_';
        return '';
    }

    function _openLink(href) {
        // Use <a> click — more reliable than window.open on iOS Safari for universal links
        const a = document.createElement('a');
        a.href = href;
        a.target = '_blank';
        a.rel = 'noopener noreferrer';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
    }

    async function send(channel, phone, client, opts) {
        try {
            const prefix = _resolveChannelPrefix((opts && opts.templateType) || '');
            const apiChannel = prefix + channel; // e.g. 'royalty_whatsapp' or 'whatsapp'

            // Synchronous fast-path: if template is already cached, build href and open
            // immediately within the user-gesture context (iOS Safari blocks window.open
            // after any await, even for a resolved promise).
            if (templateCache[apiChannel] !== undefined) {
                const message = renderMessage(templateCache[apiChannel], client);
                const href = channel === 'sms'
                    ? buildSms(phone, message)
                    : `https://wa.me/${phone.number}?text=${encodeURIComponent(message)}`;
                _openLink(href);
                return;
            }

            // Slow path: open a blank window NOW (within user-gesture), then navigate it
            // once we have the template — avoids iOS popup blocker.
            const newWin = window.open('', '_blank');
            try {
                const tpl = await getTemplate(apiChannel);
                const message = renderMessage(tpl, client);
                const href = channel === 'sms'
                    ? buildSms(phone, message)
                    : `https://wa.me/${phone.number}?text=${encodeURIComponent(message)}`;
                if (newWin && !newWin.closed) {
                    newWin.location.href = href;
                } else {
                    _openLink(href);
                }
            } catch (_) {
                if (newWin && !newWin.closed) newWin.close();
                throw _;
            }
        } catch (_) {
            if (global.showToast) global.showToast('Unable to prepare account message', 'error');
        }
    }

    // opts.templateType: 'royalty' uses royalty_info templates instead of account_info
    function open(client, opts) {
        opts = opts || {};
        const phones = extractNumbers(
            { label: 'Account name', value: client.email },
            { label: 'Comment', value: client.comment },
            { label: 'Saved phone', value: client.phone }
        );
        if (!phones.length) {
            if (global.showToast) global.showToast('No mobile number found. Add the phone in the Comment field.', 'error');
            return;
        }
        openPhoneChoice(phones, (phone) => {
            openChannelChoice(phone, (channel, selectedPhone) => send(channel, selectedPhone, client, opts));
        }, 'Select mobile number');
    }

    // Warm the templates so the first click is instant (sync fast-path in send())
    function warm() {
        getTemplate('whatsapp'); getTemplate('sms');
        getTemplate('royalty_whatsapp'); getTemplate('royalty_sms');
        getTemplate('client_created_whatsapp'); getTemplate('client_created_sms');
        getTemplate('renew_whatsapp'); getTemplate('renew_sms');
    }

    global.AccountMessage = { open, warm, extractNumbers };
})(window);
