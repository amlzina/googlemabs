let lastScan = null;
const $ = (id) => document.getElementById(id);
function toast(message) { const el = $('toast'); el.textContent = message; el.classList.add('show'); setTimeout(() => el.classList.remove('show'), 3400); }
function showResults(title, data, kind) { $('results-panel').hidden = false; $('result-title').textContent = title; $('results-content').innerHTML = ''; if (kind === 'scan') renderScan(data); else renderPlan(data); $('results-panel').scrollIntoView({behavior:'smooth', block:'start'}); }
function element(tag, className, text) { const el = document.createElement(tag); if (className) el.className = className; if (text !== undefined) el.textContent = text; return el; }
function renderScan(data) {
  lastScan = data; $('export-json').hidden = false; $('export-html').hidden = false;
  const meta = element('div','result-meta');
  meta.append(element('span','meta-chip',`TARGET: ${data.target}`),element('span','meta-chip',`HTTP: ${data.http_status}`),element('span','meta-chip',`FINDINGS: ${data.findings.length}`),element('span','meta-chip',`TIME: ${data.timestamp}`));
  $('results-content').append(meta);
  if (data.summary) {
    const summary = element('div','result-meta');
    ['critical','high','medium','low','info'].forEach(level => summary.append(element('span','meta-chip',`${level.toUpperCase()}: ${data.summary.severity_counts?.[level] ?? 0}`)));
    summary.append(element('span','meta-chip',`CONFIRMED: ${data.summary.confirmed_vulnerabilities ?? 0}`));
    $('results-content').append(summary);
    $('results-content').append(element('p','muted',data.summary.note || ''));
  }
  if (data.tls) { const tls = element('div','list-block'); tls.append(element('h3','','TLS / Certificate Check'),element('p','',data.tls.details)); $('results-content').append(tls); }
  if (data.pages) { const pages = element('div','list-block'); pages.append(element('h3','','الصفحات التي تمت زيارتها')); const ul = document.createElement('ul'); data.pages.forEach(p => ul.append(element('li','',`${p.http_status} · ${p.url} · ${p.findings_count} مؤشرات`))); pages.append(ul); $('results-content').append(pages); }
  data.findings.forEach(f => { const card = element('article','finding'); const top = element('div','finding-top'); const left = document.createElement('div'); left.append(element('h3','',f.title),element('span','status',f.status)); top.append(left,element('span',`severity sev-${f.severity}`,f.severity)); card.append(top,element('p','muted',`الفئة: ${f.category || 'General'} · الثقة: ${f.confidence || 'unspecified'}`),element('p','',`الدليل: ${f.evidence}`),element('p','',`التوصية: ${f.recommendation}`)); $('results-content').append(card); });
  const lim = element('div','list-block'); lim.append(element('h3','','حدود الفحص')); const ul = document.createElement('ul'); data.limitations.forEach(x=>ul.append(element('li','',x))); lim.append(ul); $('results-content').append(lim);
}
function renderPlan(data) {
  lastScan = null; $('export-json').hidden = true; $('export-html').hidden = true;
  $('results-content').append(element('div','result-meta'),element('div','meta-chip',`TARGET: ${data.target}`),element('div','notice',data.notice));
  $('results-content').append(element('p','muted',data.description));
  const blocks = [['خطة التحقق',data.checks],['الأدلة المطلوبة',[data.evidence]],['التوصيات',[data.remediation]]];
  blocks.forEach(([title,items])=>{const b=element('div','list-block');b.append(element('h3','',title));const ul=document.createElement('ul');items.forEach(x=>ul.append(element('li','',x)));b.append(ul);$('results-content').append(b)});
  const src=element('div','list-block');src.append(element('h3','','المراجع'));data.sources.forEach(s=>{const a=element('a','source-link',s.title);a.href=s.url;a.target='_blank';a.rel='noopener noreferrer';a.style='display:block;color:#72e0d0;margin:7px 0';src.append(a)});$('results-content').append(src);
}
$('scan-form').addEventListener('submit', async (event) => { event.preventDefault(); const button=$('scan-button'); button.disabled=true;button.textContent='جارٍ الفحص…'; try { const response=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:$('url').value,authorized:$('authorized').checked})});const data=await response.json();if(!response.ok)throw new Error(data.error||'تعذر إكمال الفحص');showResults('نتائج الفحص',data,'scan');toast('اكتمل الفحص السلبي. راجعي النتائج في سياقها.'); } catch(e){toast(e.message)} finally{button.disabled=false;button.innerHTML='ابدأ الفحص <span>↗</span>';} });
$('research-form').addEventListener('submit', async (event) => {event.preventDefault();const button=$('research-button');button.disabled=true;button.textContent='جارٍ إعداد الخطة…';try{const response=await fetch('/api/research',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:$('target').value,topic:$('topic').value})});const data=await response.json();if(!response.ok)throw new Error(data.error||'تعذر إنشاء الخطة');showResults('خطة البحث الأمني',data,'plan');toast('دي خطة بحث وليست إثباتًا لوجود ثغرة.');}catch(e){toast(e.message)}finally{button.disabled=false;button.innerHTML='إنشاء خطة البحث <span>✦</span>'}});
async function exportReport(format){if(!lastScan){toast('اعملي فحصًا أولًا عشان تصدّري تقريرًا.');return}try{const response=await fetch('/api/export',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({format,result:lastScan})});if(!response.ok)throw new Error('تعذر إنشاء التقرير');const blob=await response.blob();const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download=`security-scan-report.${format}`;document.body.appendChild(a);a.click();a.remove();URL.revokeObjectURL(url)}catch(e){toast(e.message)}}
$('export-json').addEventListener('click',()=>exportReport('json'));$('export-html').addEventListener('click',()=>exportReport('html'));
$('load-lab').addEventListener('click',async()=>{const box=$('lab-details');if(box.dataset.loaded==='true'){box.hidden=!box.hidden;return}try{const response=await fetch('/api/lab');const data=await response.json();box.innerHTML='';data.exercises.forEach(ex=>{const card=element('div','lab-detail');card.append(element('h3','',ex.name),element('p','',`السيناريو: ${ex.scenario}`),element('p','',`التحقق: ${ex.test}`),element('p','',`الإصلاح: ${ex.fix}`));box.append(card)});box.append(element('div','notice',data.notice));box.dataset.loaded='true';}catch(e){toast('تعذر تحميل تفاصيل المعمل.')} });

$('crawl-button').addEventListener('click', async () => {
  if (!$('url').value.trim()) { toast('اكتبي رابط الموقع أولًا.'); return; }
  if (!$('authorized').checked) { toast('أكدي امتلاكك للتصريح قبل الزحف.'); return; }
  const button = $('crawl-button'); button.disabled = true; button.textContent = 'جارٍ الزحف المحدود…';
  try {
    const response = await fetch('/api/crawl', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({url:$('url').value, authorized:$('authorized').checked})});
    const data = await response.json(); if (!response.ok) throw new Error(data.error || 'تعذر إكمال الزحف');
    showResults('نتائج الزحف المحدود', data, 'scan'); toast(`اكتمل الزحف: ${data.pages_scanned} صفحة.`);
  } catch (e) { toast(e.message); } finally { button.disabled = false; button.innerHTML = 'ابدأ الزحف المحدود <span>↗</span>'; }
});
$('run-lab-check').addEventListener('click', async () => {
  const button = $('run-lab-check'); button.disabled = true; button.textContent = 'جارٍ تشغيل التجربة…';
  try {
    const response = await fetch('/api/lab/check', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({exercise:$('lab-exercise').value, value:$('lab-value').value, user_id:$('lab-user').value, resource_owner:$('lab-owner').value})});
    const data = await response.json(); if (!response.ok) throw new Error(data.error || 'تعذر تشغيل التجربة');
    const output = $('lab-check-result'); output.hidden = false; output.textContent = JSON.stringify(data, null, 2); toast('اكتملت التجربة داخل المعمل المحلي.');
  } catch (e) { toast(e.message); } finally { button.disabled = false; button.textContent = 'تشغيل التجربة المحلية'; }
});


$('verification-form').addEventListener('submit', async (event) => {
  event.preventDefault(); const button=$('verification-button'); button.disabled=true; button.textContent='جارٍ تحليل الحالة…';
  const payload={method:$('v-method').value,status:$('v-status').value,business_type:$('v-type').value,phone_access:$('v-phone').value,website_match:$('v-website').value,video_issue:$('v-video-issue').value};
  try { const response=await fetch('/api/verification/advice',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)}); const data=await response.json(); if(!response.ok) throw new Error(data.error||'تعذر تحليل الحالة');
    const box=$('verification-results'); box.innerHTML=''; box.hidden=false; box.append(element('h3','',data.title));
    data.steps.forEach(step=>{const card=element('article','finding');card.append(element('span',`status ${step.priority==='important'?'':'status'}`,step.priority.toUpperCase()),element('h3','',step.title),element('p','',step.action),element('p','muted',`الأساس: ${step.basis}`));box.append(card)});
    const note=element('div','notice',data.limitations.join(' '));box.append(note); const sources=element('div','list-block');sources.append(element('h3','','المصادر الرسمية'));data.sources.forEach(src=>{const a=element('a','source-link',src.title);a.href=src.url;a.target='_blank';a.rel='noopener noreferrer';sources.append(a)});box.append(sources); box.scrollIntoView({behavior:'smooth',block:'nearest'}); toast('اكتمل التشخيص الإرشادي؛ راجعي الأدلة والقيود.');
  } catch(e){toast(e.message)} finally{button.disabled=false;button.innerHTML='حلّل الحالة واقترح الخطوات <span>↗</span>';}
});


$('verification-link-form').addEventListener('submit', async (event) => {
  event.preventDefault(); const button=$('verification-link-button'); button.disabled=true; button.textContent='جارٍ تحليل الرابط…';
  const payload={maps_url:$('maps-profile-url').value.trim(),business_name:$('maps-business-name').value.trim(),neighborhood:$('maps-neighborhood').value.trim(),phone:$('maps-phone').value.trim(),website_url:$('maps-website-url').value.trim(),authorized_website:$('maps-website-authorized').checked};
  try {
    const response=await fetch('/api/verification/link-analysis',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
    const data=await response.json(); if(!response.ok) throw new Error(data.error||'تعذر تحليل الرابط');
    const box=$('verification-link-results'); box.replaceChildren(); box.hidden=false; box.append(element('h3','',data.title));
    data.findings.forEach(f=>{const card=element('article','finding');card.append(element('span',`severity sev-${f.severity}`,f.severity.toUpperCase()),element('h3','',f.title),element('p','muted',`الحالة: ${f.status}`),element('p','',f.evidence),element('p','',f.recommendation));box.append(card)});
    const note=element('div','notice',data.limits.join(' '));box.append(note);
    if(data.sources?.length){const sources=element('div','list-block');sources.append(element('h3','','المصادر الرسمية'));data.sources.forEach(src=>{const a=element('a','source-link',src.title);a.href=src.url;a.target='_blank';a.rel='noopener noreferrer';sources.append(a)});box.append(sources)}
    box.scrollIntoView({behavior:'smooth',block:'nearest'}); toast('اكتمل تحليل الرابط والمعلومات العامة.');
  } catch(e){toast(e.message)} finally{button.disabled=false;button.innerHTML='حلّل الرابط ومؤشرات الاتساق <span>↗</span>';}
});



$('readiness-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = $('readiness-button'); button.disabled = true; button.textContent = 'جارٍ تجهيز الخطة…';
  const methods = [...document.querySelectorAll('input[name="r-method"]:checked')].map(el => el.value);
  const payload = {
    business_type: $('r-type').value, status: $('r-status').value, available_methods: methods,
    signage: $('r-signage').checked, tools: $('r-tools').checked, management_proof: $('r-management').checked,
    address_match: $('r-address').checked, phone_access: $('r-phone').checked, email_access: $('r-email').checked,
    mail_access: $('r-mail').checked, website_consistent: $('r-website').checked
  };
  try {
    const response = await fetch('/api/verification/readiness-plan', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
    const data = await response.json(); if (!response.ok) throw new Error(data.error || 'تعذر تجهيز الخطة');
    const box = $('readiness-results'); box.replaceChildren(); box.hidden = false; box.append(element('h3','',data.title));
    box.append(element('p','muted',`تصنيف الخطة: ${data.classification}`));
    if (!data.methods_user_observed.length) box.append(element('div','notice','لم تحددي خيارًا ظهر فعلًا. افتحي Get verified من حساب المالك وسجّلي الخيارات الموجودة؛ لن يخمّن الموقع خيارات مخفية.'));
    data.recommendations.forEach(item => { const card=element('article','finding'); card.append(element('span',`status ${item.priority==='important'?'':'status'}`,item.priority.toUpperCase()),element('h3','',item.title),element('p','',item.action)); box.append(card); });
    box.append(element('div','notice',data.decision_rule + ' ' + data.limitations.join(' ')));
    const sources=element('div','list-block'); sources.append(element('h3','','مراجع رسمية')); data.sources.forEach(src=>{const a=element('a','source-link',src.title);a.href=src.url;a.target='_blank';a.rel='noopener noreferrer';sources.append(a)}); box.append(sources);
    const download=element('button','secondary','تنزيل خطة الإثبات JSON'); download.type='button'; download.addEventListener('click',()=>{const blob=new Blob([JSON.stringify(data,null,2)],{type:'application/json;charset=utf-8'});const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download='gbp-verification-readiness-plan.json';document.body.append(a);a.click();a.remove();URL.revokeObjectURL(url)}); box.append(download);
    box.scrollIntoView({behavior:'smooth',block:'nearest'}); toast('اتجهزت خطة الإثبات والوسائل المتاحة.');
  } catch (e) { toast(e.message); } finally { button.disabled = false; button.innerHTML = 'اقترح خطة الإثبات <span>✦</span>'; }
});

$('evidence-form').addEventListener('submit', (event) => {
  event.preventDefault();
  if (!$('evidence-authorized').checked) { toast('أكدي وجود تصريح ونزاهة الاختبار أولًا.'); return; }
  const repeats = Number($('evidence-repeats').value);
  if (!Number.isInteger(repeats) || repeats < 1 || repeats > 20) { toast('عدد التكرارات يجب أن يكون من 1 إلى 20.'); return; }
  const before = $('evidence-before').value.trim();
  const after = $('evidence-after').value.trim();
  const changed = before !== after;
  const repeated = repeats >= 2;
  const report = {
    report_type: 'authorized_verification_hypothesis_observation',
    generated_at: new Date().toISOString(),
    hypothesis: $('evidence-title').value.trim(),
    declared_scope: $('evidence-scope').value.trim(),
    authorization_confirmed: true,
    observations: { before, after, text_changed: changed },
    repeat_count: repeats,
    evidence_notes: $('evidence-artifacts').value.trim(),
    classification: changed && repeated ? 'repeatable_association_not_confirmed_vulnerability' : 'single_or_unconfirmed_observation',
    interpretation: changed ? (repeated ? 'الفرق تكرر حسب سجل الباحثة؛ هذا يدعم وجود ارتباط يستحق المراجعة، لكنه لا يثبت سبب التغيير أو وجود ثغرة.' : 'لوحظ فرق في هذه التجربة؛ يلزم تكرار مضبوط واستبعاد التفسيرات البديلة قبل الاستنتاج.') : 'لم يسجّل النص اختلافًا بين الملاحظة قبل التغيير وبعده؛ لا تستنتجي عدم وجود خلل من هذه التجربة وحدها.',
    limitations: [
      'يعتمد التقرير على الملاحظات التي أدخلها الباحث ولا يتحقق مستقلًا من لقطات الشاشة أو نظام Google.',
      'تغيّر طريقة التحقق وحده لا يثبت وجود ثغرة أو تجاوز أمني.',
      'لا يتصل هذا النموذج بحساب Google ولا يغيّر أي ملف تجاري ولا يحاول فرض خيار تحقق.'
    ],
    next_steps: ['إرفاق أدلة مؤرخة مع إخفاء البيانات الشخصية غير الضرورية.', 'إعادة التجربة فقط ضمن نطاق تصريح واضح وبمتغير واحد كل مرة.', 'تسجيل النتائج السلبية والتفسيرات البديلة، ثم طلب مراجعة من الجهة المخوّلة قبل وصف النتيجة كثغرة.']
  };
  const box = $('evidence-results'); box.replaceChildren(); box.hidden = false;
  box.append(element('h3', '', 'تقرير تجربة الفرضية'));
  box.append(element('span', 'status', report.classification));
  box.append(element('p', '', report.interpretation));
  const details = element('pre', 'lab-result', JSON.stringify(report, null, 2)); box.append(details);
  const download = element('button', 'secondary', 'تنزيل التقرير بصيغة JSON'); download.type = 'button'; download.addEventListener('click', () => {
    const blob = new Blob([JSON.stringify(report, null, 2)], {type:'application/json;charset=utf-8'});
    const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = 'verification-hypothesis-report.json'; document.body.append(a); a.click(); a.remove(); URL.revokeObjectURL(url);
  }); box.append(download);
  box.append(element('div', 'notice', 'تصنيف التقرير آلي ومبدئي؛ لا يعلن وجود ثغرة في Google. يلزم دليل مستقل ومراجعة ضمن نطاق مصرح به.'));
  box.scrollIntoView({behavior:'smooth', block:'nearest'}); toast('تم تجهيز تقرير الملاحظات.');
});
