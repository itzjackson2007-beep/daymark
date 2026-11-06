const STORAGE_KEY = 'daymark.tasks.v1';
const PROFILE_KEY = 'daymark.profile.v1';
const SNAPSHOTS_KEY = 'daymark.snapshots.v1';
const REMINDER_INTERVAL_KEY = 'daymark.backup.interval';
const LAST_EXPORT_KEY = 'daymark.backup.lastExport';
const LAST_REMINDER_KEY = 'daymark.backup.lastReminder';
const PIN_FAILURE_KEY = 'daymark.pin.failures.v1';
const QUESTIONS = [
  'What was the name of your first school?',
  'What is the first name of a childhood friend?',
  'What city were you born in?',
  'What was the name of your first pet?',
  'What is your favorite book from childhood?',
  'What was the first concert you attended?',
  'What is a memorable street you grew up on?',
  'What was your childhood nickname?',
  'What is the first name of your favorite teacher?',
  'What was your favorite family vacation place?'
];
const PASSWORD_ITERATIONS = 180000;
const today = new Date();
const toISO = date => `${date.getFullYear()}-${String(date.getMonth()+1).padStart(2,'0')}-${String(date.getDate()).padStart(2,'0')}`;
const dateLong = new Intl.DateTimeFormat(undefined, { weekday:'long', month:'long', day:'numeric' });
const dateShort = new Intl.DateTimeFormat(undefined, { month:'short', day:'numeric' });
const $ = selector => document.querySelector(selector);
const $$ = selector => [...document.querySelectorAll(selector)];
const list = $('#task-list'), empty = $('#empty-state'), form = $('#task-form');
let profile = null;
try { profile = JSON.parse(localStorage.getItem(PROFILE_KEY) || 'null'); } catch { profile = null; }
let tasks = [];
if (!profile?.encryptionEnabled) { try { tasks = JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]'); } catch { tasks = []; } }
let vaultKey = null;
let sessionPin = null;
let lastSavedTasks = JSON.parse(JSON.stringify(tasks));
let persistenceQueue = Promise.resolve();
let currentFilter = 'all';
let toastTimer;
let recoveryStep = 0;
let recoveryVerified = false;
let pendingPhoto = null;
let pendingAvatarColor = null;
let removePhoto = false;
let pendingSecurityAction = 'change';
let securityMode = 'change';
let editingTaskId = null;
let selectedImportFile = null;
let recoveryAnswersForVault = [];
let backupPinResolver = null;
let deferredInstallPrompt = null;
const THEMES = ['forest','ocean','lavender','rose','sunset','amber','mint','sky','berry','slate','midnight','cocoa','cherry','teal','orchid','sand','emerald','graphite','lemon','coral'];

function buildPinInputs() {
  $$('[data-pin-group]').forEach(group=>{
    group.innerHTML=Array.from({length:6},(_,index)=>`<input type="password" maxlength="24" autocomplete="off" autocapitalize="none" autocorrect="off" spellcheck="false" data-pin-word="${index}" aria-label="Word ${index+1} of 6" placeholder="${index+1}">`).join('');
    const inputs=[...group.querySelectorAll('input')];
    inputs.forEach((input,index)=>{
      let advanceTimer;
      for(const eventName of ['copy','cut','paste','drop'])input.addEventListener(eventName,event=>event.preventDefault());
      input.addEventListener('contextmenu',event=>event.preventDefault());
      input.addEventListener('blur',()=>clearTimeout(advanceTimer));
      input.addEventListener('keydown',event=>{
        if((event.ctrlKey||event.metaKey)&&['c','x','v'].includes(event.key.toLowerCase())){event.preventDefault();return;}
        if(event.key===' '){event.preventDefault();inputs[Math.min(index+1,5)].focus();return;}
        if(event.key==='Backspace'&&!input.value&&index>0){inputs[index-1].focus();return;}
        if(event.key==='ArrowLeft'&&input.selectionStart===0&&index>0){event.preventDefault();inputs[index-1].focus();}
        if(event.key==='ArrowRight'&&input.selectionStart===input.value.length&&index<5){event.preventDefault();inputs[index+1].focus();}
        if(event.key==='Enter'){event.preventDefault();if(index<5)inputs[index+1].focus();else input.closest('form')?.requestSubmit();}
      });
      input.addEventListener('input',()=>{
        input.value=input.value.replace(/\s/g,'');clearTimeout(advanceTimer);
        if(input.value&&index<5)advanceTimer=setTimeout(()=>inputs[index+1].focus(),1500);
      });
    });
  });
}
buildPinInputs();
function pinParts(groupName){return [...document.querySelector(`[data-pin-group="${groupName}"]`).querySelectorAll('input')].map(input=>input.value.trim());}
function readPin(groupName){return pinParts(groupName).filter(Boolean).join(' ');}
function completePin(groupName){const words=pinParts(groupName);return words.length===6&&words.every(Boolean);}
function clearPin(groupName){document.querySelectorAll(`[data-pin-group="${groupName}"] input`).forEach(input=>input.value='');}
function focusPin(groupName,index=0){document.querySelector(`[data-pin-group="${groupName}"] input:nth-child(${index+1})`)?.focus();}

document.querySelector('#today-date').textContent = dateLong.format(today);
document.querySelector('#date-label').textContent = new Intl.DateTimeFormat(undefined, { month:'long', year:'numeric' }).format(today);
document.querySelector('#task-date').value = toISO(today);

function bytesToHex(bytes) { return [...bytes].map(byte => byte.toString(16).padStart(2,'0')).join(''); }
function randomSalt() { const bytes = crypto.getRandomValues(new Uint8Array(16)); return bytesToHex(bytes); }
function normalizeAnswer(answer) { return answer.trim().normalize('NFKC').toLocaleLowerCase(); }
function applyTheme(theme, persist=true) {
  const selected=THEMES.includes(theme)?theme:'forest';
  document.body.dataset.theme=selected;
  const picker=$('#theme-select'); if(picker)picker.value=selected;
  if(persist)localStorage.setItem('daymark.theme',selected);
}
async function deriveHash(secret, salt) {
  if (!crypto.subtle) throw new Error('Secure PIN storage is unavailable in this browser. Open Daymark in a current browser to continue.');
  const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({name:'PBKDF2', salt:Uint8Array.from(salt.match(/.{2}/g), byte=>parseInt(byte,16)), iterations:PASSWORD_ITERATIONS, hash:'SHA-256'}, material, 256);
  return bytesToHex(new Uint8Array(bits));
}
async function createSecret(secret) { const salt=randomSalt(); return {salt,hash:await deriveHash(secret,salt)}; }
function readPinFailures(){try{const value=JSON.parse(localStorage.getItem(PIN_FAILURE_KEY)||'null');return{count:Number.isInteger(value?.count)&&value.count>0?value.count:0,lockedUntil:Number.isFinite(value?.lockedUntil)?value.lockedUntil:0};}catch{return{count:0,lockedUntil:0};}}
function pinLockRemaining(){return Math.max(0,readPinFailures().lockedUntil-Date.now());}
function pinLockMessage(){const seconds=Math.ceil(pinLockRemaining()/1000);return seconds>=60?`Too many incorrect PIN attempts. Try again in ${Math.ceil(seconds/60)} minute${Math.ceil(seconds/60)===1?'':'s'}.`:`Too many incorrect PIN attempts. Try again in ${seconds} second${seconds===1?'':'s'}.`;}
function recordPinFailure(){const current=readPinFailures(),count=current.count+1;const lockMs=count>=5?Math.min(15*60*1000,30000*2**Math.min(count-5,5)):0;const value={count,lockedUntil:lockMs?Date.now()+lockMs:0};try{localStorage.setItem(PIN_FAILURE_KEY,JSON.stringify(value));}catch{}return value;}
function clearPinFailures(){try{localStorage.removeItem(PIN_FAILURE_KEY);}catch{}}
async function matchesProfilePin(pin){
  const words=pin.split(' '),candidates=[pin];
  if(profile.pinVersion!==2&&words.filter(Boolean).length===1)candidates.push(words.find(Boolean));
  for(const candidate of [...new Set(candidates)])if(candidate&&await deriveHash(candidate,profile.salt)===profile.hash)return true;
  return false;
}
function saveProfile(showError=true) {
  try { localStorage.setItem(PROFILE_KEY, JSON.stringify(profile)); return true; }
  catch { if(showError)showMessage('Could not save your profile','Browser storage may be full. Try a smaller picture or remove unused site data.','warning'); return false; }
}
function escapeHTML(value) { return String(value).replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char])); }

function showAuth(view) {
  document.body.classList.add('is-locked');
  const setup=view==='setup';
  const login=view==='login';
  const recovery=view==='recovery';
  $('#auth-title').textContent=setup?'Create your profile':login?'Welcome back':recoveryVerified?'Reset your PIN':'Recover your profile';
  $('#auth-eyebrow').textContent=setup?'YOUR PRIVATE WORKSPACE':login?'YOUR WORKSPACE IS LOCKED':'ACCOUNT RECOVERY';
  $('#auth-intro').textContent=setup?'Set up your name and a six-word PIN to keep this browser profile private.':login?`Enter the six-word PIN for ${profile?.username || 'your profile'} to continue.`:recoveryVerified?'Your recovery answers checked out. Choose a new six-word PIN to unlock Daymark.':'Answer your three recovery questions to reset your PIN.';
  $('#setup-form').classList.toggle('hidden',!setup);
  $('#login-form').classList.toggle('hidden',!login);
  $('#recovery-form').classList.toggle('hidden',!recovery);
  $('#auth-symbol').textContent=setup?'◉':login?'◈':'⌑';
  if (setup) $('#setup-name').focus();
  if (login) { $('#login-error').textContent=pinLockRemaining()?pinLockMessage():'';focusPin('login-password'); }
  if (recovery) $('#recovery-answer').focus();
}
function unlock() { document.body.classList.remove('is-locked'); renderProfile(); render(); refreshSnapshotOptions(); scheduleBackupReminder(); }
function fillQuestionSelect(select) {
  select.innerHTML='<option value="">Choose a question</option>'+QUESTIONS.map((question,index)=>`<option value="${index}">${escapeHTML(question)}</option>`).join('')+'<option value="custom">Write my own question…</option>';
}
$$('.question-select').forEach(fillQuestionSelect);
function associatedCustomField(select){return $(`#${select.dataset.set}-custom-q${select.id.match(/q(\d+)$/)?.[1]}`);}
function questionLabelForControl(select){if(!select.value)return '';if(select.value==='custom')return associatedCustomField(select)?.value.trim()||'';return QUESTIONS[Number(select.value)]||'';}
function syncQuestionSet(setName){
  const selects=$$('.question-select').filter(select=>select.dataset.set===setName);
  selects.forEach(select=>{
    const custom=associatedCustomField(select),isCustom=select.value==='custom';
    custom.classList.toggle('hidden',!isCustom);custom.required=isCustom;
    const used=selects.filter(other=>other!==select).map(questionLabelForControl).filter(Boolean).map(normalizeAnswer);
    [...select.options].forEach(option=>{
      if(!option.value||option.value==='custom'){option.disabled=false;return;}
      option.disabled=used.includes(normalizeAnswer(QUESTIONS[Number(option.value)]||''));
    });
  });
  const prompts=selects.map(questionLabelForControl).filter(Boolean).map(normalizeAnswer);
  selects.forEach(select=>{const custom=associatedCustomField(select);const duplicate=select.value==='custom'&&prompts.filter(prompt=>prompt===normalizeAnswer(custom.value)).length>1;custom.setCustomValidity(duplicate?'Choose a different recovery question.':'');});
}
['setup','security'].forEach(setName=>syncQuestionSet(setName));
$$('.question-select').forEach(select=>select.addEventListener('change',()=>syncQuestionSet(select.dataset.set)));
$$('.question-custom').forEach(input=>input.addEventListener('input',()=>syncQuestionSet(input.id.startsWith('setup-')?'setup':'security')));
function getQuestionSet(prefix) {
  return [1,2,3].map(number=>({question:$(`#${prefix}-q${number}`).value,customQuestion:$(`#${prefix}-custom-q${number}`).value.trim(),answer:$(`#${prefix}-a${number}`).value}));
}
function validateQuestions(answers) {
  const labels=answers.map(item=>item.question==='custom'?item.customQuestion:item.question!==''?QUESTIONS[Number(item.question)]||'':'');
  return answers.every((item,index)=>Boolean(labels[index].trim())&&Boolean(normalizeAnswer(item.answer)))&&new Set(labels.map(normalizeAnswer)).size===3;
}
async function protectAnswers(answers) {
  return Promise.all(answers.map(async item=>({question:item.question==='custom'?'custom':Number(item.question),...(item.question==='custom'?{prompt:item.customQuestion.trim()}:{}),...await createSecret(normalizeAnswer(item.answer))})));
}

function renderProfile() {
  if (!profile) return;
  $('#sidebar-username').textContent=profile.username;
  $('#profile-name').value=profile.username;
  $('#theme-select').value=THEMES.includes(localStorage.getItem('daymark.theme'))?localStorage.getItem('daymark.theme'):'forest';
  $('#avatar-color').value=profile.avatarColor||'#e7d8c6';
  const enabled=profile.passwordEnabled!==false;
  $('#password-state').textContent=enabled?'PIN protection is on':'PIN protection is off';
  $('#password-toggle').textContent=enabled?'Disable PIN':'Enable PIN';
  $('#change-password').textContent=enabled?'Change PIN':'Set a PIN';
  $('#lock-profile').classList.toggle('hidden',!enabled);
  $('#encryption-status').textContent=profile.encryptionEnabled?'Task backups and saved tasks are encrypted with your PIN.':'Tasks are stored in this browser.';
  $('#encryption-toggle').textContent=profile.encryptionEnabled?'Turn off encryption':'Encrypt tasks';
  $('#encryption-toggle').disabled=!profile.encryptionEnabled&&!enabled;
  for (const id of ['sidebar-avatar','top-avatar','profile-avatar']) {
    const element=$(`#${id}`);
    const color=profile.avatarColor||'#e7d8c6';
    element.style.backgroundColor=color;element.style.color=avatarTextColor(color);
    if (profile.photo) element.innerHTML=`<img src="${profile.photo}" alt="">`;
    else element.textContent=(profile.username.trim()[0] || 'Y').toUpperCase();
  }
}
function updateAuthPhoto() {
  const color=pendingAvatarColor||profile?.avatarColor||'#e7d8c6';
  const photo=pendingPhoto||(removePhoto?null:profile?.photo);
  const letter=($('#profile-name')?.value.trim()[0]||profile?.username?.trim()[0]||'Y').toUpperCase();
  const preview=$('#profile-avatar');preview.style.backgroundColor=color;preview.style.color=avatarTextColor(color);
  if(photo)preview.innerHTML=`<img src="${photo}" alt="">`;else preview.textContent=letter;
}
function avatarTextColor(hex){const match=/^#([\da-f]{6})$/i.exec(hex);if(!match)return '#4b3b2c';const value=parseInt(match[1],16),r=value>>16,g=value>>8&255,b=value&255,brightness=(r*299+g*587+b*114)/1000;return brightness>158?'#3b3328':'#fff';}

function cloneData(value){return JSON.parse(JSON.stringify(value));}
function loadSnapshots(){try{return JSON.parse(localStorage.getItem(SNAPSHOTS_KEY)||'[]');}catch{return [];}}
async function addSnapshot(previousTasks){
  if(!previousTasks.length)return;
  const id=crypto.randomUUID?.()||String(Date.now()),createdAt=Date.now(),backup=await DaymarkData.createTaskBackup(previousTasks);
  let entry;
  if(profile?.encryptionEnabled){if(!vaultKey)throw new Error('Unlock the encrypted data before making a backup.');entry={id,createdAt,...await DaymarkData.encryptObject(vaultKey,{backup})};}
  else entry={id,createdAt,encrypted:false,backup};
  const history=loadSnapshots();history.unshift(entry);localStorage.setItem(SNAPSHOTS_KEY,JSON.stringify(history.slice(0,8)));
}
async function refreshSnapshotOptions(){
  const select=$('#restore-select');if(!select)return;const history=loadSnapshots();select.innerHTML='';
  if(!history.length){select.innerHTML='<option value="">No snapshots yet</option>';return;}
  select.innerHTML='<option value="">Choose a saved snapshot</option>'+history.map(item=>`<option value="${escapeHTML(item.id)}">${new Intl.DateTimeFormat(undefined,{dateStyle:'medium',timeStyle:'short'}).format(new Date(item.createdAt))} · ${item.encrypted?'encrypted':''}</option>`).join('');
}
async function convertSnapshotEncryption(key,encrypt){
  const history=loadSnapshots(),converted=[];
  for(const item of history){
    if(encrypt&&!item.encrypted){const backup=item.backup?await DaymarkData.verifyTaskBackup(item.backup):await DaymarkData.createTaskBackup(item.tasks||[]);const encrypted=await DaymarkData.encryptObject(key,{backup});converted.push({id:item.id,createdAt:item.createdAt,...encrypted});}
    else if(!encrypt&&item.encrypted){const data=await DaymarkData.decryptObject(key,item),backup=data.backup?await DaymarkData.verifyTaskBackup(data.backup):await DaymarkData.createTaskBackup(data.tasks||[]);converted.push({id:item.id,createdAt:item.createdAt,encrypted:false,backup});}
    else converted.push(item);
  }
  localStorage.setItem(SNAPSHOTS_KEY,JSON.stringify(converted));
}
function persist(){
  const next=cloneData(tasks);
  const operation=persistenceQueue.then(async()=>{
    if(JSON.stringify(lastSavedTasks)!==JSON.stringify(next))await addSnapshot(lastSavedTasks);
    if(profile?.encryptionEnabled){
      if(!vaultKey)throw new Error('Unlock the encrypted data before saving tasks.');
      const previousVault=profile.dataVault;
      profile.dataVault=await DaymarkData.saveEncryptedTasks(previousVault,vaultKey,next);
      if(!saveProfile(false)){profile.dataVault=previousVault;throw new Error('Could not save the encrypted task data. Browser storage may be full.');}
      localStorage.removeItem(STORAGE_KEY);
    }else localStorage.setItem(STORAGE_KEY,JSON.stringify(next));
    lastSavedTasks=next;refreshSnapshotOptions();
    return true;
  });
  persistenceQueue=operation.catch(error=>{showMessage('Could not save your data',error.message||'Browser storage may be full. Export a backup and try again.','warning');return false;});
  return persistenceQueue;
}
function isToday(task) { return task.due === toISO(today); }
function visibleTasks() {
  const sorted=[...tasks].sort((a,b)=>Number(Boolean(b.pinned))-Number(Boolean(a.pinned))||Number(a.done)-Number(b.done)||(a.due||'9999').localeCompare(b.due||'9999')||b.created-a.created);
  if(currentFilter==='today')return sorted.filter(task=>isToday(task)&&!task.done);
  if(currentFilter==='upcoming')return sorted.filter(task=>task.due&&task.due>toISO(today)&&!task.done);
  if(currentFilter==='done')return sorted.filter(task=>task.done);
  if(currentFilter==='pinned')return sorted.filter(task=>task.pinned);
  return sorted;
}
function render() {
  const active=tasks.filter(task=>!task.done).length;
  const todayCount=tasks.filter(task=>isToday(task)&&!task.done).length;
  $('#all-count').textContent=active; $('#today-count').textContent=todayCount;
  const completed=tasks.filter(task=>task.done).length,total=tasks.length;
  $('#progress-text').textContent=`${completed} of ${total} done`;
  $('#progress-fill').style.width=`${total?Math.round(completed/total*100):0}%`;
  const labels={all:['All tasks','Your tasks','Make room for what matters.'],today:['Today','Today','One day, one step at a time.'],upcoming:['Upcoming','Coming up','A little planning goes a long way.'],pinned:['Pinned','Pinned tasks','Keep your priorities close.'],done:['Completed','Completed','Look how far you’ve come.']};
  const [crumb,heading,title]=labels[currentFilter]; $('#crumb').textContent=crumb; $('#list-title').textContent=heading; $('#page-title').textContent=title;
  const shown=visibleTasks();
  $('#clear-tasks').classList.toggle('hidden',tasks.length===0);
  $('#task-summary').textContent=currentFilter==='today'?`${todayCount} task${todayCount===1?'':'s'} to focus on`:currentFilter==='upcoming'?`${shown.length} task${shown.length===1?'':'s'} on the horizon`:currentFilter==='pinned'?`${shown.length} pinned task${shown.length===1?'':'s'}`:currentFilter==='done'?`${shown.length} task${shown.length===1?'':'s'} completed`:`${active} active task${active===1?'':'s'} · ${completed} completed`;
  list.innerHTML=shown.map(task=>{
    const due=task.due?new Date(`${task.due}T00:00:00`):null;
    const overdue=due&&task.due<toISO(today)&&!task.done;
    const dateText=!due?'':isToday(task)?'Today':task.due===toISO(new Date(today.getTime()+86400000))?'Tomorrow':dateShort.format(due);
    const priority=task.priority==='normal'?'':`<span class="priority ${task.priority}">${task.priority==='high'?'High':'Low'} priority</span>`;
    return `<article class="task-row ${task.done?'completed':''} ${task.pinned?'pinned':''}" data-id="${escapeHTML(task.id)}"><button class="check-button" aria-label="${task.done?'Mark incomplete':'Complete task'}">${task.done?'✓':''}</button><div class="task-body"><span class="task-name">${escapeHTML(task.title)}</span><div class="task-meta">${dateText?`<span class="task-date ${overdue?'overdue':''}">${overdue?'Overdue · ':''}${dateText}</span>`:''}${priority}</div></div><button class="edit-button" aria-label="Edit task" title="Edit task">✎</button><button class="pin-button ${task.pinned?'is-pinned':''}" aria-label="${task.pinned?'Unpin task':'Pin task'}" title="${task.pinned?'Unpin task':'Pin task'}">${task.pinned?'★':'☆'}</button><button class="delete-button" aria-label="Delete task" title="Delete task">×</button></article>`;
  }).join('');
  empty.classList.toggle('hidden',shown.length>0);
  if(!shown.length){const messages={all:['Nothing on your list yet','Give your next task a home and get it off your mind.'],today:['You’re all caught up','Enjoy the breathing room, or add something for today.'],upcoming:['No upcoming tasks','Add a due date to a task and it will show up here.'],pinned:['No pinned tasks','Pin any task with the star button to keep it close.'],done:['No completed tasks yet','Finish a task and it’ll find its way here.']};$('#empty-state h3').textContent=messages[currentFilter][0];$('#empty-state p').textContent=messages[currentFilter][1];$('#empty-add').classList.toggle('hidden',currentFilter==='done'||currentFilter==='pinned');}
}

function notify(message,type='success') {
  const toast=$('#toast'); toast.textContent=message; toast.dataset.type=type; toast.classList.add('show'); clearTimeout(toastTimer); toastTimer=setTimeout(()=>toast.classList.remove('show'),2600);
}
function showMessage(title,message,type='info') {
  $('#message-title').textContent=title; $('#message-copy').textContent=message; $('#message-icon').textContent=type==='warning'?'!':type==='success'?'✓':'i';
  $('#message-cancel').classList.add('hidden'); $('#message-ok').textContent='Got it'; $('#message-dialog').showModal();
}
function confirmMessage(title,message,confirmText='Continue') {
  $('#message-title').textContent=title; $('#message-copy').textContent=message; $('#message-icon').textContent='?'; $('#message-cancel').classList.remove('hidden'); $('#message-cancel').textContent='Cancel'; $('#message-ok').textContent=confirmText;
  const dialog=$('#message-dialog'); dialog.showModal();
  return new Promise(resolve=>{
    const finish=value=>{dialog.close();$('#message-ok').removeEventListener('click',yes);$('#message-cancel').removeEventListener('click',no);dialog.removeEventListener('cancel',cancel);resolve(value);};
    const yes=()=>finish(true),no=()=>finish(false),cancel=event=>{event.preventDefault();finish(false);};
    $('#message-ok').addEventListener('click',yes);$('#message-cancel').addEventListener('click',no);dialog.addEventListener('cancel',cancel);
  });
}
function setError(id,message) { $(id).textContent=message; }

$('#setup-form').addEventListener('submit',async event=>{
  event.preventDefault(); setError('#setup-error','');
  const username=$('#setup-name').value.trim(),password=readPin('setup-password'),confirm=readPin('setup-confirm'),answers=getQuestionSet('setup');
  if(!username)return setError('#setup-error','Please enter a username.');
  if(!completePin('setup-password')||!completePin('setup-confirm'))return setError('#setup-error','Enter a value in all six boxes for both PIN fields.');
  if(password!==confirm)return setError('#setup-error','The two six-word PIN entries do not match.');
  if(!validateQuestions(answers))return setError('#setup-error','Choose three different recovery questions and fill in every answer.');
  const submit=$('#setup-form button[type="submit"]');submit.disabled=true;submit.textContent='Creating profile…';
  try{const protectedAnswers=await protectAnswers(answers),passwordSecret=await createSecret(password);profile={username,photo:null,passwordEnabled:true,pinVersion:2,createdAt:Date.now(),...passwordSecret,recovery:protectedAnswers};sessionPin=password;lastSavedTasks=cloneData(tasks);if(saveProfile()){clearPinFailures();renderProfile();unlock();notify(`Welcome to Daymark, ${username}`);}}
  catch(error){setError('#setup-error',error.message||'Could not create your profile. Please try again.');}
  finally{submit.disabled=false;submit.innerHTML='Create profile <span>→</span>';}
});

$('#login-form').addEventListener('submit',async event=>{
  event.preventDefault();setError('#login-error','');const password=readPin('login-password'),words=pinParts('login-password');
  try{
    if(pinLockRemaining())return setError('#login-error',pinLockMessage());
    if(profile.pinVersion===2&&!completePin('login-password'))return setError('#login-error','Enter all six words of your PIN.');
    const matched=await matchesProfilePin(password);
    if(!matched){recordPinFailure();setError('#login-error',pinLockRemaining()?pinLockMessage():'That PIN did not match. Try again or use your recovery questions.');focusPin('login-password');return;}
    clearPinFailures();
    if(profile.encryptionEnabled){const opened=await DaymarkData.unlockVaultByPin(profile.dataVault,password);vaultKey=opened.key;tasks=opened.tasks;}
    else{try{tasks=JSON.parse(localStorage.getItem(STORAGE_KEY)||'[]');}catch{tasks=[];}vaultKey=null;}
    sessionPin=password;lastSavedTasks=cloneData(tasks);clearPin('login-password');unlock();notify(`Welcome back, ${profile.username}`);
    if(profile.pinVersion!==2){notify('Create a six-word PIN to finish updating your profile','warning');openSecurityForm('migration');}
  }
  catch(error){setError('#login-error',error.message||'Could not check the PIN.');}
});

$('#forgot-link').addEventListener('click',()=>{recoveryStep=0;recoveryVerified=false;recoveryAnswersForVault=[];$('#recovery-form').reset();$('#recovery-reset').classList.add('hidden');$('#recovery-question-wrap').classList.remove('hidden');$('#recovery-submit').textContent='Continue →';updateRecoveryPrompt();showAuth('recovery');});
function recoveryQuestionText(item){return item.question==='custom'?item.prompt:QUESTIONS[Number(item.question)];}
function updateRecoveryPrompt(){const item=profile?.recovery?.[recoveryStep];$('#recovery-progress').textContent=`Question ${recoveryStep+1} of 3`;$('#recovery-question-label').textContent=recoveryQuestionText(item);$('#recovery-error').textContent='';}
$('#recovery-form').addEventListener('submit',async event=>{
  event.preventDefault();setError('#recovery-error','');
  if(!recoveryVerified){const answer=$('#recovery-answer').value;try{const saved=profile.recovery[recoveryStep],normalized=normalizeAnswer(answer),attempt=await deriveHash(normalized,saved.salt);if(attempt!==saved.hash){setError('#recovery-error','That answer does not match. Check spelling and try again.');return;}recoveryAnswersForVault.push(normalized);recoveryStep++;$('#recovery-answer').value='';if(recoveryStep<3){updateRecoveryPrompt();return;}if(profile.encryptionEnabled){const opened=await DaymarkData.unlockVaultByRecovery(profile.dataVault,recoveryAnswersForVault);vaultKey=opened.key;tasks=opened.tasks;lastSavedTasks=cloneData(tasks);}recoveryVerified=true;$('#recovery-question-wrap').classList.add('hidden');$('#recovery-reset').classList.remove('hidden');$('#recovery-progress').textContent='Identity confirmed';$('#recovery-submit').textContent='Set new PIN →';$('#auth-title').textContent='Reset your PIN';$('#auth-intro').textContent='Your recovery answers checked out. Choose a new six-word PIN to unlock Daymark.';}
    catch(error){setError('#recovery-error',error.message||'Could not verify that answer.');}return;}
  const password=readPin('recovery-new-password'),confirm=readPin('recovery-new-confirm');if(!completePin('recovery-new-password')||!completePin('recovery-new-confirm'))return setError('#recovery-error','Enter a value in all six PIN boxes.');if(password!==confirm)return setError('#recovery-error','Those six entries do not match.');
  const previousProfile=cloneData(profile),previousPin=sessionPin;
  try{if(profile.encryptionEnabled)profile.dataVault=await DaymarkData.rewrapPin(profile.dataVault,vaultKey,password);sessionPin=password;Object.assign(profile,await createSecret(password),{pinVersion:2,passwordEnabled:true});if(saveProfile(false)){clearPinFailures();unlock();$('#recovery-form').reset();notify('PIN reset. Your profile is unlocked.');}else throw new Error('Could not save the PIN change.');}
  catch(error){profile=previousProfile;sessionPin=previousPin;setError('#recovery-error',error.message||'Could not reset your PIN.');}
});
$('#back-login').addEventListener('click',()=>showAuth('login'));

function showForm(){form.classList.remove('hidden');$('#task-title').focus();}
$('#open-form').addEventListener('click',showForm);$('#empty-add').addEventListener('click',showForm);$('#close-form').addEventListener('click',()=>form.classList.add('hidden'));
form.addEventListener('submit',event=>{event.preventDefault();const title=$('#task-title').value.trim();if(!title)return;tasks.push({id:crypto.randomUUID?.()||String(Date.now()),title,due:$('#task-date').value,priority:$('#task-priority').value,done:false,created:Date.now()});persist();render();form.reset();$('#task-date').value=toISO(today);$('#task-priority').value='normal';form.classList.add('hidden');notify('Task added to your list');});
list.addEventListener('click',async event=>{
  const row=event.target.closest('.task-row');if(!row)return;const task=tasks.find(item=>item.id===row.dataset.id);if(!task)return;
  if(event.target.closest('.edit-button')){editingTaskId=task.id;$('#edit-task-title').value=task.title;$('#edit-task-date').value=task.due||'';$('#edit-task-priority').value=task.priority||'normal';$('#edit-task-error').textContent='';$('#task-edit-dialog').showModal();return;}
  if(event.target.closest('.check-button')){task.done=!task.done;task.completedAt=task.done?toISO(new Date()):null;persist();render();notify(task.done?'Nice work — task completed':'Task moved back to your list');}
  if(event.target.closest('.pin-button')){task.pinned=!task.pinned;persist();render();notify(task.pinned?'Task pinned':'Task unpinned');}
  if(event.target.closest('.delete-button')){const approved=await confirmMessage('Delete this task?','This task will be removed from your Daymark list.','Delete task');if(!approved)return;tasks=tasks.filter(item=>item.id!==task.id);persist();render();notify('Task deleted');}
});
$('#task-edit-form').addEventListener('submit',event=>{event.preventDefault();const task=tasks.find(item=>item.id===editingTaskId),title=$('#edit-task-title').value.trim();if(!task)return $('#task-edit-dialog').close();if(!title)return setError('#edit-task-error','Please enter a task name.');task.title=title;task.due=$('#edit-task-date').value;task.priority=$('#edit-task-priority').value;persist();render();$('#task-edit-dialog').close();notify('Task updated');});
$('#clear-tasks').addEventListener('click',async()=>{
  if(!tasks.length)return;
  const count=tasks.length;
  const first=await confirmMessage('Clear all tasks?',`This will remove all ${count} task${count===1?'':'s'} from your list. Continue?`,'Continue');
  if(!first)return;
  const second=await confirmMessage('One last check…',`All ${count} task${count===1?'':'s'} will disappear. Your future self might ask where the to-do list went—still clear the lot?`,'Yep, clear them');
  if(!second)return;
  tasks=[];persist();render();notify('All tasks cleared');
});
$$('.nav-item').forEach(button=>button.addEventListener('click',()=>{currentFilter=button.dataset.filter;$$('.nav-item').forEach(item=>item.classList.toggle('active',item===button));render();}));
$('#theme-toggle').addEventListener('click',()=>{document.body.classList.toggle('dark');localStorage.setItem('daymark.dark',document.body.classList.contains('dark')?'1':'0');});
if(localStorage.getItem('daymark.dark')==='1')document.body.classList.add('dark');
applyTheme(localStorage.getItem('daymark.theme')||'forest',false);

$('#profile-open').addEventListener('click',()=>{$('#profile-error').textContent='';pendingPhoto=null;pendingAvatarColor=null;removePhoto=false;renderProfile();updateAuthPhoto();$('#profile-dialog').showModal();});
$('#top-profile-open').addEventListener('click',()=>$('#profile-open').click());
$$('[data-close-dialog]').forEach(button=>button.addEventListener('click',()=>button.closest('dialog').close()));
$('#profile-photo').addEventListener('change',event=>{
  const file=event.target.files?.[0];if(!file)return;if(!file.type.startsWith('image/')){showMessage('Choose an image','Select an image file from your device library.','warning');return;}
  const reader=new FileReader();reader.onload=()=>{const image=new Image();image.onload=()=>{const canvas=document.createElement('canvas'),scale=Math.min(1,512/Math.max(image.width,image.height));canvas.width=Math.round(image.width*scale);canvas.height=Math.round(image.height*scale);canvas.getContext('2d').drawImage(image,0,0,canvas.width,canvas.height);pendingPhoto=canvas.toDataURL('image/jpeg',.78);removePhoto=false;updateAuthPhoto();};image.src=reader.result;};reader.readAsDataURL(file);
});
$('#reset-profile-photo').addEventListener('click',()=>{pendingPhoto=null;removePhoto=true;$('#profile-photo').value='';updateAuthPhoto();notify('Initial avatar preview restored');});
$('#profile-name').addEventListener('input',updateAuthPhoto);
$('#avatar-color').addEventListener('input',event=>{pendingAvatarColor=event.target.value;updateAuthPhoto();});
$('#profile-form').addEventListener('submit',event=>{event.preventDefault();const username=$('#profile-name').value.trim();if(!username){setError('#profile-error','Please add a username.');return;}profile.username=username;profile.avatarColor=pendingAvatarColor||profile.avatarColor||'#e7d8c6';if(removePhoto)profile.photo=null;else if(pendingPhoto)profile.photo=pendingPhoto;if(saveProfile()){renderProfile();$('#profile-dialog').close();notify('Profile saved');}});
function openEncryptionDialog(){
  const container=$('#encryption-answers');container.replaceChildren();
  profile.recovery.forEach((item,index)=>{const label=document.createElement('label');label.className='field-label';const question=document.createElement('span');question.textContent=recoveryQuestionText(item);const input=document.createElement('input');input.type='password';input.autocomplete='off';input.id=`vault-answer-${index+1}`;input.placeholder='Recovery answer';input.required=true;label.append(question,input);container.append(label);});
  $('#encryption-error').textContent='';$('#encryption-dialog').showModal();
}
$('#encryption-toggle').addEventListener('click',async()=>{
  if(profile.encryptionEnabled){
    if(!vaultKey)return showMessage('Unlock Daymark first','Your task encryption key is available only while your profile is unlocked.','warning');
    const approved=await confirmMessage('Turn off task encryption?','Your tasks and saved snapshots will be stored unencrypted in this browser. Continue?','Turn off encryption');if(!approved)return;
    const oldProfile=profile,oldProfileRaw=localStorage.getItem(PROFILE_KEY),oldTasksRaw=localStorage.getItem(STORAGE_KEY),oldSnapshotsRaw=localStorage.getItem(SNAPSHOTS_KEY);
    try{
      await convertSnapshotEncryption(vaultKey,false);
      localStorage.setItem(STORAGE_KEY,JSON.stringify(tasks));
      profile={...profile,encryptionEnabled:false};delete profile.dataVault;
      if(!saveProfile(false))throw new Error('Could not save the profile change.');
      vaultKey=null;lastSavedTasks=cloneData(tasks);renderProfile();refreshSnapshotOptions();notify('Task encryption disabled');
    }catch(error){
      profile=oldProfile;
      try{if(oldTasksRaw===null)localStorage.removeItem(STORAGE_KEY);else localStorage.setItem(STORAGE_KEY,oldTasksRaw);if(oldSnapshotsRaw===null)localStorage.removeItem(SNAPSHOTS_KEY);else localStorage.setItem(SNAPSHOTS_KEY,oldSnapshotsRaw);if(oldProfileRaw===null)localStorage.removeItem(PROFILE_KEY);else localStorage.setItem(PROFILE_KEY,oldProfileRaw);}catch{}
      showMessage('Could not turn off encryption',error.message||'Your encrypted data was left unchanged.','warning');
    }
    return;
  }
  if(profile.passwordEnabled===false||!sessionPin)return showMessage('Set a PIN first','Local task encryption uses your six-word PIN. Enable PIN protection before encrypting tasks.','warning');
  openEncryptionDialog();
});
$('#encryption-form').addEventListener('submit',async event=>{
  event.preventDefault();setError('#encryption-error','');const answers=profile.recovery.map((item,index)=>normalizeAnswer($(`#vault-answer-${index+1}`).value));
  try{
    for(let index=0;index<answers.length;index++){const saved=profile.recovery[index],attempt=await deriveHash(answers[index],saved.salt);if(attempt!==saved.hash)return setError('#encryption-error',`Recovery answer ${index+1} does not match.`);}
    const previousProfile=profile,previousProfileRaw=localStorage.getItem(PROFILE_KEY),previousTasksRaw=localStorage.getItem(STORAGE_KEY),previousSnapshotsRaw=localStorage.getItem(SNAPSHOTS_KEY),created=await DaymarkData.createVault(tasks,sessionPin,answers);
    try{
      vaultKey=created.key;await convertSnapshotEncryption(vaultKey,true);profile={...profile,dataVault:created.vault,encryptionEnabled:true};
      if(!saveProfile(false))throw new Error('Could not save the encrypted profile.');
      localStorage.removeItem(STORAGE_KEY);lastSavedTasks=cloneData(tasks);$('#encryption-dialog').close();$('#encryption-form').reset();renderProfile();refreshSnapshotOptions();notify('Local tasks are now encrypted');
    }catch(error){
      profile=previousProfile;vaultKey=null;
      try{if(previousTasksRaw===null)localStorage.removeItem(STORAGE_KEY);else localStorage.setItem(STORAGE_KEY,previousTasksRaw);if(previousSnapshotsRaw===null)localStorage.removeItem(SNAPSHOTS_KEY);else localStorage.setItem(SNAPSHOTS_KEY,previousSnapshotsRaw);if(previousProfileRaw===null)localStorage.removeItem(PROFILE_KEY);else localStorage.setItem(PROFILE_KEY,previousProfileRaw);}catch{}
      throw error;
    }
  }catch(error){setError('#encryption-error',error.message||'Could not encrypt tasks.');}
});
$('#backup-open').addEventListener('click',()=>{$('#backup-error').textContent='';$('#backup-reminder-interval').value=localStorage.getItem(REMINDER_INTERVAL_KEY)||'7';refreshSnapshotOptions();$('#profile-dialog').close();$('#backup-dialog').showModal();});
$('#backup-reminder-interval').addEventListener('change',event=>localStorage.setItem(REMINDER_INTERVAL_KEY,event.target.value));
function requestBackupPin(mode){
  const dialog=$('#backup-pin-dialog');
  $('#backup-pin-error').textContent='';clearPin('backup-password');
  if(mode==='profile'){
    $('#backup-pin-title').textContent='Confirm your profile PIN';
    $('#backup-pin-copy').textContent='Enter your current six-word profile PIN to encrypt this backup.';
    $('#backup-pin-label').childNodes[0].textContent='Current six-word PIN';
    $('#backup-pin-submit').textContent='Verify PIN';
  }else{
    $('#backup-pin-title').textContent='Enter backup PIN';
    $('#backup-pin-copy').textContent='Enter the six-word PIN used when this backup was downloaded.';
    $('#backup-pin-label').childNodes[0].textContent='Six-word PIN';
    $('#backup-pin-submit').textContent='Unlock backup';
  }
  dialog.showModal();focusPin('backup-password');
  return new Promise(resolve=>{backupPinResolver=resolve;});
}
function finishBackupPin(value){
  if(!backupPinResolver)return;
  const resolve=backupPinResolver;backupPinResolver=null;
  if($('#backup-pin-dialog').open)$('#backup-pin-dialog').close();
  resolve(value);
}
$('#backup-pin-dialog').addEventListener('close',()=>{if(backupPinResolver){const resolve=backupPinResolver;backupPinResolver=null;resolve(null);}});
$('#backup-pin-cancel').addEventListener('click',()=>finishBackupPin(null));
$('#backup-pin-form').addEventListener('submit',async event=>{
  event.preventDefault();$('#backup-pin-error').textContent='';
  if(!completePin('backup-password'))return setError('#backup-pin-error','Enter all six words.');
  const pin=readPin('backup-password');
  if($('#backup-pin-submit').textContent==='Verify PIN'){
    if(pinLockRemaining())return setError('#backup-pin-error',pinLockMessage());
    try{
      if(!await matchesProfilePin(pin)){recordPinFailure();return setError('#backup-pin-error',pinLockRemaining()?pinLockMessage():'That PIN did not match. Try again.');}
      clearPinFailures();
    }catch(error){return setError('#backup-pin-error',error.message||'Could not check the PIN.');}
  }
  finishBackupPin(pin);
});
async function exportTasks(){
  const button=$('#export-tasks');button.disabled=true;
  try{
    const pin=sessionPin||await requestBackupPin('profile');if(!pin)return;
    const backup=await DaymarkData.createTaskBackup(tasks),encrypted=await DaymarkData.encryptBackup(backup,pin);
    const blob=new Blob([JSON.stringify(encrypted,null,2)],{type:'application/json'}),url=URL.createObjectURL(blob),anchor=document.createElement('a');anchor.href=url;anchor.download=`daymark-backup-${toISO(new Date())}.encrypted.json`;document.body.append(anchor);anchor.click();anchor.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
    localStorage.setItem(LAST_EXPORT_KEY,String(Date.now()));localStorage.setItem(LAST_REMINDER_KEY,String(Date.now()));notify('Encrypted task backup downloaded');
  }catch(error){setError('#backup-error',error.message||'Could not create an encrypted backup.');}
  finally{button.disabled=false;}
}
$('#export-tasks').addEventListener('click',exportTasks);
$('#import-tasks-file').addEventListener('change',event=>{selectedImportFile=event.target.files?.[0]||null;$('#backup-error').textContent='';});
function normalizeImportedTasks(input){
  DaymarkData.validateTasks(input);
  return input.map((task,index)=>{
    if(!task||typeof task.title!=='string'||!task.title.trim())throw new Error(`Task ${index+1} has no valid title.`);
    return {id:String(task.id||crypto.randomUUID?.()||`${Date.now()}-${index}`),title:task.title.trim().slice(0,120),due:/^\d{4}-\d{2}-\d{2}$/.test(task.due||'')?task.due:'',priority:['normal','high','low'].includes(task.priority)?task.priority:'normal',done:Boolean(task.done),completedAt:task.completedAt||null,created:Number(task.created)||Date.now(),pinned:Boolean(task.pinned)};
  });
}
$('#import-tasks').addEventListener('click',async()=>{
  setError('#backup-error','');if(!selectedImportFile)return setError('#backup-error','Choose a JSON file first.');
  try{
    const text=await selectedImportFile.text();
    const backup=DaymarkData.isEncryptedBackup(text)?await (async()=>{const pin=await requestBackupPin('import');if(!pin)return null;return DaymarkData.decryptBackup(text,pin);})():await DaymarkData.parseBackup(text);
    if(!backup)return;
    const incoming=normalizeImportedTasks(backup.tasks);
    const approved=await confirmMessage('Import tasks?',`Import ${incoming.length} task${incoming.length===1?'':'s'} using the selected merge or replace option?`,'Import tasks');if(!approved)return;
    const previousTasks=cloneData(tasks);
    if($('#import-mode').value==='replace')tasks=incoming;
    else{const existing=new Set(tasks.map(task=>task.id));tasks=[...tasks,...incoming.filter(task=>!existing.has(task.id))];}
    if(!await persist()){tasks=previousTasks;render();return;}render();selectedImportFile=null;$('#import-tasks-file').value='';notify('Tasks imported');
  }catch(error){setError('#backup-error',error.message||'That file could not be imported.');}
});
$('#restore-snapshot').addEventListener('click',async()=>{
  const item=loadSnapshots().find(snapshot=>snapshot.id===$('#restore-select').value);if(!item)return setError('#backup-error','Choose a snapshot to restore.');
  try{const saved=item.encrypted?await DaymarkData.decryptObject(vaultKey,item):item;const backup=saved.backup||{app:'Daymark',version:1,tasks:saved.tasks};const verified=await DaymarkData.verifyTaskBackup(backup),incoming=normalizeImportedTasks(verified.tasks);const approved=await confirmMessage('Restore this snapshot?',`This replaces your current ${tasks.length} task${tasks.length===1?'':'s'} with the saved list. Continue?`,'Restore snapshot');if(!approved)return;const previousTasks=cloneData(tasks);tasks=incoming;if(!await persist()){tasks=previousTasks;render();return;}render();notify('Previous task list restored');$('#backup-dialog').close();}
  catch(error){setError('#backup-error',error.message||'Could not restore that snapshot.');}
});
function scheduleBackupReminder(){
  const interval=Number(localStorage.getItem(REMINDER_INTERVAL_KEY)??7);if(!interval||!tasks.length)return;
  const exported=Number(localStorage.getItem(LAST_EXPORT_KEY)||profile?.createdAt||Date.now());
  const reminded=Number(localStorage.getItem(LAST_REMINDER_KEY)||0);
  if(Date.now()-exported<interval*86400000||Date.now()-reminded<86400000)return;
  localStorage.setItem(LAST_REMINDER_KEY,String(Date.now()));setTimeout(()=>{if(!document.body.classList.contains('is-locked'))$('#backup-reminder-dialog').showModal();},1200);
}
$('#backup-remind-later').addEventListener('click',()=>$('#backup-reminder-dialog').close());
$('#backup-remind-export').addEventListener('click',()=>{$('#backup-reminder-dialog').close();exportTasks();});
function openSecurityForm(mode){securityMode=mode;$('#security-error').textContent='';$('#security-form').reset();clearPin('new-password');clearPin('new-password-confirm');[1,2,3].forEach(number=>{$(`#security-q${number}`).value='';$(`#security-custom-q${number}`).value='';$(`#security-a${number}`).value='';});syncQuestionSet('security');const title=mode==='enable'?'Enable PIN protection':mode==='migration'?'Create your six-word PIN':'Change six-word PIN';$('#security-title').textContent=title;$('#security-submit').textContent=mode==='enable'?'Enable PIN':'Save six-word PIN';$('#security-dialog').showModal();focusPin('new-password');}
$('#theme-select').addEventListener('change',event=>applyTheme(event.target.value));
$('#change-password').addEventListener('click',()=>{
  if(profile.passwordEnabled===false){$('#profile-dialog').close();openSecurityForm('enable');return;}
  pendingSecurityAction='change';$('#pin-title').textContent='Verify to change PIN';$('#pin-copy').textContent='Enter your current six-word PIN. The PIN settings will open when it is verified.';clearPin('pin-password');$('#pin-error').textContent='';$('#pin-dialog').showModal();focusPin('pin-password');
});
$('#password-toggle').addEventListener('click',()=>{
  if(profile.passwordEnabled===false){$('#profile-dialog').close();openSecurityForm('enable');return;}
  pendingSecurityAction='disable';$('#pin-title').textContent='Verify to disable PIN';$('#pin-copy').textContent='Enter your current six-word PIN before turning off profile protection.';clearPin('pin-password');$('#pin-error').textContent='';$('#pin-dialog').showModal();focusPin('pin-password');
});
$('#pin-form').addEventListener('submit',async event=>{
  event.preventDefault();$('#pin-error').textContent='';
  try{
    if(pinLockRemaining())return setError('#pin-error',pinLockMessage());
    const words=pinParts('pin-password');if(profile.pinVersion===2&&!completePin('pin-password'))return setError('#pin-error','Enter all six words of your PIN.');
    const verified=await matchesProfilePin(readPin('pin-password'));
    if(!verified){recordPinFailure();setError('#pin-error',pinLockRemaining()?pinLockMessage():'That PIN did not match. Try again.');focusPin('pin-password');return;}
    clearPinFailures();
    const action=pendingSecurityAction;clearPin('pin-password');$('#pin-dialog').close();
    if(action==='change'){openSecurityForm('change');return;}
    const copy=profile.encryptionEnabled?'Turning off the PIN also turns off task encryption and stores tasks unencrypted in this browser. Anyone using it can open Daymark.':'Anyone using this browser profile can open Daymark without a PIN. You can turn protection back on in settings.';
    const approved=await confirmMessage('Disable PIN protection?',copy,'Disable PIN');
    if(approved){
      if(profile.encryptionEnabled){const oldProfile=cloneData(profile);try{await convertSnapshotEncryption(vaultKey,false);localStorage.setItem(STORAGE_KEY,JSON.stringify(tasks));profile.passwordEnabled=false;profile.encryptionEnabled=false;delete profile.dataVault;if(!saveProfile(false))throw new Error('Could not save the profile change.');vaultKey=null;}
        catch(error){profile=oldProfile;localStorage.removeItem(STORAGE_KEY);try{await convertSnapshotEncryption(vaultKey,true);}catch{}return showMessage('Could not disable protection',error.message,'warning');}}
      else{profile.passwordEnabled=false;if(!saveProfile())return;}
      sessionPin=null;renderProfile();$('#profile-dialog').close();notify('PIN protection disabled');
    }
  }catch(error){setError('#pin-error',error.message||'Could not verify your PIN.');}
});
$('#security-form').addEventListener('submit',async event=>{
  event.preventDefault();setError('#security-error','');const newPassword=readPin('new-password'),confirm=readPin('new-password-confirm'),answers=getQuestionSet('security');
  if(!completePin('new-password')||!completePin('new-password-confirm'))return setError('#security-error','Enter a value in all six PIN boxes.');if(newPassword!==confirm)return setError('#security-error','Those six entries do not match.');if(!validateQuestions(answers))return setError('#security-error','Choose three different questions and fill in every answer.');
  const previousProfile=cloneData(profile),previousPin=sessionPin;
  try{const protectedAnswers=await protectAnswers(answers);if(profile.encryptionEnabled){profile.dataVault=await DaymarkData.rewrapPin(profile.dataVault,vaultKey,newPassword);profile.dataVault=await DaymarkData.rewrapRecovery(profile.dataVault,vaultKey,answers.map(item=>normalizeAnswer(item.answer)));}const secret=await createSecret(newPassword);Object.assign(profile,secret,{recovery:protectedAnswers,passwordEnabled:true,pinVersion:2});sessionPin=newPassword;if(saveProfile(false)){clearPinFailures();$('#security-dialog').close();$('#security-form').reset();renderProfile();notify(securityMode==='enable'?'PIN protection enabled':'Six-word PIN updated');}else throw new Error('Could not save the security change.');}
  catch(error){profile=previousProfile;sessionPin=previousPin;setError('#security-error',error.message||'Could not update account security.');}
});
$('#lock-profile').addEventListener('click',async()=>{const approved=await confirmMessage('Lock your profile?','Your tasks and profile will be hidden until you enter your six-word PIN.','Lock profile');if(approved){sessionPin=null;vaultKey=null;$('#profile-dialog').close();showAuth('login');notify('Profile locked');}});
$('#message-ok').addEventListener('click',()=>$('#message-dialog').close());$('#message-cancel').addEventListener('click',()=>$('#message-dialog').close());

window.addEventListener('beforeinstallprompt',event=>{event.preventDefault();deferredInstallPrompt=event;$('#install-button').classList.add('install-ready');});
$('#install-button').addEventListener('click',async()=>{
  if(deferredInstallPrompt){deferredInstallPrompt.prompt();const choice=await deferredInstallPrompt.userChoice;deferredInstallPrompt=null;notify(choice.outcome==='accepted'?'Daymark installed':'Install was cancelled');return;}
  if(location.protocol==='file:')showMessage('Open Daymark from its launcher','PWA installation and offline app caching need localhost. Double-click run-daymark.bat in the Daymark folder, then use the browser’s Install option.');
  else showMessage('Install Daymark','Use your browser menu or address-bar install icon to add Daymark to this device.');
});
if('serviceWorker' in navigator&&location.protocol!=='file:')navigator.serviceWorker.register('./service-worker.js').catch(()=>{});

if(profile&&!profile.createdAt){profile.createdAt=Date.now();saveProfile();}
if(!profile)showAuth('setup');else if(profile.passwordEnabled===false&&!profile.encryptionEnabled){renderProfile();unlock();}else{renderProfile();showAuth('login');}
render();
