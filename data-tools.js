(() => {
  const ITERATIONS = 180000;
  const BACKUP_ITERATIONS = 600000;
  const MAX_BACKUP_ITERATIONS = 1000000;
  const MAX_BACKUP_BYTES = 25 * 1024 * 1024;
  const MAX_TASKS = 10000;
  const encoder = new TextEncoder();
  const decoder = new TextDecoder('utf-8', {fatal:true});

  function toBase64(bytes) {
    let binary = '';
    const input = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    for (let offset = 0; offset < input.length; offset += 0x8000) binary += String.fromCharCode(...input.subarray(offset, offset + 0x8000));
    return btoa(binary);
  }
  function fromBase64(value) {
    if (typeof value !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw new Error('This backup contains invalid encoded data.');
    const binary = atob(value);
    return Uint8Array.from(binary, char => char.charCodeAt(0));
  }
  function randomHex(length = 16) {
    return [...crypto.getRandomValues(new Uint8Array(length))].map(byte => byte.toString(16).padStart(2, '0')).join('');
  }
  function saltBytes(salt) {
    if (typeof salt !== 'string' || !/^(?:[\da-f]{2}){16,64}$/i.test(salt)) throw new Error('This backup contains an invalid encryption salt.');
    return Uint8Array.from(salt.match(/.{2}/g), byte => parseInt(byte, 16));
  }
  async function deriveAesKey(secret, salt, iterations = ITERATIONS) {
    if (!crypto.subtle) throw new Error('Encrypted storage is not available in this browser.');
    const material = await crypto.subtle.importKey('raw', encoder.encode(secret), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({name:'PBKDF2', salt:saltBytes(salt), iterations, hash:'SHA-256'}, material, {name:'AES-GCM', length:256}, true, ['encrypt','decrypt']);
  }
  async function encryptBytes(key, bytes) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, bytes);
    return {iv:toBase64(iv), ciphertext:toBase64(encrypted)};
  }
  async function decryptBytes(key, record) {
    const iv = fromBase64(record.iv);
    const ciphertext = fromBase64(record.ciphertext);
    if (iv.length !== 12 || ciphertext.length < 16 || ciphertext.length > MAX_BACKUP_BYTES) throw new Error('This backup has invalid encrypted data.');
    const decrypted = await crypto.subtle.decrypt({name:'AES-GCM', iv}, key, ciphertext);
    return new Uint8Array(decrypted);
  }
  function recoveryPhrase(answers) {
    return answers.map(answer => String(answer).trim().normalize('NFKC').toLocaleLowerCase()).join('\u001f');
  }
  async function wrapKey(dataKey, secret) {
    const salt = randomHex();
    const wrappingKey = await deriveAesKey(secret, salt);
    const rawKey = new Uint8Array(await crypto.subtle.exportKey('raw', dataKey));
    return {salt, ...(await encryptBytes(wrappingKey, rawKey))};
  }
  async function unwrapKey(wrapper, secret) {
    const wrappingKey = await deriveAesKey(secret, wrapper.salt);
    const rawKey = await decryptBytes(wrappingKey, wrapper);
    return crypto.subtle.importKey('raw', rawKey, {name:'AES-GCM'}, true, ['encrypt','decrypt']);
  }
  async function encryptObject(key, value) {
    return {encrypted:true, ...(await encryptBytes(key, encoder.encode(JSON.stringify(value))))};
  }
  async function decryptObject(key, record) {
    const bytes = await decryptBytes(key, record);
    return JSON.parse(decoder.decode(bytes));
  }
  async function createVault(tasks, pin, answers) {
    const raw = crypto.getRandomValues(new Uint8Array(32));
    const dataKey = await crypto.subtle.importKey('raw', raw, {name:'AES-GCM'}, true, ['encrypt','decrypt']);
    const pinWrap = await wrapKey(dataKey, pin);
    const recoveryWrap = await wrapKey(dataKey, recoveryPhrase(answers));
    const payload = await encryptObject(dataKey, tasks);
    return {vault:{version:1, pinWrap, recoveryWrap, payload}, key:dataKey};
  }
  async function unlockVaultByPin(vault, pin) {
    const key = await unwrapKey(vault.pinWrap, pin);
    return {key, tasks:await decryptObject(key, vault.payload)};
  }
  async function unlockVaultByRecovery(vault, answers) {
    const key = await unwrapKey(vault.recoveryWrap, recoveryPhrase(answers));
    return {key, tasks:await decryptObject(key, vault.payload)};
  }
  async function saveEncryptedTasks(vault, key, tasks) {
    return {...vault, payload:await encryptObject(key, tasks)};
  }
  async function rewrapPin(vault, key, pin) {
    return {...vault, pinWrap:await wrapKey(key, pin)};
  }
  async function rewrapRecovery(vault, key, answers) {
    return {...vault, recoveryWrap:await wrapKey(key, recoveryPhrase(answers))};
  }

  function validDate(value) {
    if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
    const [year, month, day] = value.split('-').map(Number);
    const date = new Date(Date.UTC(year, month - 1, day));
    return date.getUTCFullYear() === year && date.getUTCMonth() === month - 1 && date.getUTCDate() === day;
  }
  function stableStringify(value) {
    if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
    if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
    return JSON.stringify(value);
  }
  function validateTasks(tasks) {
    if (!Array.isArray(tasks) || tasks.length > MAX_TASKS) throw new Error(`A backup must contain no more than ${MAX_TASKS.toLocaleString()} tasks.`);
    const ids = new Set();
    for (const [index, task] of tasks.entries()) {
      const label = `Task ${index + 1}`;
      if (!task || typeof task !== 'object' || Array.isArray(task)) throw new Error(`${label} is not a valid task record.`);
      if (typeof task.title !== 'string' || !task.title.trim() || task.title.trim().length > 120) throw new Error(`${label} has an invalid title.`);
      if (task.id !== undefined && (typeof task.id !== 'string' || !task.id.trim())) throw new Error(`${label} has an invalid ID.`);
      if (task.id && ids.has(task.id)) throw new Error(`The backup contains duplicate task IDs (${task.id}).`);
      if (task.id) ids.add(task.id);
      if (task.due !== undefined && (typeof task.due !== 'string' || (task.due !== '' && !validDate(task.due)))) throw new Error(`${label} has an invalid due date.`);
      if (task.priority !== undefined && !['normal','high','low'].includes(task.priority)) throw new Error(`${label} has an invalid priority.`);
      for (const field of ['done','pinned']) if (task[field] !== undefined && typeof task[field] !== 'boolean') throw new Error(`${label} has an invalid ${field === 'done' ? 'completion state' : 'pin state'}.`);
      if (task.created !== undefined && (typeof task.created !== 'number' || !Number.isFinite(task.created) || task.created < 0)) throw new Error(`${label} has an invalid creation date.`);
      if (task.completedAt !== undefined && task.completedAt !== null && task.completedAt !== '' && !validDate(task.completedAt)) throw new Error(`${label} has an invalid completion date.`);
    }
    return tasks;
  }
  async function digestBackup(core) {
    return toBase64(await crypto.subtle.digest('SHA-256', encoder.encode(stableStringify(core))));
  }
  async function createTaskBackup(tasks, exportedAt = new Date().toISOString()) {
    validateTasks(tasks);
    if (!crypto.subtle) throw new Error('Backup integrity checks are not available in this browser.');
    const core = {app:'Daymark', version:2, exportedAt, tasks:JSON.parse(JSON.stringify(tasks))};
    return {...core, integrity:{algorithm:'SHA-256', digest:await digestBackup(core)}};
  }
  async function verifyTaskBackup(data) {
    if (Array.isArray(data)) {
      validateTasks(data);
      return {app:'Daymark', version:1, exportedAt:null, tasks:data};
    }
    if (!data || typeof data !== 'object' || Array.isArray(data) || !Array.isArray(data.tasks)) throw new Error('This JSON file does not contain a Daymark task list.');
    if (data.app !== undefined && data.app !== 'Daymark') throw new Error('This backup was created by a different app.');
    validateTasks(data.tasks);
    const version = Number(data.version || 1);
    if (!Number.isInteger(version) || version < 1 || version > 2) throw new Error('This backup version is not supported.');
    if (data.integrity !== undefined) {
      if (version < 2 || data.integrity?.algorithm !== 'SHA-256' || typeof data.integrity.digest !== 'string') throw new Error('This backup has an unsupported integrity record.');
      const core = {app:data.app || 'Daymark', version, exportedAt:data.exportedAt ?? null, tasks:data.tasks};
      const expected = await digestBackup(core);
      if (expected !== data.integrity.digest) throw new Error('The backup integrity check failed. The file may be damaged or altered.');
    } else if (version >= 2) {
      throw new Error('The backup is missing its integrity record. Restore was stopped to protect your data.');
    }
    return data;
  }
  function isEncryptedBackup(value) {
    try {
      const data = typeof value === 'string' ? JSON.parse(value) : value;
      return data?.format === 'daymark-encrypted-backup';
    } catch { return false; }
  }
  async function encryptBackup(backup, pin) {
    await verifyTaskBackup(backup);
    if (!crypto.subtle) throw new Error('Encrypted backups are not available in this browser.');
    const salt = randomHex();
    const key = await deriveAesKey(pin, salt, BACKUP_ITERATIONS);
    const plaintext = encoder.encode(JSON.stringify(backup));
    const encrypted = await encryptBytes(key, plaintext);
    return {app:'Daymark', format:'daymark-encrypted-backup', version:1, kdf:'PBKDF2-SHA-256', iterations:BACKUP_ITERATIONS, salt, ...encrypted};
  }
  async function decryptBackup(text, pin) {
    if (typeof text !== 'string' || text.length > MAX_BACKUP_BYTES * 2) throw new Error('This backup is too large or is not readable JSON.');
    let envelope;
    try { envelope = JSON.parse(text); } catch { throw new Error('This file is not valid JSON.'); }
    if (!isEncryptedBackup(envelope) || envelope.app !== 'Daymark' || envelope.version !== 1 || envelope.kdf !== 'PBKDF2-SHA-256') throw new Error('This is not a supported encrypted Daymark backup.');
    if (!Number.isInteger(envelope.iterations) || envelope.iterations < 300000 || envelope.iterations > MAX_BACKUP_ITERATIONS) throw new Error('This backup uses unsupported encryption settings.');
    const key = await deriveAesKey(pin, envelope.salt, envelope.iterations);
    let bytes;
    try { bytes = await decryptBytes(key, envelope); }
    catch { throw new Error('That six-word PIN is incorrect, or the encrypted backup is damaged.'); }
    let backup;
    try { backup = JSON.parse(decoder.decode(bytes)); }
    catch { throw new Error('The decrypted backup is not valid JSON.'); }
    return verifyTaskBackup(backup);
  }
  async function parseBackup(text) {
    if (typeof text !== 'string' || text.length > MAX_BACKUP_BYTES * 2) throw new Error('This backup is too large or is not readable JSON.');
    if (isEncryptedBackup(text)) throw new Error('This backup is encrypted. Choose it again and enter its six-word PIN to restore it.');
    let data;
    try { data = JSON.parse(text); } catch { throw new Error('This file is not valid JSON.'); }
    return verifyTaskBackup(data);
  }
  window.DaymarkData = {encryptObject, decryptObject, createVault, unlockVaultByPin, unlockVaultByRecovery, saveEncryptedTasks, rewrapPin, rewrapRecovery, parseBackup, validateTasks, createTaskBackup, verifyTaskBackup, isEncryptedBackup, encryptBackup, decryptBackup};
})();
