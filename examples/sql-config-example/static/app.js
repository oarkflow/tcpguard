const log = (msg, blocked) => {
  const e = document.createElement('div');
  e.className = 'log-entry ' + (blocked ? 'blocked' : 'allowed');
  e.textContent = new Date().toLocaleTimeString() + ' - ' + msg;
  document.getElementById('logEntries').prepend(e);
};

async function testUser() {
  const user = document.getElementById('userSelect').value;
  const endpoint = document.getElementById('userEndpoint').value;
  const count = parseInt(document.getElementById('userRequests').value);
  const result = document.getElementById('userResult');
  result.innerHTML = 'Testing...';
  result.className = 'result show';
  let blocked = 0, allowed = 0;
  
  for (let i = 0; i < count; i++) {
    try {
      const headers = {};
      if (user) headers['X-User-ID'] = user;
      const r = await fetch(endpoint, { headers });
      if (r.status === 403 || r.status === 429) {
        blocked++;
        log(`${user || 'anon'} → ${endpoint} BLOCKED (${r.status})`, true);
      } else {
        allowed++;
        log(`${user || 'anon'} → ${endpoint} allowed`, false);
      }
      await new Promise(r => setTimeout(r, 100));
    } catch (e) {
      blocked++;
      log(`${user || 'anon'} → ${endpoint} ERROR`, true);
    }
  }
  
  result.className = 'result show ' + (blocked > 0 ? 'error' : 'success');
  result.innerHTML = `<pre>User: ${user || 'Anonymous'}\nEndpoint: ${endpoint}\nTotal: ${count}\nAllowed: ${allowed}\nBlocked: ${blocked}</pre>`;
}

async function testGroup() {
  const group = document.getElementById('groupSelect').value;
  const endpoint = document.getElementById('groupEndpoint').value;
  const count = parseInt(document.getElementById('groupRequests').value);
  const result = document.getElementById('groupResult');
  result.innerHTML = 'Testing...';
  result.className = 'result show';
  const users = { 'admin-group': 'user-1', 'dev-group': 'user-2', 'viewer-group': 'user-3' };
  const user = users[group];
  let blocked = 0, allowed = 0;
  
  for (let i = 0; i < count; i++) {
    try {
      const r = await fetch(endpoint, { headers: { 'X-User-ID': user } });
      if (r.status === 403 || r.status === 429) {
        blocked++;
        log(`${group} → ${endpoint} BLOCKED (${r.status})`, true);
      } else {
        allowed++;
        log(`${group} → ${endpoint} allowed`, false);
      }
      await new Promise(r => setTimeout(r, 100));
    } catch (e) {
      blocked++;
      log(`${group} → ${endpoint} ERROR`, true);
    }
  }
  
  result.className = 'result show ' + (blocked > 0 ? 'error' : 'success');
  result.innerHTML = `<pre>Group: ${group}\nEndpoint: ${endpoint}\nTotal: ${count}\nAllowed: ${allowed}\nBlocked: ${blocked}</pre>`;
}

async function testEndpoint() {
  const endpoint = document.getElementById('endpointSelect').value;
  const user = document.getElementById('endpointUser').value;
  const count = parseInt(document.getElementById('endpointRequests').value);
  const result = document.getElementById('endpointResult');
  result.innerHTML = 'Testing...';
  result.className = 'result show';
  let blocked = 0, allowed = 0;
  
  for (let i = 0; i < count; i++) {
    try {
      const headers = {};
      if (user) headers['X-User-ID'] = user;
      const r = await fetch(endpoint, { method: 'POST', headers });
      if (r.status === 403 || r.status === 429) {
        blocked++;
        log(`${user || 'anon'} → ${endpoint} BLOCKED (${r.status})`, true);
      } else {
        allowed++;
        log(`${user || 'anon'} → ${endpoint} allowed`, false);
      }
      await new Promise(r => setTimeout(r, 100));
    } catch (e) {
      blocked++;
      log(`${user || 'anon'} → ${endpoint} ERROR`, true);
    }
  }
  
  result.className = 'result show ' + (blocked > 0 ? 'error' : 'success');
  result.innerHTML = `<pre>Endpoint: ${endpoint}\nUser: ${user || 'Anonymous'}\nTotal: ${count}\nAllowed: ${allowed}\nBlocked: ${blocked}</pre>`;
}

async function testGlobal() {
  const rule = document.getElementById('globalRule').value;
  const user = document.getElementById('globalUser').value;
  const count = parseInt(document.getElementById('globalRequests').value);
  const result = document.getElementById('globalResult');
  result.innerHTML = 'Testing...';
  result.className = 'result show';
  let blocked = 0, allowed = 0;
  
  for (let i = 0; i < count; i++) {
    try {
      const headers = {};
      if (user) headers['X-User-ID'] = user;
      const r = await fetch('/admin/dashboard', { headers });
      if (r.status === 403 || r.status === 429) {
        blocked++;
        log(`${rule} ${user || 'anon'} BLOCKED (${r.status})`, true);
      } else {
        allowed++;
        log(`${rule} ${user || 'anon'} allowed`, false);
      }
      await new Promise(r => setTimeout(r, 50));
    } catch (e) {
      blocked++;
      log(`${rule} ${user || 'anon'} ERROR`, true);
    }
  }
  
  result.className = 'result show ' + (blocked > 0 ? 'error' : 'success');
  result.innerHTML = `<pre>Rule: ${rule}\nUser: ${user || 'Anonymous'}\nTotal: ${count}\nAllowed: ${allowed}\nBlocked: ${blocked}</pre>`;
}
