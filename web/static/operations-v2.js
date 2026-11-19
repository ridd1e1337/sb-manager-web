(() => {
  const $ = id => document.getElementById(id);
  const root = $('managed-operations');
  if (!root) return;
  let catalog = [], servers = [], role = 'viewer', currentTask = null, pollTimer = null;
  const csrf = () => document.cookie.split('; ').find(value => value.startsWith('sbweb_csrf='))?.split('=')[1] || '';
  async function request(url, body) {
    const response = await fetch(url, body === undefined ? {} : {method:'POST',
      headers:{'Content-Type':'application/json','X-CSRF-Token':decodeURIComponent(csrf())},body:JSON.stringify(body)});
    const value = await response.json();
    if (!response.ok) throw new Error(value.error?.message || `请求失败 (${response.status})`);
    return value;
  }
  function message(text, failed = false) {
    $('operation-message').textContent = text;
    $('operation-message').className = failed ? 'notice error' : 'notice';
  }
  function option(value, label) { const element = document.createElement('option');element.value=value;element.textContent=label;return element; }
  function selected() {return catalog.find(op => op.action === $('operation-action').value);}
  function showTarget() {
    const server = servers.find(value => value.id === $('operation-server').value);
    $('operation-target').textContent = server?.id === 'local' ? '操作在本机执行；修改仍由 sb-manager 校验与回滚。' :
      `${server?.name || '目标服务器'} · sb-manager ${server?.sb_manager_version || '待检测'} · Agent ${server?.agent_version || '未知'}${server?.online ? '' : ' · 离线'}`;
    loadRecent().catch(error => message(error.message,true));
  }
  function showForm() {
    const op = selected(); $('operation-fields').replaceChildren();
    if (!op) return;
    $('operation-description').textContent = op.description || (op.read_only ? '读取目标状态。' : '提交后可在下方查看执行结果。');
    for (const field of op.fields) {
      const label=document.createElement('label'), title=document.createElement('span');title.textContent=field.label;
      let input;
      if (field.kind === 'select') {
        input=document.createElement('select');for(const value of field.options) input.append(option(value,value));
      } else {
        input=document.createElement('input');input.type=field.kind==='checkbox'?'checkbox':field.kind==='number'?'number':field.kind==='source-url'?'password':'text';
        if(field.min)input.min=field.min;if(field.max)input.max=field.max;
        if(field.kind==='number')input.step='1';
      }
      input.name=field.key;input.required=field.required;input.value=field.default||'';input.autocomplete='off';
      label.append(title,input);$('operation-fields').append(label);
    }
    $('operation-submit').textContent=op.read_only?'查询目标':'提交操作';
    $('operation-submit').disabled=(op.admin_only && role!=='admin') || (!op.read_only && role==='viewer');
    $('operation-access').textContent=op.admin_only?'此操作仅管理员可执行。':role==='viewer'&&!op.read_only?'当前账号为只读账号。':'';
  }
  function showActions() {
    $('operation-action').replaceChildren(...catalog.filter(op=>op.group===$('operation-group').value).map(op=>option(op.action,op.title)));
    showForm();
  }
  async function loadRecent() {
    const response=await request('/api/v1/tasks');
    const tasks=response.tasks.filter(task=>task.server_id===$('operation-server').value&&catalog.some(op=>op.action===task.action)).reverse().slice(0,12);
    $('operation-recent').replaceChildren();
    for(const task of tasks) {
      const button=document.createElement('button');button.type='button';button.className='secondary-button';
      button.textContent=`${catalog.find(op=>op.action===task.action).title} · ${({pending:'等待执行',running:'执行中',success:'完成',failed:'失败',canceled:'已取消'})[task.status] || task.status}`;
      button.addEventListener('click',()=>watchTask(task.id));$('operation-recent').append(button);
    }
  }
  async function watchTask(id) {
    clearTimeout(pollTimer);currentTask=id;
    try {
      const task=await request(`/api/v1/tasks/${encodeURIComponent(id)}`);
      if(currentTask!==id)return;
      $('operation-output').textContent=[task.output,task.error].filter(Boolean).join('\n')||'等待目标服务器执行…';
      $('operation-private').hidden=!(task.private&&role==='admin'&&!['pending','running'].includes(task.status));
      $('operation-task-link').href=`/#tasks`;
      $('operation-task-link').textContent=`任务 ${id} · ${task.status}`;
      if(['pending','running'].includes(task.status))pollTimer=setTimeout(()=>watchTask(id),2000);
      else await loadRecent();
    } catch(error) {message(error.message,true);}
  }
  $('operation-form').addEventListener('submit',async event=>{
    event.preventDefault();const op=selected();if(!op)return;
    const server=servers.find(value=>value.id===$('operation-server').value);
    if(!op.read_only&&!confirm(`在「${server?.name || '本机'}」执行「${op.title}」？`))return;
    const args={};for(const field of op.fields){const input=event.target.elements.namedItem(field.key);if(field.kind==='checkbox')args[field.key]=input.checked;else if(input.value!=='')args[field.key]=field.kind==='number'?Number(input.value):input.value;}
    const button=$('operation-submit');button.disabled=true;
    try {
      const task=await request('/api/v1/operations',{server_id:$('operation-server').value,action:op.action,args,idempotency_key:crypto.randomUUID()});
      if(op.private)for(const input of $('operation-fields').querySelectorAll('input[type="password"]'))input.value='';
      message('任务已提交。');await watchTask(task.id);
    }catch(error){message(error.message,true);}finally{button.disabled=(op.admin_only&&role!=='admin')||(!op.read_only&&role==='viewer');}
  });
  $('operation-private').addEventListener('click',async()=>{
    if(!currentTask)return;
    const button=$('operation-private');button.disabled=true;
    try {const value=await request(`/api/v1/tasks/${encodeURIComponent(currentTask)}/private-result`,{});
      clearTimeout(pollTimer);$('operation-output').textContent=[value.output,value.error].filter(Boolean).join('\n');
      button.hidden=true;message('私有结果已领取，仅在本页显示，请立即复制。刷新页面后无法再次领取。');
    }catch(error){message(error.message,true);}finally{button.disabled=false;}
  });
  $('operation-clear').addEventListener('click',()=>{clearTimeout(pollTimer);currentTask=null;$('operation-output').textContent='结果已清除。';$('operation-private').hidden=true;});
  $('operation-group').addEventListener('change',showActions);$('operation-action').addEventListener('change',showForm);
  $('operation-server').addEventListener('change',showTarget);
  $('operation-refresh').addEventListener('click',()=>loadRecent().catch(error=>message(error.message,true)));
  async function init() {
    const [operations,list]=await Promise.all([request('/api/v1/operations'),request('/api/v1/servers')]);
    catalog=operations.operations;role=operations.role;servers=list.servers;
    $('operation-server').replaceChildren(...servers.map(server=>option(server.id,server.name+(server.id==='local'?'（本机）':''))));
    const target=new URLSearchParams(location.search).get('server');if(servers.some(server=>server.id===target))$('operation-server').value=target;
    $('operation-group').replaceChildren(...[...new Set(catalog.map(op=>op.group))].map(group=>option(group,group)));
    showActions();showTarget();
  }
  init().catch(error=>message(error.message,true));
})();
