import {BRANDS,parseImport,filter,csv} from './model.mjs';
import {$,el,link,download,status,detailPairs,base,readFile} from './ui.mjs';
let dataset=null,local=[],shown=100;
function stats(){const rows=dataset.records.filter(r=>r.kind==='phishing');$('#stats').replaceChildren();for(const [n,label]of [[rows.reduce((s,r)=>s+r.count,0),'brand-token matches · overlapping'],[rows.length,'configured Canadian brands'],[local.length,'reports in your local workbench']]){const div=el('div',null,'stat');div.append(el('b',n),el('span',label));$('#stats').append(div);}}
function watch(){const kind=$('#signal-kind').value,rows=dataset.records.filter(r=>r.kind===kind),max=Math.max(...rows.map(r=>r.count),1);$('#brands').replaceChildren();$('#aggregate-detail').hidden=true;if(!rows.length){const n=el('div',null,'empty panel');const source=kind==='malware'?'URLhaus malware':'PhishStats phishing';n.append(el('strong','No saved '+source+' sample.'),el('p','This source has no published counts for the selected observation.'));$('#brands').append(n);return;}for(const r of rows){const card=el('article',null,'watch');const top=el('div',null,'watch-top'),button=el('button',r.brand,'row-button');button.addEventListener('click',()=>aggregateDetail(r));top.append(button,el('b',r.count));const bar=el('div',null,'bar'),fill=el('i');fill.style.width=(r.count/max*100)+'%';bar.append(fill);card.append(top,bar,el('p',r.source+' · '+r.kind+' candidates','meta no-margin'),el('p',(r.capped?'Capped source result page':'Selected source results')+' · heuristic token match','fine no-margin'));$('#brands').append(card);}}
function aggregateDetail(r){const p=$('#aggregate-detail');p.replaceChildren(el('h3',r.brand+' · aggregate evidence'));detailPairs(p,[['Source',r.source],['Classification',r.kind],['Matched candidates',r.count],['Source rows examined',r.queried_rows],['Match rule',r.match_method],['Registrar',r.registrar]]);for(const [title,values]of [['Hosting ASN groups',r.networks],['Report month groups',r.months]]){p.append(el('h3',title));p.append(el('p',values.length?values.map(x=>x.label+': '+x.count).join(' · '):'No matching observations in this result page.','meta'));}p.append(el('p','Counts under three are pooled. No URL, source ID or exact report date is included in this public aggregate.','fine'));p.hidden=false;p.focus();p.scrollIntoView({block:'start'});}
function selected(){return filter(local,{q:$('#q').value,brand:$('#brand').value,kind:$('#kind').value});}
function render(){const rows=selected();$('#rows').replaceChildren();$('#result-count').textContent=rows.length+' matching imported reports · '+local.length+' in this tab';$('#empty').hidden=rows.length>0;$('#export-csv').disabled=!rows.length;$('#more').hidden=rows.length<=shown;if(!rows.length&&local.length){$('#empty').replaceChildren(el('strong','No reports match these filters.'),el('p','Try another brand, source or search term.'));}for(const r of rows.slice(0,shown)){const tr=el('tr'),first=el('td'),btn=el('button',r.url,'row-button');btn.addEventListener('click',()=>report(r));first.append(btn,el('small',r.brands.join(' · ')));tr.append(first,el('td',r.source+' / '+r.kind),el('td',r.reported_at),el('td',r.asn));$('#rows').append(tr);}if(dataset)stats();}
function report(r){const p=$('#evidence-detail');p.replaceChildren(el('h3','Imported evidence · '+r.source));detailPairs(p,[['Defanged URL',r.url],['Brand candidates',r.brands],['Classification',r.kind],['Reported',r.reported_at],['Updated',r.updated_at],['Hosting ASN',r.asn],['Reported registrar',r.registrar],['Hosting country',r.country],['Reported title',r.title||'Not supplied'],['Source status',r.status]]);if(r.reference)p.append(link('Open URLhaus evidence page ↗',r.reference,'btn'));p.append(el('p','The reported URL is inert. This tool never contacts it. Report dates are source dates, not capture dates. A listed ASN or registrar is not an allegation of wrongdoing.','fine'));p.hidden=false;p.scrollIntoView({behavior:'smooth',block:'nearest'});}
$('#import-button').addEventListener('click',()=>{try{const rows=parseImport($('#input').value);local=rows;shown=100;$('#input').value='';$('#evidence-detail').hidden=true;render();status('Imported '+rows.length+' reports locally. No upstream requests were made.');}catch(e){status('Import failed: '+e.message,true);}});
$('#clear').addEventListener('click',()=>{local=[];$('#input').value='';$('#file').value='';$('#evidence-detail').hidden=true;render();status('Local evidence cleared.');});
$('#file').addEventListener('change',e=>readFile(e.target.files[0],$('#input')));
for(const selector of ['#q','#brand','#kind'])$(selector).addEventListener('input',()=>{shown=100;render();});
$('#more').addEventListener('click',()=>{shown+=100;render();});
$('#export-csv').addEventListener('click',()=>download('maplephish-evidence.csv',csv(selected()),'text/csv'));
for(const [brand]of BRANDS){const o=el('option',brand);o.value=brand;$('#brand').append(o);}const o=el('option','No configured brand token');o.value=o.textContent;$('#brand').append(o);
$('#signal-kind').addEventListener('change',watch);
base().then(x=>{
  dataset=x;stats();watch();render();
  const button=$('#open-example');
  const example=x.records.find(r=>r.id===button?.dataset.record && r.kind==='phishing' && r.source==='PhishStats');
  if(example){
    button.hidden=false;
    button.onclick=()=>{
      $('#signal-kind').value='phishing';
      watch();
      aggregateDetail(example);
    };
  }
}).catch(e=>{status(e.message,true);$('#checked').textContent='Saved data unavailable';});
