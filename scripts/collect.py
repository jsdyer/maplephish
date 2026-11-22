"""Daily bounded aggregate collection. No raw phishing indicators are republished."""
from archive import save,request_json,ROOT
from collections import Counter
from urllib.parse import urlencode
import os,re,json,datetime
BRANDS=[('Interac',['interac']),('RBC',['rbc','royal bank']),('Canada Post',['canadapost','canada post']),('Scotiabank',['scotiabank']),('CIBC',['cibc']),('Desjardins',['desjardins'])]
def matched(row,terms):
    text=str(row.get('url',''))+' '+str(row.get('title',''))
    return any(re.search(r'(?<![a-z])'+re.escape(t)+r'(?![a-z])',text,re.I) for t in terms)
def summarize(name,rows,terms,kind='phishing',source='PhishStats'):
    if not isinstance(rows,list) or any(not isinstance(x,dict) for x in rows):raise ValueError('Expected list of source records')
    selected={str(r.get('id') or r.get('url')):r for r in rows if matched(r,terms)}
    records=list(selected.values());dates=[str(r.get('date') or r.get('date_added') or '')[:7] for r in records]
    months=Counter(d for d in dates if re.fullmatch(r'\d{4}-\d{2}',d));asn=Counter(str(r.get('asn') or 'Not reported') for r in records)
    # Groups with fewer than three observations are pooled; no IDs, URLs, dates or titles survive.
    def pooled(counts):
        result=[{'label':k,'count':v} for k,v in counts.items() if v>=3]
        small=sum(v for v in counts.values() if v<3)
        if small:result.append({'label':'Other / fewer than 3','count':small})
        return sorted(result,key=lambda x:(-x['count'],x['label']))
    return {'id':source.lower()+'-'+name.lower().replace(' ','-'),'brand':name,'source':source,'kind':kind,'count':len(records),'queried_rows':len(rows),'capped':len(rows)>=100,'months':pooled(months),'networks':pooled(asn),'registrar':'Not supplied by these source responses','match_method':'Case-insensitive brand token in reported URL or title; unverified impersonation candidate'}
def run():
    rows=[];sources=[];warnings=[];headers={}
    if os.getenv('PHISHSTATS_API_KEY'):headers['X-API-Key']=os.environ['PHISHSTATS_API_KEY']
    for name,terms in BRANDS:
        where='~or'.join('('+field+',like,~'+term+'~)' for term in terms for field in ['url','title'])
        data=request_json('https://api.phishstats.info/api/phishing?'+urlencode({'_where':where,'_sort':'-id','_p':0,'_size':100}),headers)
        rows.append(summarize(name,data,terms))
    sources.append({'name':'PhishStats','url':'https://www.phishstats.info/api-docs','status':'collected','policy':'https://www.phishstats.info/terms','detail':'Six bounded queries; newest page of at most 100 reports per brand. Derived aggregate groups only.'})
    key=os.getenv('URLHAUS_AUTH_KEY')
    if key:
        data=request_json('https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1000/',{'Auth-Key':key})
        if data.get('query_status') not in ['ok','no_results']:raise ValueError('Unexpected URLhaus status')
        raw=data.get('urls',[])
        if not isinstance(raw,list):raise ValueError('Invalid URLhaus records')
        for name,terms in BRANDS:
            row=summarize(name,raw,terms,'malware','URLhaus');row['capped']=len(raw)>=1000;rows.append(row)
        sources.append({'name':'URLhaus','url':'https://urlhaus-api.abuse.ch/','status':'collected','policy':'https://abuse.ch/terms-of-use/','detail':'Latest additions in past 3 days, maximum 1,000. Malware distribution, not phishing.'})
    else:
        sources.append({'name':'URLhaus','url':'https://urlhaus-api.abuse.ch/','status':'awaiting credential','policy':'https://abuse.ch/terms-of-use/','detail':'URLHAUS_AUTH_KEY required in repository Actions secrets.'})
        warnings.append('URLhaus has not been collected. A missing malware source is not zero malware activity.')
    return save({'needs_credentials':not bool(os.getenv('URLHAUS_AUTH_KEY')),'records':rows,'sources':sources,'status':'ready' if key else 'partial','coverage':'Six Canadian-brand token queries. PhishStats newest result page (up to 100 each); URLhaus latest 3-day additions (up to 1,000 total) when configured. Not a census.','warnings':warnings,'policy_checked':'2026-11-22','publication':'Derived counts only; upstream raw feeds are not redistributed.'})
if __name__=='__main__':
    try:run()
    except Exception as e:raise SystemExit('Collection stopped; previous data retained. '+str(e)) from None
