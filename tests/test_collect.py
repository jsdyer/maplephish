import unittest,sys,json,tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from collect import summarize,matched
from archive import save,assemble
class CollectTests(unittest.TestCase):
 def test_derived_aggregates_never_republish_indicators(self):
  data=[{'id':i,'url':'https://interac-pay.example/private-secret','title':'Interac','date':'2026-11-02','asn':'AS123'} for i in range(5)]
  row=summarize('Interac',data,['interac']);self.assertEqual(row['count'],5);self.assertEqual(row['networks'][0],{'label':'AS123','count':5});self.assertNotIn('private-secret',json.dumps(row));self.assertNotIn('example',json.dumps(row));self.assertNotIn('2026-11-02',json.dumps(row))
 def test_small_groups_are_pooled_and_duplicate_ids_count_once(self):
  row=summarize('RBC',[{'id':1,'url':'https://rbc.example','asn':'AS1','date':'2026-01-01'},{'id':1,'url':'https://rbc.example'}],['rbc']);self.assertEqual(row['count'],1);self.assertEqual(row['networks'][0]['label'],'Other / fewer than 3');self.assertFalse(matched({'url':'https://barbcode.example'},['rbc']))
 def test_malware_does_not_become_phishing(self):
  x=summarize('RBC',[{'id':1,'url':'https://rbc.example'}],['rbc'],'malware','URLhaus');self.assertEqual(x['kind'],'malware')
 def test_archive_is_immutable_and_validated(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);(root/'tool.json').write_text('{"title":"test"}');payload={'records':[],'sources':[{'name':'source','url':'https://example.org'}],'coverage':'Known empty response'}
   save(payload,root);files=list(root.glob('archive/*/*'));original=files[0].read_bytes();save(payload,root);self.assertEqual(len(list(root.glob('archive/*/*'))),1);self.assertEqual(original,files[0].read_bytes());stage=root/'stage';stage.mkdir();assemble(root,stage);files[0].write_text('{}');
   with self.assertRaisesRegex(ValueError,'checksum'):assemble(root,root/'invalid')
