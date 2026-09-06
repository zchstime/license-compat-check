import tempfile, unittest
from pathlib import Path
from license_compat_check.__main__ import check
class Tests(unittest.TestCase):
 def test_policy(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/"d.csv"; p.write_text("name,version,license\na,1,MIT\nb,2,GPL3\nc,3,Unknown\n")
   rows=check(p,{"allow":["MIT"],"deny":["GPL-3.0-only"]}); self.assertEqual([x["status"] for x in rows],["allow","deny","review"])
if __name__=="__main__": unittest.main()
