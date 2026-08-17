from apiat.core.verify import materially_different, is_denied
from apiat.models.schema import Observation

def o(status, body): return Observation(status,{},body,1)
def test_denials(): assert is_denied(o(403,{})) and not is_denied(o(200,{}))
def test_difference(): assert materially_different(o(200,{'id':1}),o(200,{'id':2}))
